/**
 * Relay-owned BrowserActExecutor — the broker act path for S3 interactive
 * browser writes.
 *
 * The contained (untrusted) runtime never drives a browser. It asks the relay,
 * through the served MCP, to act on an interactive session. This executor runs
 * relay-side. It splits acts by their commit signal:
 *
 * - NON-committing acts (fill/type) on cookie-less public pages mutate the page
 *   inline and return relay-owned evidence. They cross no approval boundary, so they
 *   do not touch the side-effect ledger. selectOption/click/press/goto — and ANY act
 *   on a resolved logged-in session — are committing: the surface refuses them inline
 *   and routes them to prepare.
 * - COMMITTING acts (submit, a click that navigates/posts, …) are two-phase:
 *   `prepareIntent` captures the SETTLED pre-commit page WITHOUT firing, stages a
 *   `prepareBrowserWrite` record for human approval, and HOLDS the live page +
 *   the approved submitted values in the relay-only session pool keyed by the
 *   ledger ref. The committing act itself fires only later, via the
 *   `BrowserWriteCommitter` the ledger drives after the operator approves.
 *
 * The executor depends on an injected `BrowserActDriver` (the Playwright verbs +
 * a `BrowserActEvidencePage` view of the live page) so the act/evidence logic is
 * unit-testable with a fake driver. The real driver is a thin Playwright adapter
 * over the broker's page.
 *
 * Authority + session resolution for an act is IDENTICAL to a browse: the
 * authority is server-stamped on the request (#171) and the session is resolved
 * by the relay from the cookie store with PSL scoping (#172). The runtime never
 * names its own scope, session, or origin set.
 *
 * VALUE CUSTODY: the approved submitted values live ONLY in the pool entry,
 * never in the ledger (hashes only) and never injected into the page DOM.
 * recapture/commit read them from the pool. The bound `submittedValuesHash`
 * makes a mutated page or value fail verification, so custody + binding together
 * pin exactly what fires.
 */

import crypto from "node:crypto";
import type { BrowserWriteCommitter } from "../hermes/mcp/ledger-execute.js";
import type { TelclaudeMcpBrowserWriteSideEffectRecord } from "../hermes/mcp/side-effect-ledger.js";
import {
	type BrowserActEvidence,
	type BrowserActEvidencePage,
	type BrowserActIntent,
	type BrowserActJsonValue,
	type BrowserActObservedSignals,
	type BrowserActScreenshotSink,
	captureBrowserActEvidence,
	classifyCommitSignal,
} from "./browser-act-evidence.js";
import type {
	BrowserActHeldDriver,
	BrowserActLiveContext,
	BrowserActLivePage,
	BrowserActPoolEntry,
	BrowserActSessionPool,
} from "./browser-act-session-pool.js";
import {
	type BrowserAuthorityDomain,
	type BrowserSessionAuthority,
	browserAuthorityDomainFromMcp,
} from "./browser-cookie-store.js";
import { type PreparedBrowserWrite, prepareBrowserWrite } from "./browser-write-confirm.js";

const BROWSER_ACT_EVIDENCE_COMMITMENT_INFO = "telclaude.browser-act-evidence.v1";
const COMMITMENT_SECRET_BYTES = 32;
/** Minimum length of the raw context-token secret used to derive the commitment key. */
const MIN_CONTEXT_TOKEN_SECRET_LENGTH = 32;
const DEFAULT_SETTLE_MS = 750;

export type BrowserActVerb = "click" | "fill" | "selectOption" | "press" | "goto" | "type";

/**
 * The single seam between the executor and Playwright. The executor never imports
 * Playwright; the production driver wraps the broker's live page, tests inject a
 * fake. `page` is the `BrowserActEvidencePage` view used for evidence capture and
 * is the SAME live page the verbs act on (so recapture re-produces the bound
 * revision). The driver is what the pool holds across the async approval, so the
 * committer fires the approved act on the exact same live page.
 */
export interface BrowserActDriver extends BrowserActHeldDriver {
	/** Evidence/recapture view of the live page (url/evaluate/screenshot). */
	readonly page: BrowserActLivePage;
	/** The live context, closed by the pool on eviction (M6). */
	readonly context: BrowserActLiveContext;
	/** Dispatch a Playwright verb against the live page. */
	dispatch(input: {
		readonly verb: BrowserActVerb;
		readonly target?: string;
		readonly submittedValues?: BrowserActJsonValue;
	}): Promise<void>;
	/**
	 * Wait for the page to settle after a dispatched act (navigation/network
	 * idle). Returns the observed signals seen during the action window.
	 */
	settle(options: { readonly timeoutMs: number }): Promise<BrowserActObservedSignals>;
}

/** The pool the executor uses holds the full act driver per pending committing act. */
export type BrowserActExecutorPool = BrowserActSessionPool<BrowserActDriver>;

/**
 * A server-resolved interactive act request. Authority (`actor`/`profileId`/
 * `authorityDomain`) is stamped by the live MCP server from the peer-bound
 * handle; `sessionRef`/`host`/`originScope` come from the relay-resolved session.
 * The runtime supplies only verb/target/submittedValues.
 */
export interface BrowserActRequest {
	readonly actor: string;
	readonly profileId: string;
	/** MCP trust domain (`private|social|household|public`); mapped to the browser domain. */
	readonly mcpDomain: string;
	readonly sessionRef: string;
	readonly host: string;
	readonly originScope: readonly string[];
	/**
	 * Server-resolved ENTRY url the live page is auto-loaded to before capture/
	 * dispatch (Option A). NOT a runtime free-field beyond the already-validated +
	 * secret-preflighted tool `url`; the relay derives `host`/`originScope` from it
	 * and the M1 origin-pinned proxy denies an off-scope entry navigation at the
	 * network layer. Distinct from a `goto` act's destination, which lives in
	 * `submittedValues` and only navigates post-approval.
	 */
	readonly url: string;
	readonly verb: BrowserActVerb;
	readonly target?: string;
	readonly submittedValues?: BrowserActJsonValue;
	/** Escalate-only: forces confirmation even for a non-committing verb. */
	readonly forceConfirm?: boolean;
	readonly settleTimeoutMs?: number;
}

export interface BrowserActInlineResult {
	readonly committing: false;
	readonly evidence: BrowserActEvidence;
}

export interface BrowserActPrepareResult {
	readonly committing: true;
	readonly prepared: PreparedBrowserWrite;
	readonly record: TelclaudeMcpBrowserWriteSideEffectRecord["kind"];
}

export class BrowserActExecutorError extends Error {
	readonly code: string;
	constructor(code: string, message: string) {
		super(message);
		this.code = code;
		this.name = "BrowserActExecutorError";
	}
}

/**
 * Derive the 32-byte HMAC commitment key for browser-act evidence from the
 * relay's context-token secret. Domain-separated by an HKDF-style label so the
 * key is distinct from the per-context proxy token signing. The key is held only
 * in memory, never logged or persisted; fail closed if the source secret is
 * missing or too short.
 */
export function deriveBrowserActCommitmentSecret(contextTokenSecret: string): Buffer {
	const raw = contextTokenSecret?.trim() ?? "";
	if (raw.length < MIN_CONTEXT_TOKEN_SECRET_LENGTH) {
		throw new BrowserActExecutorError(
			"browser_act_commitment_secret_missing",
			`browser-act commitment requires a context-token secret of at least ${MIN_CONTEXT_TOKEN_SECRET_LENGTH} chars`,
		);
	}
	return crypto
		.createHmac("sha256", Buffer.from(raw, "utf8"))
		.update(BROWSER_ACT_EVIDENCE_COMMITMENT_INFO)
		.digest()
		.subarray(0, COMMITMENT_SECRET_BYTES);
}

/** How the executor resolves the live driver for a server-resolved act. */
export type BrowserActDriverFactory = (
	request: BrowserActRequest,
) => Promise<BrowserActDriver> | BrowserActDriver;

/** How the executor resolves the approver actor for a staged committing write. */
export type BrowserActApproverResolver = (request: BrowserActRequest) => string | Promise<string>;

export interface BrowserActExecutorOptions {
	readonly driverFactory: BrowserActDriverFactory;
	readonly pool: BrowserActExecutorPool;
	readonly screenshotSink: BrowserActScreenshotSink;
	/** Raw relay context-token secret; the 32-byte commitment key is derived from it. */
	readonly contextTokenSecret: string;
	readonly resolveApprover: BrowserActApproverResolver;
	/** TTL forwarded to `prepareBrowserWrite`. */
	readonly writeConfirmTtlMs?: number;
	readonly now?: () => number;
}

export class BrowserActExecutor {
	private readonly driverFactory: BrowserActDriverFactory;
	private readonly pool: BrowserActExecutorPool;
	private readonly screenshotSink: BrowserActScreenshotSink;
	private readonly commitmentSecret: Buffer;
	private readonly resolveApprover: BrowserActApproverResolver;
	private readonly writeConfirmTtlMs?: number;
	private readonly now: () => number;

	constructor(options: BrowserActExecutorOptions) {
		this.driverFactory = options.driverFactory;
		this.pool = options.pool;
		this.screenshotSink = options.screenshotSink;
		// Derive (and validate) the commitment key once. Fail closed at construction
		// rather than per-act if the relay is misconfigured.
		this.commitmentSecret = deriveBrowserActCommitmentSecret(options.contextTokenSecret);
		this.resolveApprover = options.resolveApprover;
		this.writeConfirmTtlMs = options.writeConfirmTtlMs;
		this.now = options.now ?? Date.now;
	}

	/**
	 * Execute a NON-committing act (fill/type) inline on a COOKIE-LESS public page and
	 * return its relay-owned evidence. The relay surface refuses inline acts on a
	 * resolved logged-in session, and committing verbs (selectOption/click/press/goto)
	 * are refused pre-dispatch and routed to prepareIntent — so this path only ever runs
	 * a data-entry verb on a public page with no credentials. Runs under the per-session
	 * serial lock so it never races a pending committing act on the same page. After
	 * settling, the observed signals are re-classified and the act FAILS CLOSED if a
	 * mutation actually fired (a "non-committing" verb that nonetheless navigated or
	 * submitted). The live page is closed afterward — a non-committing act keeps no pool
	 * custody.
	 */
	async act(request: BrowserActRequest): Promise<BrowserActInlineResult> {
		this.assertActIdentity(request);
		// Defense-in-depth (mirrors the doubled verb gate below): the relay surface already
		// refuses inline acts on a resolved cookie-bearing session, but guard here too so any
		// future caller that bypasses the surface cannot run an inline act with a login
		// attached. The session is resolved one layer up and threaded onto the request for the
		// driver factory; its presence here means a logged-in context — never run inline.
		if ((request as { readonly session?: unknown }).session) {
			throw new BrowserActExecutorError(
				"browser_act_cookie_bearing_requires_prepare",
				"an inline act on a cookie-bearing session is not allowed; use prepareIntent + approval",
			);
		}
		const commitSignal = classifyCommitSignal(
			{
				verb: request.verb,
				...(request.target ? { target: request.target } : {}),
				// forceConfirm is RELAY-set + escalate-only. Threading it here lets a
				// relay-escalated non-committing verb refuse the inline path (and route to
				// prepare); dropping it would silently downgrade an escalation.
				...(request.forceConfirm !== undefined ? { forceConfirm: request.forceConfirm } : {}),
			},
			{},
		);
		if (commitSignal.forceConfirm) {
			throw new BrowserActExecutorError(
				"browser_act_requires_prepare",
				"committing act (or forceConfirm) must go through prepareIntent, not inline act",
			);
		}
		return this.pool.withSessionLock(request.sessionRef, async () => {
			const driver = await this.driverFactory(request);
			try {
				await driver.dispatch({
					verb: request.verb,
					...(request.target ? { target: request.target } : {}),
					...(request.submittedValues !== undefined
						? { submittedValues: request.submittedValues }
						: {}),
				});
				const observed = await driver.settle({
					timeoutMs: request.settleTimeoutMs ?? DEFAULT_SETTLE_MS,
				});
				// Defense-in-depth: a verb classified non-committing can still trigger a
				// page-driven navigation/submit/mutating request (onchange/oninput auto-save,
				// single-field search-and-redirect). Re-run the classifier WITH the now-observed
				// signals; if the inline act actually mutated, fail closed. The surface already
				// blocks cookie-bearing inline acts, so this guards cookie-less public pages — an
				// unexpected mutation there is refused, never returned as a clean result.
				const postSettle = classifyCommitSignal(
					{
						verb: request.verb,
						...(request.target ? { target: request.target } : {}),
					},
					observed,
				);
				if (postSettle.forceConfirm) {
					throw new BrowserActExecutorError(
						"browser_act_inline_mutation_observed",
						"a non-committing inline act produced an observed mutation (navigation/submit/mutating request); failing closed",
					);
				}
				const evidence = await this.captureEvidence(driver.page, request, observed);
				return { committing: false, evidence };
			} finally {
				await safeClose(() => driver.page.close());
				await safeClose(() => driver.context.close());
			}
		});
	}

	/**
	 * Stage a COMMITTING act for human approval WITHOUT firing it. Captures the
	 * settled pre-commit page (observedSignals = {} since nothing fired) under a
	 * freshly generated + locked evidence nonce, classifies the commit signal
	 * (which must force confirmation), derives the WYSIWYS binding via
	 * `prepareBrowserWrite`, and HOLDS the live page + approved values in the pool
	 * keyed by the ledger ref. Returns the prepared write for `ledger.prepare`.
	 */
	async prepareIntent(
		request: BrowserActRequest & { readonly actionRef: string },
	): Promise<BrowserActPrepareResult> {
		this.assertActIdentity(request);
		const actionRef = request.actionRef.trim();
		if (!actionRef) {
			throw new BrowserActExecutorError(
				"browser_act_action_ref_missing",
				"prepareIntent requires an actionRef to key the pooled live page",
			);
		}
		return this.pool.withSessionLock(request.sessionRef, async () => {
			const driver = await this.driverFactory(request);
			let held = false;
			try {
				// Capture the SETTLED pre-commit page. Generate + lock the nonce so
				// recapture/commit re-use the EXACT nonce the binding was bound under.
				// Thread the relay-set escalate-only forceConfirm so an escalated
				// non-committing verb stages instead of failing browser_act_not_committing.
				const evidenceNonce = crypto.randomBytes(16).toString("base64url");
				const evidence = await this.captureEvidence(
					driver.page,
					{
						verb: request.verb,
						...(request.target ? { target: request.target } : {}),
						...(request.submittedValues !== undefined
							? { submittedValues: request.submittedValues }
							: {}),
						...(request.forceConfirm !== undefined ? { forceConfirm: request.forceConfirm } : {}),
					},
					{},
					evidenceNonce,
				);
				if (!evidence.commitSignal.forceConfirm) {
					throw new BrowserActExecutorError(
						"browser_act_not_committing",
						"prepareIntent requires a committing act (or forceConfirm); use inline act otherwise",
					);
				}
				const approver = (await this.resolveApprover(request)).trim();
				const prepared = prepareBrowserWrite({
					context: {
						sessionRef: request.sessionRef,
						actor: request.actor,
						profile: request.profileId,
						authorityDomain: this.authorityDomain(request),
						host: request.host,
						originScope: request.originScope,
					},
					action: {
						verb: request.verb,
						...(request.target ? { target: request.target } : {}),
					},
					evidence,
					approver,
					...(this.writeConfirmTtlMs !== undefined ? { ttlMs: this.writeConfirmTtlMs } : {}),
					now: this.now(),
				});
				// VALUE CUSTODY: stash the live driver + the APPROVED submitted values in
				// the pool keyed by the ledger ref. The values never enter the ledger
				// record or the page DOM. recapture/commit read them back from here.
				this.pool.hold({
					sessionRef: request.sessionRef,
					actionRef,
					driver,
					approvedSubmittedValues: normalizeApprovedValues(request.submittedValues),
				});
				held = true;
				return { committing: true, prepared, record: "browser-write" };
			} finally {
				// Only close the driver if we did NOT hand the page to the pool. A held
				// page must stay live across the async approval until commit/eviction.
				if (!held) {
					await safeClose(() => driver.page.close());
					await safeClose(() => driver.context.close());
				}
			}
		});
	}

	/**
	 * The committer the side-effect ledger drives after approval. `recaptureEvidence`
	 * fetches the live page + approved values from the pool by the ledger ref and
	 * recaptures with the STORED nonce + the EXACT approved {verb, target, values}
	 * (W3 — live page, stored nonce, exact values). `commit` fires the committing act
	 * exactly once with the approved values, settles, returns a small receipt, then
	 * evicts the pool entry. The ledger gates verify/claim before recapture and runs
	 * `verifyBrowserWriteExecution` between recapture and commit; this committer does
	 * NOT re-verify.
	 */
	committer(): BrowserWriteCommitter {
		return {
			recaptureEvidence: async (record) => {
				const entry = this.requirePoolEntry(record);
				// W3: recapture must run against the SAME live page, under the STORED
				// nonce, with the EXACT approved values — only then does an unchanged
				// page re-produce the bound revision/url/submitted-value HMACs.
				return this.captureEvidence(
					entry.driver.page,
					{
						verb: record.actionVerb as BrowserActVerb,
						...(record.actionTarget ? { target: record.actionTarget } : {}),
						submittedValues: entry.approvedSubmittedValues,
					},
					{},
					record.evidenceNonce,
				);
			},
			commit: async (record) => {
				const entry = this.requirePoolEntry(record);
				try {
					// Fire the committing act EXACTLY ONCE on the SAME live driver, with
					// the approved values from custody (never the ledger, never re-derived
					// from the page DOM).
					const { driver } = entry;
					await driver.dispatch({
						verb: record.actionVerb as BrowserActVerb,
						...(record.actionTarget ? { target: record.actionTarget } : {}),
						submittedValues: entry.approvedSubmittedValues,
					});
					const observed = await driver.settle({ timeoutMs: DEFAULT_SETTLE_MS });
					// Redact to ORIGIN ONLY (scheme + host): the post-commit landing URL can
					// carry a token/session in its path or query, and this receipt is returned
					// to the contained runtime via tc_browse_act_execute. Origin-only confirms
					// where we landed without leaking the secret-bearing path/query.
					const finalUrlOrigin = redactFinalUrlToOrigin(driver.page.url());
					return {
						receipt: {
							committedAtMs: this.now(),
							host: record.host,
							verb: record.actionVerb,
							finalUrlOrigin,
							observed: {
								navigation: Boolean(observed.navigation),
								formSubmit: Boolean(observed.formSubmit),
								mutatingRequest: Boolean(observed.mutatingRequest),
							},
						},
					};
				} finally {
					// One commit per ref: drop the live page + custody whatever the outcome.
					await this.pool.evict(record.sessionRef, record.ref);
				}
			},
		};
	}

	private requirePoolEntry(
		record: TelclaudeMcpBrowserWriteSideEffectRecord,
	): BrowserActPoolEntry<BrowserActDriver> {
		const entry = this.pool.get(record.sessionRef, record.ref);
		if (!entry) {
			// Fail closed: the live page is gone (restart, TTL lapse, or already
			// committed/evicted). The ledger surfaces this terminally; re-prepare.
			throw new BrowserActExecutorError(
				"browser_write_page_lost",
				"the live interactive page for this browser write is no longer held; re-prepare",
			);
		}
		return entry;
	}

	private async captureEvidence(
		page: BrowserActEvidencePage,
		action: {
			readonly verb: string;
			readonly target?: string;
			readonly submittedValues?: BrowserActJsonValue;
			readonly forceConfirm?: boolean;
		},
		observed: BrowserActObservedSignals,
		evidenceNonce?: string,
	): Promise<BrowserActEvidence> {
		const intent: BrowserActIntent = {
			verb: action.verb,
			...(action.target ? { target: action.target } : {}),
			...(action.submittedValues !== undefined ? { submittedValues: action.submittedValues } : {}),
			...(action.forceConfirm !== undefined ? { forceConfirm: action.forceConfirm } : {}),
		};
		return captureBrowserActEvidence(page, intent, {
			screenshotSink: this.screenshotSink,
			commitmentSecret: this.commitmentSecret,
			observedSignals: observed,
			...(evidenceNonce ? { evidenceNonce } : {}),
		});
	}

	private assertActIdentity(request: BrowserActRequest): void {
		if (
			!request.actor.trim() ||
			!request.profileId.trim() ||
			!request.sessionRef.trim() ||
			!request.host.trim()
		) {
			throw new BrowserActExecutorError(
				"browser_act_identity_missing",
				"browser act requires server-stamped actor, profileId, sessionRef, and host",
			);
		}
	}

	private authorityDomain(request: BrowserActRequest): BrowserAuthorityDomain {
		return browserAuthorityDomainFromMcp(request.mcpDomain);
	}

	/** The server-resolved authority a session must match (parity with the browse resolver). */
	authorityFor(request: BrowserActRequest): BrowserSessionAuthority {
		return {
			actorId: request.actor,
			profileId: request.profileId,
			authorityDomain: this.authorityDomain(request),
		};
	}
}

function normalizeApprovedValues(value: BrowserActJsonValue | undefined): BrowserActJsonValue {
	return value === undefined ? null : value;
}

/**
 * Reduce a post-commit landing URL to its ORIGIN (scheme + host), dropping any
 * path/query/fragment that could carry a token or session id. The receipt is
 * returned to the contained runtime, so the path/query must never leak. Returns
 * `null` for an unparseable or opaque-origin URL.
 */
function redactFinalUrlToOrigin(url: string): string | null {
	try {
		const origin = new URL(url).origin;
		return origin === "null" ? null : origin;
	} catch {
		return null;
	}
}

/**
 * Content-addressed screenshot sink over the relay media store. The evidence
 * module hands us the PNG bytes + their sha256; we persist them under the
 * `generated` media category and return the on-disk path as the opaque ref. The
 * ref is display metadata only (the WYSIWYS binding anchors on the HMAC
 * `revision`, NOT the screenshot), so an operator/approval card can surface the
 * shot the human approved without it being a runtime-forgeable commitment.
 *
 * Implemented against the media-store API as `saveMediaBuffer(bytes, { mimeType:
 * "image/png", category: "generated", filename: "<sha256-slug>", extension:
 * ".png" })`, which returns `{ path }`; we hand that path back as the ref.
 */
export function createBrowserActScreenshotSink(
	saveMediaBuffer: (
		buffer: Buffer,
		options: {
			readonly mimeType: string;
			readonly category: "generated";
			readonly filename: string;
			readonly extension: string;
		},
	) => Promise<{ readonly path: string }>,
): BrowserActScreenshotSink {
	return {
		async storeScreenshot(input) {
			const slug = input.hash.replace(/^sha256:/, "").slice(0, 32);
			const saved = await saveMediaBuffer(Buffer.from(input.bytes), {
				mimeType: input.contentType,
				category: "generated",
				filename: `browser-act-${slug}`,
				extension: ".png",
			});
			return saved.path;
		},
	};
}

async function safeClose(close: () => Promise<void>): Promise<void> {
	try {
		await close();
	} catch {
		// Teardown failures must not mask the act result.
	}
}
