/**
 * Relay-side write-confirm binding for state-changing browser actions (S3).
 *
 * When the contained (untrusted) runtime drives an interactive browse session and
 * performs a COMMITTING act (submit a form, click pay/send/delete), the relay binds
 * a human confirmation to BOTH the exact action AND the page revision the human was
 * shown — what-you-see-is-what-you-sign. The model cannot mutate the action or the
 * page after approval: execute re-derives the binding from the CURRENT action +
 * freshly captured evidence and fails closed on any drift.
 *
 * The WYSIWYS anchor is the relay-owned, HMAC-bound evidence produced by
 * `captureBrowserActEvidence` (src/relay/browser-act-evidence.ts), running in the
 * relay's own Playwright page. We bind over the evidence's HMAC `revision` (plus
 * `schemaVersion`/`evidenceNonce`/`urlHash`/`submittedValuesHash`) — NOT the
 * display-only `domDigest`/`screenshotHash`, which are unauthenticated render
 * metadata the human looks at, not a commitment the runtime cannot forge. The
 * commit/escalation decision is `evidence.commitSignal`, recomputed relay-side by
 * the evidence module from the canonical verb + observed signals; it is relay
 * OUTPUT, never a runtime-trusted input.
 *
 * This module owns the binding hash + the prepared record + the immediately-before
 * drift check. The Ed25519 approval token + one-time JTI layer on top via the
 * side-effect ledger, which treats a browser write as a ledger KIND; this module
 * provides the binding-hash, the redacted display summary, and the fail-closed
 * verification it calls.
 */

import { canonicalHash, sortKeysDeep } from "../crypto/canonical-hash.js";
import { redactSecrets } from "../security/output-filter.js";
import type { BrowserActEvidence, BrowserActIntent } from "./browser-act-evidence.js";
import type { BrowserAuthorityDomain } from "./browser-cookie-store.js";

const MAX_DISPLAY_TARGET_LEN = 120;

/**
 * Derive a safe display target from the raw (possibly model-supplied) action target.
 * The raw target is bound verbatim in the HMAC binding (drift integrity), but the
 * display copy is persisted into the ledger record + surfaced on the approval card,
 * so it must never carry a secret or a full URL: a URL target collapses to its origin
 * (path/query — which can hold tokens — are dropped), and a selector/text target is
 * secret-redacted and length-bounded.
 */
function safeDisplayTarget(target: string | null | undefined): string | null {
	const raw = target?.trim();
	if (!raw) return null;
	try {
		const url = new URL(raw);
		return `${url.protocol}//${url.host}`;
	} catch {
		// not a URL — fall through to redaction
	}
	const redacted = redactSecrets(raw);
	return redacted.length > MAX_DISPLAY_TARGET_LEN
		? `${redacted.slice(0, MAX_DISPLAY_TARGET_LEN)}…`
		: redacted;
}

const BROWSER_WRITE_BINDING_PREFIX = "browser-write-v1";

const DEFAULT_WRITE_CONFIRM_TTL_MS = 5 * 60_000;
const MAX_WRITE_CONFIRM_TTL_MS = 10 * 60_000;
const MIN_WRITE_CONFIRM_TTL_MS = 30_000;

/**
 * The server-resolved context a browser write runs under. None of these fields are
 * agent-supplied: the live MCP server stamps actor/profile/authorityDomain from the
 * peer-bound authority handle, and sessionRef/host/originScope come from the
 * resolved cookie-bearing session — the model never names its own scope.
 */
export interface BrowserWriteContext {
	/** Server-resolved interactive session (the cookie-bearing browse session). */
	readonly sessionRef: string;
	/** Server-resolved actor identity (from the authority handle). */
	readonly actor: string;
	/** Server-resolved operator profile (private-agent mode). */
	readonly profile: string;
	/** Server-resolved trust domain — pins the binding to one persona. */
	readonly authorityDomain: BrowserAuthorityDomain;
	/** Registrable host the action runs on (destination). */
	readonly host: string;
	/** The cookie-bearing session's M1 origin scope (egress is pinned to it). */
	readonly originScope: readonly string[];
}

/** A redacted, display-only summary of the staged write — NEVER raw values/URL. */
export interface BrowserWriteDisplay {
	readonly verb: string;
	readonly target: string | null;
	/** Origin only (scheme + host), redacted of path/query — `null` for opaque origins. */
	readonly urlOrigin: string | null;
}

export interface PreparedBrowserWrite {
	readonly writeRef: string;
	readonly actor: string;
	readonly approver: string;
	readonly profile: string;
	readonly authorityDomain: BrowserAuthorityDomain;
	readonly host: string;
	readonly originScope: readonly string[];
	/** HMAC page revision the human is approving (drift signal). */
	readonly evidenceRevision: string;
	/**
	 * The capture nonce the prepared evidence was bound under. Execute MUST recapture
	 * with THIS nonce (the page revision / url / submitted-value HMACs all incorporate
	 * it), or an otherwise-unchanged page fails `write_confirm_binding_drift`.
	 */
	readonly evidenceNonce: string;
	/** The WYSIWYS binding hash — re-derived and matched at execute time. */
	readonly bindingHash: string;
	/** Redacted action summary surfaced to the approver (no raw values/URL). */
	readonly display: BrowserWriteDisplay;
	/** Relay-computed commit signal (why confirmation is required); relay OUTPUT. */
	readonly commitSignal: BrowserActEvidence["commitSignal"];
	readonly createdAtMs: number;
	readonly expiresAtMs: number;
}

export type BrowserWriteConfirmErrorCode =
	| "write_confirm_identity_missing"
	| "write_confirm_self_approval"
	| "write_confirm_not_required"
	| "write_confirm_expired"
	| "write_confirm_actor_mismatch"
	| "write_confirm_host_mismatch"
	| "write_confirm_binding_drift";

export class BrowserWriteConfirmError extends Error {
	readonly code: BrowserWriteConfirmErrorCode;
	constructor(code: BrowserWriteConfirmErrorCode, message: string) {
		super(message);
		this.code = code;
		this.name = "BrowserWriteConfirmError";
	}
}

/** Normalize an origin scope (lowercased, deduped, sorted) so the binding is order-stable. */
function buildCanonicalOriginScope(scope: readonly string[]): string[] {
	return [...new Set(scope.map((entry) => entry.trim().toLowerCase()).filter(Boolean))].sort();
}

/**
 * Bind the action + the page revision the human saw into one domain-separated hash.
 *
 * Anchored on the relay-owned evidence's HMAC `revision` plus `schemaVersion`,
 * `evidenceNonce`, `urlHash`, and `submittedValuesHash` — the runtime cannot forge
 * any of these (they are HMAC'd by the relay's commitment secret). The display-only
 * `domDigest`/`screenshotHash` are deliberately NOT in the binding. We re-serialize
 * canonically (recursive key sort) so key order / object shape never shifts the hash.
 */
export function deriveBrowserWriteBindingHash(
	context: BrowserWriteContext,
	action: Pick<BrowserActIntent, "verb" | "target">,
	evidence: BrowserActEvidence,
): string {
	const params = sortKeysDeep({
		context: {
			actor: context.actor.trim(),
			authorityDomain: context.authorityDomain,
			host: context.host.trim().toLowerCase(),
			originScope: buildCanonicalOriginScope(context.originScope),
			profile: context.profile.trim(),
			sessionRef: context.sessionRef.trim(),
		},
		action: {
			target: action.target?.trim() || null,
			verb: action.verb.trim().toLowerCase(),
		},
		evidence: {
			evidenceNonce: evidence.evidenceNonce,
			revision: evidence.revision,
			schemaVersion: evidence.schemaVersion,
			submittedValuesHash: evidence.submittedValuesHash,
			urlHash: evidence.urlHash,
		},
	}) as Record<string, unknown>;
	return canonicalHash({
		service: BROWSER_WRITE_BINDING_PREFIX,
		action: "bind",
		params,
		actorUserId: context.actor.trim(),
		subjectUserId: null,
	});
}

let writeRefCounter = 0;

function nextWriteRef(): string {
	writeRefCounter = (writeRefCounter + 1) >>> 0;
	const rand = `${Date.now().toString(36)}${(Math.random() * 0xffffffff) | 0}`;
	return `bwrite-${rand}-${writeRefCounter.toString(36)}`;
}

/**
 * Stage a state-changing browser write for human confirmation.
 *
 * Requires actor != approver (no self-approval) and a present identity set. The
 * commit decision comes from `evidence.commitSignal` (relay output): a write is
 * only staged when the evidence forced confirmation — we do NOT re-classify the
 * verb here. The prepared record carries the binding hash + a redacted display
 * summary (verb, target, origin only) — never raw submitted values or full URL.
 */
export function prepareBrowserWrite(input: {
	readonly context: BrowserWriteContext;
	readonly action: Pick<BrowserActIntent, "verb" | "target">;
	readonly evidence: BrowserActEvidence;
	readonly approver: string;
	readonly ttlMs?: number;
	readonly now?: number;
}): PreparedBrowserWrite {
	const actor = input.context.actor.trim();
	const approver = input.approver.trim();
	const host = input.context.host.trim().toLowerCase();
	if (
		!actor ||
		!approver ||
		!host ||
		!input.context.sessionRef.trim() ||
		!input.context.profile.trim()
	) {
		throw new BrowserWriteConfirmError(
			"write_confirm_identity_missing",
			"write-confirm requires actor, approver, host, sessionRef, and profile",
		);
	}
	if (actor === approver) {
		throw new BrowserWriteConfirmError(
			"write_confirm_self_approval",
			"a browser write cannot be approved by its own actor",
		);
	}
	if (!input.evidence.commitSignal.forceConfirm) {
		throw new BrowserWriteConfirmError(
			"write_confirm_not_required",
			"evidence did not force confirmation; non-committing act does not go through write-confirm",
		);
	}

	const now = input.now ?? Date.now();
	const ttlMs = Math.min(
		Math.max(input.ttlMs ?? DEFAULT_WRITE_CONFIRM_TTL_MS, MIN_WRITE_CONFIRM_TTL_MS),
		MAX_WRITE_CONFIRM_TTL_MS,
	);
	const context: BrowserWriteContext = { ...input.context, actor, host };

	return {
		writeRef: nextWriteRef(),
		actor,
		approver,
		profile: context.profile,
		authorityDomain: context.authorityDomain,
		host,
		originScope: buildCanonicalOriginScope(context.originScope),
		evidenceRevision: input.evidence.revision,
		evidenceNonce: input.evidence.evidenceNonce,
		bindingHash: deriveBrowserWriteBindingHash(context, input.action, input.evidence),
		display: {
			verb: input.action.verb.trim().toLowerCase(),
			// Redacted/scrubbed — the raw target is bound in the hash, never persisted/displayed.
			target: safeDisplayTarget(input.action.target),
			urlOrigin: input.evidence.urlOrigin,
		},
		commitSignal: input.evidence.commitSignal,
		createdAtMs: now,
		expiresAtMs: now + ttlMs,
	};
}

export interface BrowserWriteExecutionCheck {
	readonly ok: boolean;
	readonly reason: "ok" | BrowserWriteConfirmErrorCode;
}

/**
 * Verify an execution against the prepared record. The execution must run the SAME
 * action against the SAME page revision the human approved: this re-derives the
 * binding hash from the CURRENT action + freshly-captured evidence (taken
 * immediately before the act commits) and FAILS CLOSED on any drift — page
 * mutated, action redirected, values changed — plus expiry / actor / host /
 * self-approval checks. The one-time approval-token (JTI) check is enforced by the
 * ledger on top.
 */
export function verifyBrowserWriteExecution(input: {
	readonly prepared: PreparedBrowserWrite;
	readonly context: BrowserWriteContext;
	readonly action: Pick<BrowserActIntent, "verb" | "target">;
	readonly currentEvidence: BrowserActEvidence;
	readonly now?: number;
}): BrowserWriteExecutionCheck {
	const now = input.now ?? Date.now();
	if (now > input.prepared.expiresAtMs) {
		return { ok: false, reason: "write_confirm_expired" };
	}
	if (input.prepared.actor === input.prepared.approver) {
		return { ok: false, reason: "write_confirm_self_approval" };
	}
	if (input.context.actor.trim() !== input.prepared.actor) {
		return { ok: false, reason: "write_confirm_actor_mismatch" };
	}
	if (input.context.host.trim().toLowerCase() !== input.prepared.host) {
		return { ok: false, reason: "write_confirm_host_mismatch" };
	}
	// Re-derive over the prepared actor/host (already verified equal above) so the
	// binding check isolates page/action/evidence drift from identity drift.
	const current = deriveBrowserWriteBindingHash(
		{ ...input.context, actor: input.prepared.actor, host: input.prepared.host },
		input.action,
		input.currentEvidence,
	);
	if (current !== input.prepared.bindingHash) {
		return { ok: false, reason: "write_confirm_binding_drift" };
	}
	return { ok: true, reason: "ok" };
}
