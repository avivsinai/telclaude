import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	createTelclaudeMcpSideEffectApprovalVerifier,
	generateTelclaudeMcpSideEffectApprovalToken,
	TelclaudeMcpSideEffectJtiStore,
} from "../../src/hermes/mcp/approval-token.js";
import {
	type BrowserWriteCommitter,
	createTelclaudeMcpLedgerExecuteDependencies,
} from "../../src/hermes/mcp/ledger-execute.js";
import {
	createTelclaudeMcpSideEffectLedger,
	getTelclaudeMcpSideEffectApprovalBinding,
	type TelclaudeMcpBrowserWriteSideEffectPrepareInput,
	type TelclaudeMcpBrowserWriteSideEffectRecord,
	type TelclaudeMcpSideEffectApprovalVerifier,
	type TelclaudeMcpSideEffectLedger,
} from "../../src/hermes/mcp/side-effect-ledger.js";
import {
	type BrowserActEvidence,
	type BrowserActEvidencePage,
	type BrowserActScreenshotSink,
	captureBrowserActEvidence,
} from "../../src/relay/browser-act-evidence.js";
import {
	type BrowserWriteContext,
	prepareBrowserWrite,
} from "../../src/relay/browser-write-confirm.js";

const COMMITMENT_SECRET = "browser-write-commitment-secret-32-bytes!";
const ACTOR = "telegram:123";
const APPROVER = "telegram:operator";

/**
 * A minimal page whose DOM/URL can be mutated between prepare and execute so the
 * REAL captureBrowserActEvidence produces genuinely-drifted evidence — not a mocked
 * hash.
 */
class FakePage implements BrowserActEvidencePage {
	currentUrl = "https://shop.example.com/cart/checkout";
	currentDom = "<html><body><button id=pay>Pay $40.00</button></body></html>";

	url(): string {
		return this.currentUrl;
	}

	async evaluate<T>(_expression: string): Promise<T> {
		return this.currentDom as unknown as T;
	}

	async screenshot(_options: {
		readonly type: "png";
		readonly fullPage: true;
	}): Promise<Uint8Array> {
		// Deterministic, derived from the current DOM so an unchanged page yields the
		// same screenshot bytes (and thus the same HMAC revision).
		return Buffer.from(`shot:${this.currentDom}`, "utf8");
	}
}

class FakeScreenshotSink implements BrowserActScreenshotSink {
	async storeScreenshot(input: { readonly hash: string }): Promise<string> {
		return `screenshot-ref:${input.hash}`;
	}
}

async function captureFixture(page: FakePage, evidenceNonce?: string): Promise<BrowserActEvidence> {
	return captureBrowserActEvidence(
		page,
		{ verb: "click", target: "#pay", submittedValues: { amount: "40.00" }, forceConfirm: true },
		{
			screenshotSink: new FakeScreenshotSink(),
			commitmentSecret: COMMITMENT_SECRET,
			observedSignals: {},
			...(evidenceNonce ? { evidenceNonce } : {}),
		},
	);
}

function browseContext(overrides: Partial<BrowserWriteContext> = {}): BrowserWriteContext {
	return {
		sessionRef: "browse-session:shop",
		actor: ACTOR,
		profile: "private",
		authorityDomain: "private",
		host: "shop.example.com",
		originScope: ["https://shop.example.com"],
		...overrides,
	};
}

function prepareInputFromConfirm(args: {
	readonly bindingHash: string;
	readonly evidence: BrowserActEvidence;
	readonly ttlMs?: number;
	readonly approverActorId?: string;
}): TelclaudeMcpBrowserWriteSideEffectPrepareInput {
	return {
		kind: "browser-write",
		actorId: ACTOR,
		approverActorId: args.approverActorId ?? APPROVER,
		profileId: "private",
		domain: "private",
		sessionRef: "browse-session:shop",
		host: "shop.example.com",
		originScope: ["https://shop.example.com"],
		authorityDomain: "private",
		actionVerb: "click",
		actionTarget: "#pay",
		evidenceRevision: args.evidence.revision,
		evidenceNonce: args.evidence.evidenceNonce,
		display: { verb: "click", target: "#pay", urlOrigin: args.evidence.urlOrigin },
		commitSignal: args.evidence.commitSignal,
		bindingHash: args.bindingHash,
		approvalRequestId: "approval-browser-write-1",
		approvalRevision: 1,
		idempotencyKey: "idem-browser-write-1",
		...(args.ttlMs ? { ttlMs: args.ttlMs } : {}),
	};
}

/**
 * Stages a browser write through the REAL prepareBrowserWrite (which produces the
 * binding hash) and inserts the record into the ledger.
 */
async function stagePreparedWrite(
	ledger: TelclaudeMcpSideEffectLedger,
	page: FakePage,
	opts: { ttlMs?: number; approverActorId?: string } = {},
): Promise<{
	readonly record: TelclaudeMcpBrowserWriteSideEffectRecord;
	readonly evidence: BrowserActEvidence;
}> {
	const evidence = await captureFixture(page);
	const prepared = prepareBrowserWrite({
		context: browseContext(),
		action: { verb: "click", target: "#pay" },
		evidence,
		approver: opts.approverActorId ?? APPROVER,
	});
	const record = ledger.prepare(
		prepareInputFromConfirm({
			bindingHash: prepared.bindingHash,
			evidence,
			ttlMs: opts.ttlMs,
			approverActorId: opts.approverActorId,
		}),
	) as TelclaudeMcpBrowserWriteSideEffectRecord;
	return { record, evidence };
}

/**
 * A committer that recaptures the live page with the stored nonce + empty observed
 * signals (the contract) and commits exactly once. Records commit calls so a test
 * can assert "committed exactly once" / "never committed".
 */
function makeCommitter(
	page: FakePage,
	options: { useFreshNonce?: boolean } = {},
): BrowserWriteCommitter & { readonly commits: string[] } {
	const commits: string[] = [];
	return {
		commits,
		async recaptureEvidence(record) {
			return captureBrowserActEvidence(
				page,
				// Recapture with the SAME action intent being committed (verb, target,
				// submittedValues) — the production committer knows the values it is about
				// to submit; an unchanged page + same intent reproduces the binding.
				{
					verb: record.actionVerb,
					target: record.actionTarget ?? undefined,
					submittedValues: { amount: "40.00" },
					forceConfirm: true,
				},
				{
					screenshotSink: new FakeScreenshotSink(),
					commitmentSecret: COMMITMENT_SECRET,
					observedSignals: {},
					// CONTRACT: recapture under the STORED nonce. A fresh random nonce is a
					// bug that must fail binding_drift (the negative test below flips this).
					evidenceNonce: options.useFreshNonce ? undefined : record.evidenceNonce,
				},
			);
		},
		async commit(record) {
			commits.push(record.ref);
			return { receipt: { committed: true, ref: record.ref, verb: record.actionVerb } };
		},
	};
}

class MockVaultClient {
	throwOnVerify = false;

	async signPayload(payload: string, prefix: string): Promise<{ type: string; signature: string }> {
		return { type: "sign-payload", signature: signatureFor(prefix, payload) };
	}

	async verifyPayload(
		payload: string,
		signature: string,
		prefix: string,
	): Promise<{ type: string; valid: boolean }> {
		if (this.throwOnVerify) throw new Error("vault unavailable");
		return { type: "verify-payload", valid: signature === signatureFor(prefix, payload) };
	}
}

function signatureFor(prefix: string, payload: string): string {
	return Buffer.from(`${prefix}\n${payload}`, "utf8").toString("base64url");
}

describe("Telclaude MCP browser-write side-effect ledger", () => {
	let tempDir: string;
	let jtiStore: TelclaudeMcpSideEffectJtiStore;
	let vault: MockVaultClient;
	let nowMs: number;

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tc-mcp-browser-write-"));
		jtiStore = new TelclaudeMcpSideEffectJtiStore(tempDir);
		vault = new MockVaultClient();
		nowMs = 1_000_000;
	});

	afterEach(() => {
		jtiStore.close();
		fs.rmSync(tempDir, { recursive: true, force: true });
	});

	function createLedger(
		verifier?: TelclaudeMcpSideEffectApprovalVerifier,
	): TelclaudeMcpSideEffectLedger {
		let nextRef = 0;
		return createTelclaudeMcpSideEffectLedger({
			verifyApproval:
				verifier ?? createTelclaudeMcpSideEffectApprovalVerifier({ vaultClient: vault, jtiStore }),
			nowMs: () => nowMs,
			makeRef: () => `effect-bw-${++nextRef}`,
			defaultTtlMs: 5 * 60_000,
		});
	}

	/** Mint a real, ledger-bound approval token for a prepared record. */
	async function mintToken(
		record: TelclaudeMcpBrowserWriteSideEffectRecord,
		jti: string,
	): Promise<string> {
		const binding = getTelclaudeMcpSideEffectApprovalBinding(record);
		return generateTelclaudeMcpSideEffectApprovalToken(binding, vault, {
			nowSeconds: () => Math.floor(nowMs / 1000),
			ttlSeconds: 60,
			jti,
		});
	}

	function deps(args: {
		readonly ledger: TelclaudeMcpSideEffectLedger;
		readonly committer: BrowserWriteCommitter;
		readonly tokenFor: Map<string, string>;
	}) {
		return createTelclaudeMcpLedgerExecuteDependencies({
			ledger: args.ledger,
			browserWriteCommitter: args.committer,
			nowMs: () => nowMs,
			sideEffectApprovalTokenResolver: ({ actionRef }) => {
				const approvalToken = args.tokenFor.get(actionRef);
				if (!approvalToken) {
					return {
						ok: false,
						code: "side_effect_approval_token_unavailable",
						reason: "no token",
						retryable: true,
					};
				}
				return { ok: true, approvalToken };
			},
		});
	}

	function executeRequest(record: TelclaudeMcpBrowserWriteSideEffectRecord) {
		return {
			actorId: record.actorId,
			profileId: record.profileId,
			domain: record.domain,
			actionRef: record.ref,
		};
	}

	it("prepare → approve → execute happy path commits exactly once with a real token + fresh evidence", async () => {
		const page = new FakePage();
		const ledger = createLedger();
		const { record } = await stagePreparedWrite(ledger, page);
		const committer = makeCommitter(page);
		const token = await mintToken(record, "jti-bw-happy");
		const execute = deps({
			ledger,
			committer,
			tokenFor: new Map([[record.ref, token]]),
		});

		const result = await execute.browserWriteExecute(executeRequest(record));

		expect(result).toEqual({
			ok: true,
			receipt: { committed: true, ref: record.ref, verb: "click" },
		});
		expect(committer.commits).toEqual([record.ref]);
		expect(ledger.get(record.ref)?.status).toBe("executed");
	});

	it("rejects self-approval (actor === approver) at prepare and at execute", async () => {
		const page = new FakePage();
		const ledger = createLedger();
		// prepareBrowserWrite itself refuses a self-approval.
		const evidence = await captureFixture(page);
		expect(() =>
			prepareBrowserWrite({
				context: browseContext(),
				action: { verb: "click", target: "#pay" },
				evidence,
				approver: ACTOR,
			}),
		).toThrow(/self|approved by its own actor/i);

		// And if a self-approving record is forced into the ledger, execute fails closed.
		const record = ledger.prepare(
			prepareInputFromConfirm({
				bindingHash: "sha256:".concat("0".repeat(64)),
				evidence,
				approverActorId: ACTOR,
			}),
		) as TelclaudeMcpBrowserWriteSideEffectRecord;
		const committer = makeCommitter(page);
		const token = await mintToken(record, "jti-bw-self").catch(() => "unusable");
		const execute = deps({ ledger, committer, tokenFor: new Map([[record.ref, token]]) });

		const result = await execute.browserWriteExecute(executeRequest(record));
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.code).toBe("side_effect_distinct_human_approver_required");
		}
		expect(committer.commits).toEqual([]);
		expect(ledger.get(record.ref)?.status).toBe("prepared");
	});

	it("rejects an expired record before approval and does not commit", async () => {
		const page = new FakePage();
		const ledger = createLedger();
		const { record } = await stagePreparedWrite(ledger, page, { ttlMs: 60_000 });
		const committer = makeCommitter(page);
		const token = await mintToken(record, "jti-bw-expired");
		const execute = deps({ ledger, committer, tokenFor: new Map([[record.ref, token]]) });

		nowMs += 61_000; // past the record TTL

		const result = await execute.browserWriteExecute(executeRequest(record));
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe("effect_expired");
		expect(committer.commits).toEqual([]);
		expect(ledger.get(record.ref)?.status).toBe("prepared");
	});

	it("rejects a replayed approval-token JTI on a second execute", async () => {
		const page = new FakePage();
		const ledger = createLedger();
		const { record: first } = await stagePreparedWrite(ledger, page);
		const committerOne = makeCommitter(page);
		const tokenOne = await mintToken(first, "jti-bw-replay");
		const executeOne = deps({
			ledger,
			committer: committerOne,
			tokenFor: new Map([[first.ref, tokenOne]]),
		});

		await expect(executeOne.browserWriteExecute(executeRequest(first))).resolves.toMatchObject({
			ok: true,
		});

		// Stage a SECOND prepared record and try to authorize it with the SAME JTI.
		const { record: second } = await stagePreparedWrite(ledger, page);
		const replayToken = await generateTelclaudeMcpSideEffectApprovalToken(
			getTelclaudeMcpSideEffectApprovalBinding(second),
			vault,
			{ nowSeconds: () => Math.floor(nowMs / 1000), ttlSeconds: 60, jti: "jti-bw-replay" },
		);
		const committerTwo = makeCommitter(page);
		const executeTwo = deps({
			ledger,
			committer: committerTwo,
			tokenFor: new Map([[second.ref, replayToken]]),
		});

		const result = await executeTwo.browserWriteExecute(executeRequest(second));
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe("approval_replayed");
		expect(committerTwo.commits).toEqual([]);
		expect(ledger.get(second.ref)?.status).toBe("prepared");
	});

	it("does not verify a cross-kind (provider-domain) token as browser-write — domain separation", async () => {
		const page = new FakePage();
		const ledger = createLedger();
		const { record } = await stagePreparedWrite(ledger, page);

		// Build a token whose binding is the SAME field-for-field as the browser-write
		// binding but signed under the PROVIDER approval domain. Domain separation must
		// make it unverifiable as browser-write.
		const binding = getTelclaudeMcpSideEffectApprovalBinding(record);
		const crossDomainBinding = {
			...binding,
			domainSeparator: "telclaude.hermes.mcp.side-effect.provider.approval.v1",
		} as unknown as Parameters<typeof generateTelclaudeMcpSideEffectApprovalToken>[0];
		// The generator validates the binding against the kind schema, so it rejects a
		// browser-write binding wearing a provider domain separator outright.
		await expect(
			generateTelclaudeMcpSideEffectApprovalToken(crossDomainBinding, vault, {
				nowSeconds: () => Math.floor(nowMs / 1000),
				ttlSeconds: 60,
				jti: "jti-bw-cross-kind",
			}),
		).rejects.toThrow("Invalid side-effect approval binding");

		// Even a genuine provider token (different domain) does not pass verification
		// for this browser-write record: the signature is computed under the wrong
		// domain prefix, so verifyPayload fails.
		const claimsB64 = Buffer.from(
			JSON.stringify({ ...binding, kind: "browser-write" }),
			"utf8",
		).toString("base64url");
		const wrongDomainSig = signatureFor(
			"telclaude.hermes.mcp.side-effect.provider.approval.v1",
			claimsB64,
		);
		const forged = `v1.${claimsB64}.${wrongDomainSig}`;
		const committer = makeCommitter(page);
		const execute = deps({ ledger, committer, tokenFor: new Map([[record.ref, forged]]) });

		const result = await execute.browserWriteExecute(executeRequest(record));
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.retryable).toBe(true);
		expect(committer.commits).toEqual([]);
		expect(ledger.get(record.ref)?.status).toBe("prepared");
	});

	it("fails closed on a DRIFTED page at execute (different bindingHash) and does not commit", async () => {
		const page = new FakePage();
		const ledger = createLedger();
		const { record } = await stagePreparedWrite(ledger, page);
		const committer = makeCommitter(page);
		const token = await mintToken(record, "jti-bw-drift");
		const execute = deps({ ledger, committer, tokenFor: new Map([[record.ref, token]]) });

		// Mutate the live page AFTER prepare/approve: a different price the human never saw.
		page.currentDom = "<html><body><button id=pay>Pay $4000.00</button></body></html>";

		const result = await execute.browserWriteExecute(executeRequest(record));
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe("browser_write_write_confirm_binding_drift");
		expect(committer.commits).toEqual([]);
		// Drift is detected AFTER the single-flight claim, so the record fails terminally
		// (the consumed approval is not reopened); the operator must re-prepare.
		expect(ledger.get(record.ref)?.status).toBe("failed");
	});

	it("fails binding_drift when the committer recaptures with a FRESH random nonce on an unchanged page", async () => {
		const page = new FakePage();
		const ledger = createLedger();
		const { record } = await stagePreparedWrite(ledger, page);
		// Same page, but committer ignores the stored nonce — the page-revision /
		// submitted-value HMACs incorporate the nonce, so the binding can't re-match.
		const committer = makeCommitter(page, { useFreshNonce: true });
		const token = await mintToken(record, "jti-bw-fresh-nonce");
		const execute = deps({ ledger, committer, tokenFor: new Map([[record.ref, token]]) });

		const result = await execute.browserWriteExecute(executeRequest(record));
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe("browser_write_write_confirm_binding_drift");
		expect(committer.commits).toEqual([]);
		// Drift after the claim is terminal — the ref ends `failed`, not `prepared`.
		expect(ledger.get(record.ref)?.status).toBe("failed");
	});
});
