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
 * A page whose DOM/URL can be mutated between prepare and execute so the REAL
 * captureBrowserActEvidence produces genuinely-drifted evidence — not a mocked hash.
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
		return Buffer.from(`shot:${this.currentDom}`, "utf8");
	}
}

class FakeScreenshotSink implements BrowserActScreenshotSink {
	async storeScreenshot(input: { readonly hash: string }): Promise<string> {
		return `screenshot-ref:${input.hash}`;
	}
}

async function captureFixture(page: FakePage): Promise<BrowserActEvidence> {
	return captureBrowserActEvidence(
		page,
		{ verb: "click", target: "#pay", submittedValues: { amount: "40.00" }, forceConfirm: true },
		{
			screenshotSink: new FakeScreenshotSink(),
			commitmentSecret: COMMITMENT_SECRET,
			observedSignals: {},
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
}): TelclaudeMcpBrowserWriteSideEffectPrepareInput {
	return {
		kind: "browser-write",
		actorId: ACTOR,
		approverActorId: APPROVER,
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
	};
}

async function stagePreparedWrite(
	ledger: TelclaudeMcpSideEffectLedger,
	page: FakePage,
): Promise<TelclaudeMcpBrowserWriteSideEffectRecord> {
	const evidence = await captureFixture(page);
	const prepared = prepareBrowserWrite({
		context: browseContext(),
		action: { verb: "click", target: "#pay" },
		evidence,
		approver: APPROVER,
	});
	return ledger.prepare(
		prepareInputFromConfirm({ bindingHash: prepared.bindingHash, evidence }),
	) as TelclaudeMcpBrowserWriteSideEffectRecord;
}

/**
 * A committer that recaptures the live page with the stored nonce + empty observed
 * signals (the contract) and commits exactly once. `commits` records every commit so a
 * test can assert "committed exactly once total" / "never committed". `gateRecapture`,
 * when set, blocks recaptureEvidence until it resolves — letting a test interleave a
 * second concurrent execute while the first holds the claim.
 */
function makeCommitter(
	page: FakePage,
	options: { gateRecapture?: Promise<void> } = {},
): BrowserWriteCommitter & { readonly commits: string[] } {
	const commits: string[] = [];
	return {
		commits,
		async recaptureEvidence(record) {
			if (options.gateRecapture) await options.gateRecapture;
			return captureBrowserActEvidence(
				page,
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
					evidenceNonce: record.evidenceNonce,
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
	async signPayload(payload: string, prefix: string): Promise<{ type: string; signature: string }> {
		return { type: "sign-payload", signature: signatureFor(prefix, payload) };
	}

	async verifyPayload(
		payload: string,
		signature: string,
		prefix: string,
	): Promise<{ type: string; valid: boolean }> {
		return { type: "verify-payload", valid: signature === signatureFor(prefix, payload) };
	}
}

function signatureFor(prefix: string, payload: string): string {
	return Buffer.from(`${prefix}\n${payload}`, "utf8").toString("base64url");
}

describe("Telclaude MCP browser-write single-flight execution claim (CAS)", () => {
	let tempDir: string;
	let jtiStore: TelclaudeMcpSideEffectJtiStore;
	let vault: MockVaultClient;
	let nowMs: number;

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tc-mcp-exec-claim-"));
		jtiStore = new TelclaudeMcpSideEffectJtiStore(tempDir);
		vault = new MockVaultClient();
		nowMs = 1_000_000;
	});

	afterEach(() => {
		jtiStore.close();
		fs.rmSync(tempDir, { recursive: true, force: true });
	});

	function createLedger(): TelclaudeMcpSideEffectLedger {
		let nextRef = 0;
		return createTelclaudeMcpSideEffectLedger({
			verifyApproval: createTelclaudeMcpSideEffectApprovalVerifier({
				vaultClient: vault,
				jtiStore,
			}),
			nowMs: () => nowMs,
			makeRef: () => `effect-claim-${++nextRef}`,
			defaultTtlMs: 5 * 60_000,
		});
	}

	/** Mint a distinct, ledger-bound approval token (unique JTI) for a prepared record. */
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

	it("two distinct valid approval tokens for one ref: winner commits once, the second loses BEFORE the committer", async () => {
		const page = new FakePage();
		const ledger = createLedger();
		const record = await stagePreparedWrite(ledger, page);

		// One shared committer + commit log proves the irreversible commit runs once TOTAL,
		// even though two executes both carry a genuinely-valid distinct approval token.
		let releaseGate: () => void = () => {};
		const gateRecapture = new Promise<void>((resolve) => {
			releaseGate = resolve;
		});
		const committer = makeCommitter(page, { gateRecapture });

		// Each execute has its OWN distinct token (distinct JTI), both binding-valid — i.e.
		// two separate human approvals. Both will pass `verify`; only one may claim.
		const tokenA = await mintToken(record, "jti-claim-A");
		const tokenB = await mintToken(record, "jti-claim-B");
		const executeA = deps({ ledger, committer, tokenFor: new Map([[record.ref, tokenA]]) });
		const executeB = deps({ ledger, committer, tokenFor: new Map([[record.ref, tokenB]]) });

		// A starts and parks inside recaptureEvidence holding the `executing` claim.
		const aPromise = executeA.browserWriteExecute(executeRequest(record));
		// Let A reach (and block on) recapture so its claim is committed to the ledger.
		await new Promise<void>((resolve) => setImmediate(resolve));
		expect(ledger.get(record.ref)?.status).toBe("executing");

		// B runs to completion while A is parked: it must lose the claim before committing.
		const bResult = await executeB.browserWriteExecute(executeRequest(record));
		expect(bResult.ok).toBe(false);
		if (!bResult.ok) {
			expect(["effect_execution_in_flight", "effect_invalid_state"]).toContain(bResult.code);
		}
		expect(committer.commits).toEqual([]); // B never reached the committer

		// Now release A; it commits exactly once and finalizes.
		releaseGate();
		const aResult = await aPromise;
		expect(aResult).toEqual({
			ok: true,
			receipt: { committed: true, ref: record.ref, verb: "click" },
		});

		expect(committer.commits).toEqual([record.ref]); // commit called EXACTLY ONCE total
		expect(ledger.get(record.ref)?.status).toBe("executed");
	});

	it("serial double execute: the second execute on an already-executed ref fails closed with no commit", async () => {
		const page = new FakePage();
		const ledger = createLedger();
		const record = await stagePreparedWrite(ledger, page);
		const committer = makeCommitter(page);
		const tokenA = await mintToken(record, "jti-serial-A");
		const tokenB = await mintToken(record, "jti-serial-B");

		const first = await deps({
			ledger,
			committer,
			tokenFor: new Map([[record.ref, tokenA]]),
		}).browserWriteExecute(executeRequest(record));
		expect(first.ok).toBe(true);
		expect(committer.commits).toEqual([record.ref]);
		expect(ledger.get(record.ref)?.status).toBe("executed");

		const second = await deps({
			ledger,
			committer,
			tokenFor: new Map([[record.ref, tokenB]]),
		}).browserWriteExecute(executeRequest(record));
		expect(second.ok).toBe(false);
		if (!second.ok) expect(second.code).toBe("effect_already_executed");
		// Still exactly one commit total: the second execute did not re-commit.
		expect(committer.commits).toEqual([record.ref]);
		expect(ledger.get(record.ref)?.status).toBe("executed");
	});

	it("binding drift AFTER the claim closes the ref terminally (failed, not prepared) with no commit", async () => {
		const page = new FakePage();
		const ledger = createLedger();
		const record = await stagePreparedWrite(ledger, page);
		const committer = makeCommitter(page);
		const token = await mintToken(record, "jti-drift");
		const execute = deps({ ledger, committer, tokenFor: new Map([[record.ref, token]]) });

		// Mutate the live page after prepare/approve: a price the human never saw.
		page.currentDom = "<html><body><button id=pay>Pay $4000.00</button></body></html>";

		const result = await execute.browserWriteExecute(executeRequest(record));
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe("browser_write_write_confirm_binding_drift");
		expect(committer.commits).toEqual([]);
		// The ref does NOT revert to prepared and the consumed approval is NOT reopened.
		const after = ledger.get(record.ref);
		expect(after?.status).toBe("failed");
		expect(after?.status).not.toBe("prepared");
	});

	it("recapture failure AFTER the claim closes the ref terminally (failed) with no commit", async () => {
		const page = new FakePage();
		const ledger = createLedger();
		const record = await stagePreparedWrite(ledger, page);
		const token = await mintToken(record, "jti-recapture-throw");
		const throwingCommitter: BrowserWriteCommitter & { readonly commits: string[] } = {
			commits: [],
			async recaptureEvidence() {
				throw new Error("page navigated away");
			},
			async commit(rec) {
				this.commits.push(rec.ref);
				return { receipt: { committed: true } };
			},
		};
		const execute = deps({
			ledger,
			committer: throwingCommitter,
			tokenFor: new Map([[record.ref, token]]),
		});

		const result = await execute.browserWriteExecute(executeRequest(record));
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe("browser_write_recapture_failed");
		expect(throwingCommitter.commits).toEqual([]);
		expect(ledger.get(record.ref)?.status).toBe("failed");
	});

	it("ambiguous commit() failure after the claim is terminal — no second commit on the ref", async () => {
		const page = new FakePage();
		const ledger = createLedger();
		const record = await stagePreparedWrite(ledger, page);
		const token = await mintToken(record, "jti-commit-throw");
		let commitAttempts = 0;
		const throwingCommitter = makeCommitter(page);
		const ambiguousCommitter: BrowserWriteCommitter = {
			recaptureEvidence: throwingCommitter.recaptureEvidence.bind(throwingCommitter),
			async commit() {
				commitAttempts += 1;
				throw new Error("network dropped after submit; outcome unknown");
			},
		};
		const execute = deps({
			ledger,
			committer: ambiguousCommitter,
			tokenFor: new Map([[record.ref, token]]),
		});

		const result = await execute.browserWriteExecute(executeRequest(record));
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe("browser_write_commit_failed");
		expect(commitAttempts).toBe(1); // exactly one commit attempt, never retried
		expect(ledger.get(record.ref)?.status).toBe("failed");
	});
});
