import { describe, expect, it } from "vitest";
import type { TelclaudeMcpBrowserWriteSideEffectRecord } from "../../src/hermes/mcp/side-effect-ledger.js";
import type {
	BrowserActJsonValue,
	BrowserActObservedSignals,
	BrowserActScreenshotSink,
} from "../../src/relay/browser-act-evidence.js";
import {
	type BrowserActDriver,
	BrowserActExecutor,
	BrowserActExecutorError,
	type BrowserActRequest,
	type BrowserActVerb,
	deriveBrowserActCommitmentSecret,
} from "../../src/relay/browser-act-executor.js";
import {
	type BrowserActLiveContext,
	type BrowserActLivePage,
	BrowserActSessionPool,
} from "../../src/relay/browser-act-session-pool.js";
import { verifyBrowserWriteExecution } from "../../src/relay/browser-write-confirm.js";

const CONTEXT_TOKEN_SECRET = "browser-act-executor-test-secret-32bytes!";

const PAGE_URL = "https://shop.example.com/checkout?step=review";
const PAGE_DOM = "<html><body>review order</body></html>";
const HOST = "shop.example.com";
const APPROVED_VALUES: BrowserActJsonValue = { qty: "1", to: "alice@example.com" };

class FakeLivePage implements BrowserActLivePage {
	closes = 0;
	constructor(
		public currentUrl: string,
		public dom: string,
		private readonly screenshotBytes: Uint8Array = Buffer.from("png-bytes"),
	) {}
	url(): string {
		return this.currentUrl;
	}
	async evaluate<T>(_expression: string): Promise<T> {
		return this.dom as T;
	}
	async screenshot(): Promise<Uint8Array> {
		return this.screenshotBytes;
	}
	async close(): Promise<void> {
		this.closes += 1;
	}
}

class FakeContext implements BrowserActLiveContext {
	closes = 0;
	async close(): Promise<void> {
		this.closes += 1;
	}
}

class FakeSink implements BrowserActScreenshotSink {
	async storeScreenshot(input: { readonly hash: string }): Promise<string> {
		return `att_${input.hash.slice("sha256:".length, "sha256:".length + 16)}`;
	}
}

class FakeDriver implements BrowserActDriver {
	readonly dispatched: Array<{
		readonly verb: BrowserActVerb;
		readonly target?: string;
		readonly submittedValues?: BrowserActJsonValue;
	}> = [];
	settleCalls = 0;
	constructor(
		readonly page: FakeLivePage,
		readonly context: FakeContext,
		private readonly observed: BrowserActObservedSignals = { navigation: true, formSubmit: true },
		private readonly onDispatch?: (verb: BrowserActVerb) => void,
	) {}
	async dispatch(input: {
		readonly verb: BrowserActVerb;
		readonly target?: string;
		readonly submittedValues?: BrowserActJsonValue;
	}): Promise<void> {
		this.dispatched.push(input);
		this.onDispatch?.(input.verb);
	}
	async settle(): Promise<BrowserActObservedSignals> {
		this.settleCalls += 1;
		return this.observed;
	}
}

function commitRequest(
	actionRef: string,
	overrides: Partial<BrowserActRequest> = {},
): BrowserActRequest & { readonly actionRef: string } {
	return {
		actor: "telegram:default:operator",
		profileId: "default",
		mcpDomain: "private",
		sessionRef: "sess-1",
		host: HOST,
		originScope: [HOST],
		verb: "click",
		target: "#checkout-form",
		submittedValues: APPROVED_VALUES,
		actionRef,
		...overrides,
	};
}

function buildExecutor(opts: { driver?: FakeDriver; now?: () => number }): {
	executor: BrowserActExecutor;
	pool: BrowserActSessionPool<BrowserActDriver>;
} {
	const pool = new BrowserActSessionPool<BrowserActDriver>({ sweepIntervalMs: 0, now: opts.now });
	const driver =
		opts.driver ?? new FakeDriver(new FakeLivePage(PAGE_URL, PAGE_DOM), new FakeContext());
	const executor = new BrowserActExecutor({
		driverFactory: () => driver,
		pool,
		screenshotSink: new FakeSink(),
		contextTokenSecret: CONTEXT_TOKEN_SECRET,
		resolveApprover: () => "telegram:default:human",
		...(opts.now ? { now: opts.now } : {}),
	});
	return { executor, pool };
}

/** Build a faithful browser-write ledger record from a prepared write. */
function recordFor(
	prepared: Awaited<ReturnType<BrowserActExecutor["prepareIntent"]>> extends { prepared: infer P }
		? P
		: never,
	actionRef: string,
	overrides: Partial<TelclaudeMcpBrowserWriteSideEffectRecord> = {},
): TelclaudeMcpBrowserWriteSideEffectRecord {
	const p = prepared as {
		actor: string;
		approver: string;
		profile: string;
		authorityDomain: TelclaudeMcpBrowserWriteSideEffectRecord["authorityDomain"];
		host: string;
		originScope: readonly string[];
		evidenceRevision: string;
		evidenceNonce: string;
		bindingHash: string;
		display: TelclaudeMcpBrowserWriteSideEffectRecord["display"];
		commitSignal: TelclaudeMcpBrowserWriteSideEffectRecord["commitSignal"];
		createdAtMs: number;
		expiresAtMs: number;
	};
	return {
		ref: actionRef,
		kind: "browser-write",
		actorId: p.actor,
		approverActorId: p.approver,
		profileId: p.profile,
		domain: "private",
		sessionRef: "sess-1",
		host: p.host,
		originScope: p.originScope,
		authorityDomain: p.authorityDomain,
		actionVerb: "click",
		actionTarget: "#checkout-form",
		evidenceRevision: p.evidenceRevision,
		evidenceNonce: p.evidenceNonce,
		display: p.display,
		commitSignal: p.commitSignal,
		approvalRequestId: "appr-1",
		approvalRevision: 1,
		bindingHash: p.bindingHash,
		status: "executing",
		createdAtMs: p.createdAtMs,
		expiresAtMs: p.expiresAtMs,
		...overrides,
	};
}

function verify(
	record: TelclaudeMcpBrowserWriteSideEffectRecord,
	currentEvidence: Awaited<
		ReturnType<ReturnType<BrowserActExecutor["committer"]>["recaptureEvidence"]>
	>,
	now?: number,
) {
	return verifyBrowserWriteExecution({
		prepared: {
			writeRef: record.ref,
			actor: record.actorId,
			approver: record.approverActorId,
			profile: record.profileId,
			authorityDomain: record.authorityDomain,
			host: record.host,
			originScope: record.originScope,
			evidenceRevision: record.evidenceRevision,
			evidenceNonce: record.evidenceNonce,
			bindingHash: record.bindingHash,
			display: record.display,
			commitSignal: record.commitSignal,
			createdAtMs: record.createdAtMs,
			expiresAtMs: record.expiresAtMs,
		},
		context: {
			sessionRef: record.sessionRef,
			actor: record.actorId,
			profile: record.profileId,
			authorityDomain: record.authorityDomain,
			host: record.host,
			originScope: record.originScope,
		},
		action: { verb: record.actionVerb, target: record.actionTarget ?? undefined },
		currentEvidence,
		...(now !== undefined ? { now } : {}),
	});
}

describe("deriveBrowserActCommitmentSecret", () => {
	it("derives a 32-byte key and fails closed on a short secret", () => {
		const key = deriveBrowserActCommitmentSecret(CONTEXT_TOKEN_SECRET);
		expect(key.byteLength).toBe(32);
		expect(() => deriveBrowserActCommitmentSecret("too-short")).toThrowError(
			BrowserActExecutorError,
		);
	});
});

describe("BrowserActExecutor non-committing act", () => {
	it("runs a fill inline, returns evidence, and keeps no pool custody", async () => {
		const driver = new FakeDriver(new FakeLivePage(PAGE_URL, PAGE_DOM), new FakeContext(), {});
		const { executor, pool } = buildExecutor({ driver });
		const result = await executor.act(
			commitRequest("n/a", { verb: "fill", target: "#email", submittedValues: "a@b.com" }),
		);
		expect(result.committing).toBe(false);
		if (result.committing) throw new Error("unreachable");
		expect(result.evidence.commitSignal.forceConfirm).toBe(false);
		expect(driver.dispatched).toHaveLength(1);
		expect(driver.dispatched[0]?.verb).toBe("fill");
		expect(driver.page.closes).toBe(1);
		expect(driver.context.closes).toBe(1);
		expect(pool.size()).toBe(0);
	});

	it("refuses a committing verb on the inline path (must prepareIntent)", async () => {
		const { executor } = buildExecutor({});
		await expect(executor.act(commitRequest("n/a"))).rejects.toMatchObject({
			code: "browser_act_requires_prepare",
		});
	});

	it("refuses an inline goto (committing) WITHOUT dispatching the navigation", async () => {
		const driver = new FakeDriver(new FakeLivePage(PAGE_URL, PAGE_DOM), new FakeContext(), {});
		const { executor, pool } = buildExecutor({ driver });
		await expect(
			executor.act(
				commitRequest("n/a", {
					verb: "goto",
					target: undefined,
					submittedValues: "https://shop.example.com/account/delete",
				}),
			),
		).rejects.toMatchObject({ code: "browser_act_requires_prepare" });
		// The navigation never fired: classify refuses BEFORE any driver dispatch.
		expect(driver.dispatched).toHaveLength(0);
		expect(driver.dispatched.some((d) => d.verb === "goto")).toBe(false);
		expect(driver.settleCalls).toBe(0);
		expect(pool.size()).toBe(0);
	});

	it("stages an escalated non-committing fill (forceConfirm:true) instead of refusing", async () => {
		const driver = new FakeDriver(new FakeLivePage(PAGE_URL, PAGE_DOM), new FakeContext(), {});
		const { executor } = buildExecutor({ driver });
		await expect(
			executor.act(
				commitRequest("n/a", {
					verb: "fill",
					target: "#email",
					submittedValues: "a@b.com",
					forceConfirm: true,
				}),
			),
		).rejects.toMatchObject({ code: "browser_act_requires_prepare" });
		// An escalated act must NOT run inline either; the driver never dispatched.
		expect(driver.dispatched).toHaveLength(0);
	});
});

describe("BrowserActExecutor prepareIntent", () => {
	it("holds the live driver + approved values without firing the act", async () => {
		const driver = new FakeDriver(new FakeLivePage(PAGE_URL, PAGE_DOM), new FakeContext());
		const { executor, pool } = buildExecutor({ driver });
		const prepared = await executor.prepareIntent(commitRequest("effect-1"));
		expect(prepared.committing).toBe(true);
		if (!prepared.committing) throw new Error("unreachable");
		expect(prepared.prepared.commitSignal.forceConfirm).toBe(true);
		// prepare never dispatches the act.
		expect(driver.dispatched).toHaveLength(0);
		// The live page is held, not closed.
		expect(driver.page.closes).toBe(0);
		expect(pool.size()).toBe(1);
		const entry = pool.get("sess-1", "effect-1");
		expect(entry?.approvedSubmittedValues).toEqual(APPROVED_VALUES);
	});

	it("stages a goto (committing) without firing the navigation; commit fires it post-approval", async () => {
		const dest = "https://shop.example.com/account/delete";
		const driver = new FakeDriver(new FakeLivePage(PAGE_URL, PAGE_DOM), new FakeContext());
		const { executor, pool } = buildExecutor({ driver });
		const prepared = await executor.prepareIntent(
			commitRequest("effect-goto", {
				verb: "goto",
				target: undefined,
				submittedValues: dest,
			}),
		);
		expect(prepared.committing).toBe(true);
		if (!prepared.committing) throw new Error("unreachable");
		// goto is committing → forceConfirm true → staged, not refused.
		expect(prepared.prepared.commitSignal.forceConfirm).toBe(true);
		// prepare never navigates; the page is held live, not closed.
		expect(driver.dispatched).toHaveLength(0);
		expect(driver.page.closes).toBe(0);
		expect(pool.size()).toBe(1);

		// The committer fires the goto exactly once, post-approval, with the approved dest.
		const record = recordFor(prepared.prepared, "effect-goto", {
			actionVerb: "goto",
			actionTarget: null,
		});
		const committer = executor.committer();
		await committer.recaptureEvidence(record);
		await committer.commit(record);
		const gotos = driver.dispatched.filter((d) => d.verb === "goto");
		expect(gotos).toHaveLength(1);
		expect(gotos[0]?.submittedValues).toBe(dest);
		expect(pool.size()).toBe(0);
	});

	it("stages an escalated non-committing fill (forceConfirm:true) instead of browser_act_not_committing", async () => {
		const driver = new FakeDriver(new FakeLivePage(PAGE_URL, PAGE_DOM), new FakeContext(), {});
		const { executor, pool } = buildExecutor({ driver });
		const prepared = await executor.prepareIntent(
			commitRequest("effect-esc", {
				verb: "fill",
				target: "#email",
				submittedValues: "a@b.com",
				forceConfirm: true,
			}),
		);
		expect(prepared.committing).toBe(true);
		if (!prepared.committing) throw new Error("unreachable");
		// The relay-set forceConfirm escalates a non-committing verb into a staged write.
		expect(prepared.prepared.commitSignal.forceConfirm).toBe(true);
		expect(prepared.prepared.commitSignal.reasons).toContain("action.force_confirm");
		// Still no firing at prepare time; page held for approval.
		expect(driver.dispatched).toHaveLength(0);
		expect(pool.size()).toBe(1);
	});
});

describe("BrowserActExecutor committer (W3 recapture + commit)", () => {
	it("recaptures with the STORED nonce + approved values; an unchanged page passes, commit fires once", async () => {
		const driver = new FakeDriver(new FakeLivePage(PAGE_URL, PAGE_DOM), new FakeContext());
		const { executor, pool } = buildExecutor({ driver });
		const prepared = await executor.prepareIntent(commitRequest("effect-1"));
		if (!prepared.committing) throw new Error("unreachable");
		const record = recordFor(prepared.prepared, "effect-1");

		const committer = executor.committer();
		const current = await committer.recaptureEvidence(record);
		expect(current.evidenceNonce).toBe(record.evidenceNonce);
		expect(verify(record, current)).toEqual({ ok: true, reason: "ok" });

		await committer.commit(record);
		const submits = driver.dispatched.filter((d) => d.verb === "click");
		expect(submits).toHaveLength(1);
		expect(submits[0]?.submittedValues).toEqual(APPROVED_VALUES);
		// Pool entry evicted after commit; the live page is closed.
		expect(pool.size()).toBe(0);
		expect(driver.page.closes).toBe(1);
	});

	it("returns an ORIGIN-ONLY finalUrl in the commit receipt (no path/query/token leak)", async () => {
		const page = new FakeLivePage(PAGE_URL, PAGE_DOM);
		const driver = new FakeDriver(page, new FakeContext());
		const { executor } = buildExecutor({ driver });
		const prepared = await executor.prepareIntent(commitRequest("effect-1"));
		if (!prepared.committing) throw new Error("unreachable");
		const record = recordFor(prepared.prepared, "effect-1");
		const committer = executor.committer();
		await committer.recaptureEvidence(record);
		// The post-commit landing URL carries a secret-bearing token in the query.
		page.currentUrl = "https://shop.example.com/account?session=SECRET_TOKEN_abc123&path=/private";
		const { receipt } = await committer.commit(record);
		// Receipt exposes ONLY the origin — no path, query, or token.
		expect(receipt.finalUrlOrigin).toBe("https://shop.example.com");
		expect(receipt).not.toHaveProperty("finalUrl");
		const serialized = JSON.stringify(receipt);
		expect(serialized).not.toContain("SECRET_TOKEN");
		expect(serialized).not.toContain("session=");
		expect(serialized).not.toContain("/private");
	});

	it("fails binding drift when the page mutates between prepare and recapture", async () => {
		const page = new FakeLivePage(PAGE_URL, PAGE_DOM);
		const driver = new FakeDriver(page, new FakeContext());
		const { executor } = buildExecutor({ driver });
		const prepared = await executor.prepareIntent(commitRequest("effect-1"));
		if (!prepared.committing) throw new Error("unreachable");
		const record = recordFor(prepared.prepared, "effect-1");

		page.dom = "<html><body>review order CHANGED</body></html>";
		const committer = executor.committer();
		const current = await committer.recaptureEvidence(record);
		const check = verify(record, current);
		expect(check).toEqual({ ok: false, reason: "write_confirm_binding_drift" });
		// The ledger would NOT call commit; assert no committing dispatch fired.
		expect(driver.dispatched.some((d) => d.verb === "click")).toBe(false);
	});

	it("fails binding drift when the approved value in custody differs (values drift)", async () => {
		const driver = new FakeDriver(new FakeLivePage(PAGE_URL, PAGE_DOM), new FakeContext());
		const { executor, pool } = buildExecutor({ driver });
		const prepared = await executor.prepareIntent(commitRequest("effect-1"));
		if (!prepared.committing) throw new Error("unreachable");
		const record = recordFor(prepared.prepared, "effect-1");
		// Tamper the pooled approved values: recapture re-derives a different binding.
		await pool.evict("sess-1", "effect-1");
		pool.hold({
			sessionRef: "sess-1",
			actionRef: "effect-1",
			driver,
			approvedSubmittedValues: { qty: "9", to: "mallory@evil.com" },
		});
		const committer = executor.committer();
		const current = await committer.recaptureEvidence(record);
		expect(verify(record, current)).toEqual({ ok: false, reason: "write_confirm_binding_drift" });
	});

	it("a fresh random recapture nonce breaks the binding (custody nonce lock)", async () => {
		const driver = new FakeDriver(new FakeLivePage(PAGE_URL, PAGE_DOM), new FakeContext());
		const { executor } = buildExecutor({ driver });
		const prepared = await executor.prepareIntent(commitRequest("effect-1"));
		if (!prepared.committing) throw new Error("unreachable");
		const record = recordFor(prepared.prepared, "effect-1");
		const wrongNonce = recordFor(prepared.prepared, "effect-1", {
			evidenceNonce: "a-totally-different-nonce",
		});
		const committer = executor.committer();
		const current = await committer.recaptureEvidence(wrongNonce);
		// Re-derived revision differs → the stored binding fails.
		expect(verify(record, current)).toEqual({ ok: false, reason: "write_confirm_binding_drift" });
	});

	it("commit fires exactly once even if invoked after a passing verify (no double dispatch)", async () => {
		const driver = new FakeDriver(new FakeLivePage(PAGE_URL, PAGE_DOM), new FakeContext());
		const { executor, pool } = buildExecutor({ driver });
		const prepared = await executor.prepareIntent(commitRequest("effect-1"));
		if (!prepared.committing) throw new Error("unreachable");
		const record = recordFor(prepared.prepared, "effect-1");
		const committer = executor.committer();
		const current = await committer.recaptureEvidence(record);
		expect(verify(record, current).ok).toBe(true);
		await committer.commit(record);
		// A second commit attempt fails closed: the pool entry is gone.
		await expect(committer.commit(record)).rejects.toMatchObject({
			code: "browser_write_page_lost",
		});
		expect(driver.dispatched.filter((d) => d.verb === "click")).toHaveLength(1);
		expect(pool.size()).toBe(0);
	});
});

describe("BrowserActExecutor fail-closed: TTL + restart", () => {
	it("recapture fails closed after the pool entry expires (TTL)", async () => {
		let clock = 1_000;
		const driver = new FakeDriver(new FakeLivePage(PAGE_URL, PAGE_DOM), new FakeContext());
		const pool = new BrowserActSessionPool<BrowserActDriver>({
			sweepIntervalMs: 0,
			ttlMs: 30_000,
			now: () => clock,
		});
		const executor = new BrowserActExecutor({
			driverFactory: () => driver,
			pool,
			screenshotSink: new FakeSink(),
			contextTokenSecret: CONTEXT_TOKEN_SECRET,
			resolveApprover: () => "telegram:default:human",
			now: () => clock,
		});
		const prepared = await executor.prepareIntent(commitRequest("effect-1"));
		if (!prepared.committing) throw new Error("unreachable");
		const record = recordFor(prepared.prepared, "effect-1");
		clock += 30_001; // past TTL
		const committer = executor.committer();
		await expect(committer.recaptureEvidence(record)).rejects.toMatchObject({
			code: "browser_write_page_lost",
		});
		expect(driver.dispatched.some((d) => d.verb === "click")).toBe(false);
	});

	it("recapture fails closed when the pool is empty (relay restart)", async () => {
		const driver = new FakeDriver(new FakeLivePage(PAGE_URL, PAGE_DOM), new FakeContext());
		const { executor, pool } = buildExecutor({ driver });
		const prepared = await executor.prepareIntent(commitRequest("effect-1"));
		if (!prepared.committing) throw new Error("unreachable");
		const record = recordFor(prepared.prepared, "effect-1");
		// Simulate a restart: a brand-new (empty) pool + executor; the held page is gone.
		const fresh = buildExecutor({
			driver: new FakeDriver(new FakeLivePage(PAGE_URL, PAGE_DOM), new FakeContext()),
		});
		const committer = fresh.executor.committer();
		await expect(committer.recaptureEvidence(record)).rejects.toMatchObject({
			code: "browser_write_page_lost",
		});
		expect(fresh.pool.size()).toBe(0);
		// The original pool still holds it (we never committed); evict to clean up.
		await pool.evict("sess-1", "effect-1");
	});
});

describe("BrowserActSessionPool per-session serial lock", () => {
	it("serializes acts on the same session, runs different sessions in parallel", async () => {
		const pool = new BrowserActSessionPool<BrowserActDriver>({ sweepIntervalMs: 0 });
		const order: string[] = [];
		const slow = (label: string, ms: number) =>
			pool.withSessionLock("sess-A", async () => {
				order.push(`A:${label}:start`);
				await new Promise((r) => setTimeout(r, ms));
				order.push(`A:${label}:end`);
			});
		const other = pool.withSessionLock("sess-B", async () => {
			order.push("B:start");
			order.push("B:end");
		});
		const first = slow("1", 20);
		const second = slow("2", 0);
		await Promise.all([first, second, other]);
		// sess-A acts never interleave: 1 fully completes before 2 starts.
		expect(order.indexOf("A:1:end")).toBeLessThan(order.indexOf("A:2:start"));
	});
});
