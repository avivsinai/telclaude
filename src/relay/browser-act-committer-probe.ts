/**
 * Structured probe for the BrowserActExecutor committer (S3 browser writes).
 *
 * Drives the REAL `BrowserActExecutor` + `BrowserActSessionPool` + the REAL
 * `captureBrowserActEvidence` / `prepareBrowserWrite` / `verifyBrowserWriteExecution`
 * stack through a fake action driver fixture, asserting the security properties the
 * ledger relies on:
 *
 * - positive  — prepare → recapture-same-nonce → verify passes → commit fires the
 *               committing act EXACTLY ONCE with the approved values.
 * - drift     — page URL changed / submitted value changed / DOM mutated between
 *               prepare and recapture → the re-derived binding fails
 *               verifyBrowserWriteExecution and NO commit fires.
 * - custody   — a fresh random recapture nonce fails the binding (only the stored
 *               nonce re-produces it); the values fired are exactly the approved
 *               ones held in the pool, never agent-resupplied.
 * - restart   — the pool entry is evicted (relay restart / TTL lapse) → recapture
 *               fails closed (`browser_write_page_lost`) before any commit.
 *
 * The probe is a self-contained relay-side check (no docker-exec). It returns a
 * structured result; signing/attestation is layered by the ledger/approval stack
 * that consumes the committer, not by this probe.
 */

import type {
	TelclaudeMcpBrowserWriteSideEffectRecord,
	TelclaudeMcpSideEffectDomain,
} from "../hermes/mcp/side-effect-ledger.js";
import type {
	BrowserActEvidence,
	BrowserActJsonValue,
	BrowserActObservedSignals,
	BrowserActScreenshotSink,
} from "./browser-act-evidence.js";
import {
	type BrowserActDriver,
	BrowserActExecutor,
	type BrowserActRequest,
	type BrowserActVerb,
} from "./browser-act-executor.js";
import {
	type BrowserActLiveContext,
	type BrowserActLivePage,
	BrowserActSessionPool,
} from "./browser-act-session-pool.js";
import { verifyBrowserWriteExecution } from "./browser-write-confirm.js";

export const BROWSER_ACT_COMMITTER_PROBE_SCHEMA_VERSION =
	"telclaude.relay.browser-act-committer-probe.v1";

export interface BrowserActCommitterProbeCheck {
	readonly id: string;
	readonly pass: boolean;
	readonly detail: string;
}

export interface BrowserActCommitterProbeResult {
	readonly schemaVersion: typeof BROWSER_ACT_COMMITTER_PROBE_SCHEMA_VERSION;
	readonly pass: boolean;
	readonly checks: readonly BrowserActCommitterProbeCheck[];
}

// A fixed, non-secret fixture used only to derive the probe's commitment subkey. gitleaks:allow
const PROBE_CONTEXT_TOKEN_SECRET = "browser-act-committer-probe-secret-32bytes!";
const COMMIT_HOST = "shop.example.com";
const COMMIT_URL = "https://shop.example.com/checkout?step=review";
const COMMIT_DOM = "<html><body>review order</body></html>";
const APPROVED_VALUES: BrowserActJsonValue = { qty: "1", confirm: true };

/** A scriptable fake live page that records its closes and reports a current URL/DOM. */
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

/** Records every committing dispatch so the probe can assert "fires exactly once". */
class FakeDriver implements BrowserActDriver {
	readonly dispatched: Array<{
		readonly verb: BrowserActVerb;
		readonly target?: string;
		readonly submittedValues?: BrowserActJsonValue;
	}> = [];
	constructor(
		readonly page: FakeLivePage,
		readonly context: FakeContext,
	) {}
	async dispatch(input: {
		readonly verb: BrowserActVerb;
		readonly target?: string;
		readonly submittedValues?: BrowserActJsonValue;
	}): Promise<void> {
		this.dispatched.push(input);
	}
	async settle(): Promise<BrowserActObservedSignals> {
		return { navigation: true, formSubmit: true };
	}
}

function commitRequest(actionRef: string): BrowserActRequest & { readonly actionRef: string } {
	return {
		actor: "telegram:default:operator",
		profileId: "default",
		mcpDomain: "private",
		sessionRef: "probe-session",
		host: COMMIT_HOST,
		originScope: [COMMIT_HOST],
		verb: "click",
		target: "#checkout-form",
		submittedValues: APPROVED_VALUES,
		actionRef,
	};
}

/**
 * Build a browser-write ledger record that mirrors what `ledger.prepare` would
 * persist from a `PreparedBrowserWrite`. The committer only reads `ref`/
 * `sessionRef`/`actionVerb`/`actionTarget`/`evidenceNonce` from it, plus the
 * verify fields; we fill the rest with the prepared values so the record is a
 * faithful stand-in for the ledger's.
 */
function ledgerRecordFor(
	prepared: {
		readonly writeRef: string;
		readonly actor: string;
		readonly approver: string;
		readonly profile: string;
		readonly authorityDomain: TelclaudeMcpBrowserWriteSideEffectRecord["authorityDomain"];
		readonly host: string;
		readonly originScope: readonly string[];
		readonly evidenceRevision: string;
		readonly evidenceNonce: string;
		readonly bindingHash: string;
		readonly display: TelclaudeMcpBrowserWriteSideEffectRecord["display"];
		readonly commitSignal: TelclaudeMcpBrowserWriteSideEffectRecord["commitSignal"];
		readonly createdAtMs: number;
		readonly expiresAtMs: number;
	},
	actionRef: string,
): TelclaudeMcpBrowserWriteSideEffectRecord {
	return {
		ref: actionRef,
		kind: "browser-write",
		actorId: prepared.actor,
		approverActorId: prepared.approver,
		profileId: prepared.profile,
		domain: "private" as TelclaudeMcpSideEffectDomain,
		sessionRef: "probe-session",
		host: prepared.host,
		originScope: prepared.originScope,
		authorityDomain: prepared.authorityDomain,
		actionVerb: "click",
		actionTarget: "#checkout-form",
		evidenceRevision: prepared.evidenceRevision,
		evidenceNonce: prepared.evidenceNonce,
		display: prepared.display,
		commitSignal: prepared.commitSignal,
		approvalRequestId: "probe-approval",
		approvalRevision: 1,
		bindingHash: prepared.bindingHash,
		status: "executing",
		createdAtMs: prepared.createdAtMs,
		expiresAtMs: prepared.expiresAtMs,
	};
}

interface ProbeFixture {
	readonly executor: BrowserActExecutor;
	readonly pool: BrowserActSessionPool<BrowserActDriver>;
	readonly page: FakeLivePage;
	readonly driver: FakeDriver;
	readonly record: TelclaudeMcpBrowserWriteSideEffectRecord;
}

async function stage(actionRef: string): Promise<ProbeFixture> {
	const pool = new BrowserActSessionPool<BrowserActDriver>({ sweepIntervalMs: 0 });
	const page = new FakeLivePage(COMMIT_URL, COMMIT_DOM);
	const driver = new FakeDriver(page, new FakeContext());
	const executor = new BrowserActExecutor({
		driverFactory: () => driver,
		pool,
		screenshotSink: new FakeSink(),
		contextTokenSecret: PROBE_CONTEXT_TOKEN_SECRET,
		resolveApprover: () => "telegram:default:human",
	});
	const prepared = await executor.prepareIntent(commitRequest(actionRef));
	if (!prepared.committing) {
		throw new Error("probe: prepareIntent did not classify a committing act");
	}
	const record = ledgerRecordFor(prepared.prepared, actionRef);
	return { executor, pool, page, driver, record };
}

/**
 * The ledger gate: recapture → verifyBrowserWriteExecution → commit. Mirrors how
 * `browserWriteExecute` sequences the committer so the probe exercises the real
 * end-to-end path. Returns the outcome plus the dispatch count.
 */
async function runLedgerGate(
	fixture: ProbeFixture,
	now: number,
): Promise<{ committed: boolean; reason: string; dispatches: number }> {
	const committer = fixture.executor.committer();
	let currentEvidence: BrowserActEvidence;
	try {
		currentEvidence = await committer.recaptureEvidence(fixture.record);
	} catch (error) {
		return {
			committed: false,
			reason:
				error instanceof Error ? ((error as { code?: string }).code ?? error.message) : "error",
			dispatches: countCommittingDispatches(fixture),
		};
	}
	const verification = verifyBrowserWriteExecution({
		prepared: {
			writeRef: fixture.record.ref,
			actor: fixture.record.actorId,
			approver: fixture.record.approverActorId,
			profile: fixture.record.profileId,
			authorityDomain: fixture.record.authorityDomain,
			host: fixture.record.host,
			originScope: fixture.record.originScope,
			evidenceRevision: fixture.record.evidenceRevision,
			evidenceNonce: fixture.record.evidenceNonce,
			bindingHash: fixture.record.bindingHash,
			display: fixture.record.display,
			commitSignal: fixture.record.commitSignal,
			createdAtMs: fixture.record.createdAtMs,
			expiresAtMs: fixture.record.expiresAtMs,
		},
		context: {
			sessionRef: fixture.record.sessionRef,
			actor: fixture.record.actorId,
			profile: fixture.record.profileId,
			authorityDomain: fixture.record.authorityDomain,
			host: fixture.record.host,
			originScope: fixture.record.originScope,
		},
		action: { verb: fixture.record.actionVerb, target: fixture.record.actionTarget ?? undefined },
		currentEvidence,
		now,
	});
	if (!verification.ok) {
		return {
			committed: false,
			reason: verification.reason,
			dispatches: countCommittingDispatches(fixture),
		};
	}
	await committer.commit(fixture.record);
	return { committed: true, reason: "ok", dispatches: countCommittingDispatches(fixture) };
}

/** Count dispatches that fired the COMMITTING verb (prepare never dispatches). */
function countCommittingDispatches(fixture: ProbeFixture): number {
	return fixture.driver.dispatched.filter(
		(d) => d.verb === fixture.record.actionVerb && d.target === fixture.record.actionTarget,
	).length;
}

/** Drive the real committer through positive / drift / custody / restart scenarios. */
export async function runBrowserActCommitterProbe(): Promise<BrowserActCommitterProbeResult> {
	const checks: BrowserActCommitterProbeCheck[] = [];

	// positive: prepare never dispatches; recapture-same-nonce verifies; commit fires once.
	{
		const fixture = await stage("effect-positive");
		const preDispatch = countCommittingDispatches(fixture);
		const result = await runLedgerGate(fixture, Date.now());
		checks.push({
			id: "positive.commit_fires_exactly_once",
			pass:
				preDispatch === 0 &&
				result.committed &&
				result.dispatches === 1 &&
				fixture.pool.size() === 0,
			detail: `preDispatch=${preDispatch} committed=${result.committed} dispatches=${result.dispatches} poolSize=${fixture.pool.size()}`,
		});
		// custody: the values fired are exactly the approved ones (the pool's), and the
		// approved values never leaked into the ledger record.
		const fired = fixture.driver.dispatched.find((d) => d.verb === "click");
		checks.push({
			id: "custody.fires_approved_values",
			pass: JSON.stringify(fired?.submittedValues) === JSON.stringify(APPROVED_VALUES),
			detail: `fired=${JSON.stringify(fired?.submittedValues)}`,
		});
		checks.push({
			id: "custody.values_absent_from_ledger_record",
			pass: !JSON.stringify(fixture.record).includes("confirm"),
			detail: "approved submittedValues are not serialized in the browser-write record",
		});
	}

	// drift: a page change between prepare and recapture fails the binding → no commit.
	for (const scenario of ["url", "value", "dom"] as const) {
		const fixture = await stage(`effect-drift-${scenario}`);
		if (scenario === "url") fixture.page.currentUrl = "https://shop.example.com/checkout?step=paid";
		if (scenario === "dom") fixture.page.dom = "<html><body>review order CHANGED</body></html>";
		if (scenario === "value") {
			// A mutated approved value in custody simulates a tampered recapture: re-key
			// the pool entry with a different value so recapture re-derives a new binding.
			await fixture.pool.evict("probe-session", fixture.record.ref);
			fixture.pool.hold({
				sessionRef: "probe-session",
				actionRef: fixture.record.ref,
				driver: fixture.driver,
				approvedSubmittedValues: { qty: "9", confirm: true },
			});
		}
		const result = await runLedgerGate(fixture, Date.now());
		checks.push({
			id: `drift.${scenario}_fails_no_commit`,
			pass:
				!result.committed &&
				result.reason === "write_confirm_binding_drift" &&
				result.dispatches === 0,
			detail: `committed=${result.committed} reason=${result.reason} dispatches=${result.dispatches}`,
		});
	}

	// custody (nonce): a fresh random recapture nonce fails the binding on an unchanged page.
	{
		const fixture = await stage("effect-nonce");
		const committer = fixture.executor.committer();
		const recordWrongNonce: TelclaudeMcpBrowserWriteSideEffectRecord = {
			...fixture.record,
			evidenceNonce: "a-fresh-random-nonce",
		};
		const reEvidence = await committer.recaptureEvidence(recordWrongNonce);
		const drift = reEvidence.revision !== fixture.record.evidenceRevision;
		checks.push({
			id: "custody.fresh_nonce_breaks_binding",
			pass: drift && fixture.driver.dispatched.every((d) => d.verb !== "click"),
			detail: `revisionDiffers=${drift}`,
		});
	}

	// restart: pool evicted (relay restart / TTL) → recapture fails closed before commit.
	{
		const fixture = await stage("effect-restart");
		await fixture.pool.evict("probe-session", fixture.record.ref);
		const result = await runLedgerGate(fixture, Date.now());
		checks.push({
			id: "restart.pool_lost_fails_closed",
			pass:
				!result.committed && result.reason === "browser_write_page_lost" && result.dispatches === 0,
			detail: `committed=${result.committed} reason=${result.reason}`,
		});
	}

	return {
		schemaVersion: BROWSER_ACT_COMMITTER_PROBE_SCHEMA_VERSION,
		pass: checks.every((c) => c.pass),
		checks,
	};
}
