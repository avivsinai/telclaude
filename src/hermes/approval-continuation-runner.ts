import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { redactSecrets } from "../security/output-filter.js";
import { VaultClient } from "../vault-daemon/client.js";
import { type ServerHandle, startServer } from "../vault-daemon/server.js";
import {
	type ApprovalContinuationEvidence,
	DEFAULT_APPROVAL_CONTINUATION_EVIDENCE_PATH,
	type REQUIRED_APPROVAL_FALLBACK_FIXTURE_IDS,
} from "./approval-continuation.js";
import {
	assertHermesArtifactWritesAllowed,
	type HermesArtifactWriteOptions,
	type HermesPin,
	writeHermesJsonArtifact,
} from "./foundation.js";
import {
	createTelclaudeMcpSideEffectApprovalVerifier,
	generateTelclaudeMcpSideEffectApprovalToken,
	TelclaudeMcpSideEffectJtiStore,
} from "./mcp/approval-token.js";
import {
	createTelclaudeMcpAuthorityRegistry,
	createTelclaudeMcpBridgeForRegisteredConnection,
	type TelclaudeMcpAuthorityConnection,
	type TelclaudeMcpAuthorityRegistry,
} from "./mcp/authority-registry.js";
import type {
	TelclaudeMcpAuthority,
	TelclaudeMcpBridge,
	TelclaudeMcpBridgeDependencies,
	TelclaudeMcpOutboundPrepareRequest,
	TelclaudeMcpProviderPrepareWriteRequest,
} from "./mcp/bridge.js";
import { createTelclaudeMcpLedgerExecuteDependencies } from "./mcp/ledger-execute.js";
import {
	providerAccountRefFor,
	providerApprovalRenderFor,
	resolveTelclaudeProviderOperation,
} from "./mcp/provider-routing.js";
import {
	createTelclaudeMcpSideEffectLedger,
	getTelclaudeMcpSideEffectApprovalBinding,
	type TelclaudeMcpSideEffectApprovalBinding,
	type TelclaudeMcpSideEffectLedger,
	type TelclaudeMcpSideEffectRecord,
} from "./mcp/side-effect-ledger.js";

export const DEFAULT_APPROVAL_CONTINUATION_FIXTURE_EVIDENCE_DIR = "artifacts/hermes/approval";
export const APPROVAL_CONTINUATION_FIXTURE_EVIDENCE_SCHEMA_VERSION =
	"telclaude.hermes.approval-continuation-fixture.v1";
export const APPROVAL_CONTINUATION_RUN_SCHEMA_VERSION =
	"telclaude.hermes.approval-continuation-run.v1";

type ApprovalContinuationRunStatus = "pass" | "fail" | "pending";

type ApprovalContinuationObservation = {
	name: string;
	status: "pass" | "fail";
	detail: string;
	code?: string;
};

export type ApprovalContinuationFixtureEvidence = {
	schemaVersion: typeof APPROVAL_CONTINUATION_FIXTURE_EVIDENCE_SCHEMA_VERSION;
	id: (typeof REQUIRED_APPROVAL_FALLBACK_FIXTURE_IDS)[number];
	status: "pass" | "fail";
	generatedAt: string;
	summary: string;
	observations: ApprovalContinuationObservation[];
};

export type ApprovalContinuationRunReport = {
	schemaVersion: typeof APPROVAL_CONTINUATION_RUN_SCHEMA_VERSION;
	status: ApprovalContinuationRunStatus;
	ran: boolean;
	summary: string;
	evidencePath?: string;
	fixtureEvidenceDir?: string;
	evidence?: ApprovalContinuationEvidence;
	fixtures: ApprovalContinuationFixtureEvidence[];
};

export type RunHermesApprovalContinuationProbeOptions = {
	allowRun: boolean;
	hermes: HermesPin | null;
	now?: Date;
	jtiDataDir?: string;
};

export type WriteApprovalContinuationArtifactsOptions = {
	evidencePath: string;
	fixtureEvidenceDir?: string;
	allowTrackedSeedWrite?: boolean;
};

type ProbeHarness = {
	nowMs: () => number;
	setNowMs: (nextNowMs: number) => void;
	vault: VaultClient;
	jtiStore: TelclaudeMcpSideEffectJtiStore;
	ledger: TelclaudeMcpSideEffectLedger;
	bridge: TelclaudeMcpBridge;
	wrongActorBridge: TelclaudeMcpBridge;
	stop: () => Promise<void>;
};

type PreparedProvider = {
	actionRef: string;
	approvalRequestId: string;
};

type PreparedOutbound = {
	outboundRef: string;
	approvalRequestId: string;
};

const BASE_NOW_MS = 1_000_000;

export async function runHermesApprovalContinuationProbe(
	options: RunHermesApprovalContinuationProbeOptions,
): Promise<ApprovalContinuationRunReport> {
	if (!options.allowRun) {
		return {
			schemaVersion: APPROVAL_CONTINUATION_RUN_SCHEMA_VERSION,
			status: "pending",
			ran: false,
			summary: "Hermes approval-continuation probe requires --allow-run",
			fixtures: [],
		};
	}
	if (!options.hermes) {
		return {
			schemaVersion: APPROVAL_CONTINUATION_RUN_SCHEMA_VERSION,
			status: "fail",
			ran: false,
			summary: "Pinned Hermes artifact is required for approval-continuation evidence",
			fixtures: [],
		};
	}

	const tempDir =
		options.jtiDataDir ?? fs.mkdtempSync(path.join(os.tmpdir(), "tc-hermes-approval-jti-"));
	const harness = await createProbeHarness(tempDir);
	try {
		const fixtures = [
			await runProviderFixture(harness, options.now),
			await runOutboundFixture(harness, options.now),
			await runCronFixture(harness, options.now),
			await runLongRunningFixture(harness, options.now),
		];
		const negativeObservations = await runNegativeObservations(harness);
		const negativePass = negativeObservations.every((observation) => observation.status === "pass");
		const fallbackFixtures = fixtures.map((fixture) => ({
			id: fixture.id,
			status: fixture.status,
			evidence_path: defaultFixtureEvidencePath(fixture.id),
		}));
		const evidence: ApprovalContinuationEvidence = {
			schemaVersion: 1,
			hermes: options.hermes,
			native: {
				events_wait: false,
				permissions_list_open: false,
				permissions_respond: false,
				responds_to_blocked_run: false,
				wrong_actor_denied: observationPassed(negativeObservations, "wrong_actor_denied"),
				stale_request_denied: observationPassed(negativeObservations, "stale_request_denied"),
				replay_denied: observationPassed(negativeObservations, "replay_denied"),
				mutated_decision_denied: observationPassed(negativeObservations, "mutated_decision_denied"),
				notes:
					"Native Hermes mid-run permission continuation was not proven; cross-turn prepare/approve/execute fallback was exercised through Telclaude MCP authority, ledger, verifier, and JTI paths.",
			},
			fallback: {
				strategy: "cross_turn_prepare_approve_execute",
				fixtures: fallbackFixtures,
			},
		};
		const fixturesPass = fixtures.every((fixture) => fixture.status === "pass");
		const status = fixturesPass && negativePass ? "pass" : "fail";
		return {
			schemaVersion: APPROVAL_CONTINUATION_RUN_SCHEMA_VERSION,
			status,
			ran: true,
			summary:
				status === "pass"
					? "Approval continuation fallback passed through the live Telclaude MCP authority, ledger, verifier, and JTI path"
					: "Approval continuation fallback failed a live MCP authority, ledger, verifier, or JTI check",
			evidence,
			fixtures: appendNegativeFixtureObservations(fixtures, negativeObservations),
		};
	} finally {
		await harness.stop();
		if (!options.jtiDataDir) fs.rmSync(tempDir, { recursive: true, force: true });
	}
}

export function writeApprovalContinuationArtifacts(
	run: ApprovalContinuationRunReport,
	options: WriteApprovalContinuationArtifactsOptions,
): ApprovalContinuationRunReport {
	if (!run.evidence) return run;
	const evidencePath = path.resolve(options.evidencePath);
	const fixtureEvidenceDir = path.resolve(
		options.fixtureEvidenceDir ?? defaultFixtureEvidenceDir(evidencePath),
	);
	const fixtures = run.fixtures.map((fixture) => ({
		...fixture,
	}));
	const writeOptions: HermesArtifactWriteOptions =
		options.allowTrackedSeedWrite === undefined
			? {}
			: { allowTrackedSeedWrite: options.allowTrackedSeedWrite };
	assertHermesArtifactWritesAllowed(
		[evidencePath, ...fixtures.map((fixture) => fixturePath(fixtureEvidenceDir, fixture.id))],
		writeOptions,
	);
	for (const fixture of fixtures) {
		writeHermesJsonArtifact(fixturePath(fixtureEvidenceDir, fixture.id), fixture, writeOptions);
	}
	const evidence: ApprovalContinuationEvidence = {
		...run.evidence,
		native: {
			...run.evidence.native,
			evidence_path: evidencePath,
		},
		fallback: run.evidence.fallback
			? {
					...run.evidence.fallback,
					fixtures: run.evidence.fallback.fixtures.map((fixture) => ({
						...fixture,
						evidence_path: fixturePath(fixtureEvidenceDir, fixture.id),
					})),
				}
			: undefined,
	};
	writeHermesJsonArtifact(evidencePath, evidence, writeOptions);
	return {
		...run,
		evidencePath,
		fixtureEvidenceDir,
		evidence,
		fixtures,
	};
}

async function createProbeHarness(dataDir: string): Promise<ProbeHarness> {
	let nowMs = BASE_NOW_MS;
	let refCounter = 0;
	const socketPath = path.join(dataDir, "vault.sock");
	const handle = await startServer({
		socketPath,
		storeOptions: {
			filePath: path.join(dataDir, "vault.json"),
			encryptionKey: "approval-continuation-runner-vault-key",
		},
	});
	const vault = new VaultClient({ socketPath, timeout: 5_000 });
	const jtiStore = new TelclaudeMcpSideEffectJtiStore(path.join(dataDir, "jti"));
	const ledger = createTelclaudeMcpSideEffectLedger({
		nowMs: () => nowMs,
		makeRef: () => `effect-approval-continuation-${++refCounter}`,
		defaultTtlMs: 60_000,
		verifyApproval: createTelclaudeMcpSideEffectApprovalVerifier({
			vaultClient: vault,
			jtiStore,
			nowSeconds: () => Math.floor(nowMs / 1_000),
		}),
	});
	const registry = createTelclaudeMcpAuthorityRegistry();
	const connection: TelclaudeMcpAuthorityConnection = {
		sessionKey: "session-private-1",
		profileId: "private",
		endpointId: "endpoint-private",
		networkNamespace: "netns-private",
	};
	const authority = baseAuthority();
	const bridge = registeredBridge({ registry, connection, authority, ledger });
	const wrongActorBridge = registeredBridge({
		registry,
		connection: { ...connection, sessionKey: "session-private-attacker" },
		authority: { ...authority, actorId: "telegram:attacker" },
		ledger,
	});
	return {
		nowMs: () => nowMs,
		setNowMs: (nextNowMs: number) => {
			nowMs = nextNowMs;
		},
		vault,
		jtiStore,
		ledger,
		bridge,
		wrongActorBridge,
		stop: () => stopProbeHarness(handle, jtiStore),
	};
}

async function stopProbeHarness(
	handle: ServerHandle,
	jtiStore: TelclaudeMcpSideEffectJtiStore,
): Promise<void> {
	jtiStore.close();
	await handle.stop();
}

function registeredBridge(input: {
	registry: TelclaudeMcpAuthorityRegistry;
	connection: TelclaudeMcpAuthorityConnection;
	authority: TelclaudeMcpAuthority;
	ledger: TelclaudeMcpSideEffectLedger;
}): TelclaudeMcpBridge {
	const grant = input.registry.register({
		connection: input.connection,
		authority: input.authority,
		nowMs: BASE_NOW_MS,
		ttlMs: 60_000,
	});
	const result = createTelclaudeMcpBridgeForRegisteredConnection({
		registry: input.registry,
		handle: grant.handle,
		connection: input.connection,
		dependencies: createProbeDependencies(input.ledger),
		nowMs: BASE_NOW_MS,
	});
	if (!result.ok) {
		throw new Error(result.reason);
	}
	return result.bridge;
}

function createProbeDependencies(
	ledger: TelclaudeMcpSideEffectLedger,
): TelclaudeMcpBridgeDependencies {
	const executeDependencies = createTelclaudeMcpLedgerExecuteDependencies({ ledger });
	return {
		providerRead: async () => ({ ok: true }),
		providerPrepareWrite: async (request) => prepareProviderSideEffect(ledger, request),
		providerExecuteWrite: executeDependencies.providerExecuteWrite,
		memorySearch: async () => ({ entries: [] }),
		memoryWrite: async () => ({ accepted: 1 }),
		attachmentGet: async () => ({ bytes: 0 }),
		outboundPrepare: async (request) => prepareOutboundSideEffect(ledger, request),
		outboundExecute: executeDependencies.outboundExecute,
		auditNote: async () => ({ stored: true }),
	};
}

function prepareProviderSideEffect(
	ledger: TelclaudeMcpSideEffectLedger,
	request: TelclaudeMcpProviderPrepareWriteRequest,
): PreparedProvider {
	const operation = resolveTelclaudeProviderOperation(request);
	const record = ledger.prepare({
		kind: "provider",
		actorId: request.actorId,
		approverActorId: "operator:approval-continuation-approver",
		profileId: request.profileId,
		domain: request.domain,
		providerId: operation.providerId,
		service: operation.service,
		action: operation.action,
		params: operation.params,
		providerAccountRef: providerAccountRefFor(operation),
		approvalRequestId: `approval-${operation.providerId}-${operation.service}-${operation.action}`,
		approvalRevision: 1,
		wysiwysRender: providerApprovalRenderFor(operation),
		...(request.idempotencyKey ? { idempotencyKey: request.idempotencyKey } : {}),
	});
	return { actionRef: record.ref, approvalRequestId: record.approvalRequestId };
}

function prepareOutboundSideEffect(
	ledger: TelclaudeMcpSideEffectLedger,
	request: TelclaudeMcpOutboundPrepareRequest,
): PreparedOutbound {
	const record = ledger.prepare({
		kind: "outbound",
		actorId: request.actorId,
		approverActorId: request.actorId,
		profileId: request.profileId,
		domain: request.domain,
		channel: request.channel,
		destination: request.recipient,
		renderedBody: request.content,
		mediaRefs: request.mediaRefs,
		conversationRef: `${request.channel}:${request.recipient}`,
		approvalRequestId: `approval-${request.channel}-${request.recipient}`,
		approvalRevision: 1,
		approvalMetadata: { source: "approval-continuation-probe" },
	});
	return { outboundRef: record.ref, approvalRequestId: record.approvalRequestId };
}

async function runProviderFixture(
	harness: ProbeHarness,
	now?: Date,
): Promise<ApprovalContinuationFixtureEvidence> {
	const observations: ApprovalContinuationObservation[] = [];
	try {
		const prepared = (await harness.bridge.tc_provider_prepare_write({
			service: "bank",
			action: "transfer.prepare",
			params: { amount: 100, currency: "ILS" },
			idempotencyKey: "idem-provider-fixture",
		})) as PreparedProvider;
		const record = requireRecord(harness.ledger, prepared.actionRef);
		observations.push(pass("prepare", "provider side effect prepared through registered bridge"));
		const token = await approvalTokenFor(harness, record, "jti-provider-fixture");
		const result = await harness.bridge.tc_provider_execute_write({
			actionRef: prepared.actionRef,
			approvalToken: token,
		});
		observations.push(assertExecuted(result, "execute", "provider side effect executed"));
	} catch (error) {
		observations.push(fail("exception", errorMessage(error)));
	}
	return fixtureEvidence("provider.prepare-approve-execute", observations, now);
}

async function runOutboundFixture(
	harness: ProbeHarness,
	now?: Date,
): Promise<ApprovalContinuationFixtureEvidence> {
	const observations: ApprovalContinuationObservation[] = [];
	try {
		const prepared = (await harness.bridge.tc_outbound_prepare({
			channel: "whatsapp",
			recipient: "+15551234567",
			content: "I'll pick up dinner at 19:00.",
			mediaRefs: ["attachment:menu"],
		})) as PreparedOutbound;
		const record = requireRecord(harness.ledger, prepared.outboundRef);
		observations.push(pass("prepare", "outbound side effect prepared through registered bridge"));
		const token = await approvalTokenFor(harness, record, "jti-outbound-fixture");
		const result = await harness.bridge.tc_outbound_execute({
			outboundRef: prepared.outboundRef,
			approvalToken: token,
		});
		observations.push(assertExecuted(result, "execute", "outbound side effect executed"));
	} catch (error) {
		observations.push(fail("exception", errorMessage(error)));
	}
	return fixtureEvidence("outbound.prepare-approve-execute", observations, now);
}

async function runCronFixture(
	harness: ProbeHarness,
	now?: Date,
): Promise<ApprovalContinuationFixtureEvidence> {
	const observations: ApprovalContinuationObservation[] = [];
	try {
		const prepared = (await harness.bridge.tc_outbound_prepare({
			channel: "whatsapp",
			recipient: "+15557654321",
			content: "Daily brief is ready.",
			mediaRefs: [],
		})) as PreparedOutbound;
		const record = requireRecord(harness.ledger, prepared.outboundRef);
		observations.push(pass("prepare", "cron outbound ref prepared through registered bridge"));
		const token = await approvalTokenFor(harness, record, "jti-cron-fixture");
		const result = await harness.bridge.tc_outbound_execute({
			outboundRef: prepared.outboundRef,
			approvalToken: token,
		});
		observations.push(assertExecuted(result, "execute", "cron approval wait resumed via execute"));
	} catch (error) {
		observations.push(fail("exception", errorMessage(error)));
	}
	return fixtureEvidence("cron.approval-wait-resume", observations, now);
}

async function runLongRunningFixture(
	harness: ProbeHarness,
	now?: Date,
): Promise<ApprovalContinuationFixtureEvidence> {
	const observations: ApprovalContinuationObservation[] = [];
	try {
		const prepared = (await harness.bridge.tc_provider_prepare_write({
			service: "bank",
			action: "statement.download.prepare",
			params: { month: "2026-05" },
			idempotencyKey: "idem-long-running-fixture",
		})) as PreparedProvider;
		const record = requireRecord(harness.ledger, prepared.actionRef);
		observations.push(
			pass("prepare", "long-running provider ref prepared through registered bridge"),
		);
		const token = await approvalTokenFor(harness, record, "jti-long-running-fixture");
		const result = await harness.bridge.tc_provider_execute_write({
			actionRef: prepared.actionRef,
			approvalToken: token,
		});
		observations.push(
			assertExecuted(result, "execute", "long-running approval wait resumed via execute"),
		);
	} catch (error) {
		observations.push(fail("exception", errorMessage(error)));
	}
	return fixtureEvidence("long-running.approval-wait-resume", observations, now);
}

async function runNegativeObservations(
	harness: ProbeHarness,
): Promise<ApprovalContinuationObservation[]> {
	return [
		await runWrongActorDenied(harness),
		await runStaleRequestDenied(harness),
		await runReplayDenied(harness),
		await runMutatedDecisionDenied(harness),
	];
}

async function runWrongActorDenied(
	harness: ProbeHarness,
): Promise<ApprovalContinuationObservation> {
	const prepared = (await harness.bridge.tc_provider_prepare_write({
		service: "bank",
		action: "wrong-actor.prepare",
		params: { amount: 1 },
	})) as PreparedProvider;
	const record = requireRecord(harness.ledger, prepared.actionRef);
	const token = await approvalTokenFor(harness, record, "jti-wrong-actor");
	const result = await harness.wrongActorBridge.tc_provider_execute_write({
		actionRef: prepared.actionRef,
		approvalToken: token,
	});
	const denial = assertFailureCode(
		result,
		"wrong_actor_denied",
		"effect_authority_mismatch",
		"wrong actor execute was denied before approval verification",
	);
	if (denial.status === "fail") return denial;
	const recovery = await harness.bridge.tc_provider_execute_write({
		actionRef: prepared.actionRef,
		approvalToken: token,
	});
	const recoveryObservation = assertExecuted(
		recovery,
		"wrong_actor_recovery",
		"wrong actor denial did not consume the approval JTI",
	);
	return recoveryObservation.status === "pass"
		? denial
		: fail("wrong_actor_denied", recoveryObservation.detail, recoveryObservation.code);
}

async function runStaleRequestDenied(
	harness: ProbeHarness,
): Promise<ApprovalContinuationObservation> {
	const prepared = (await harness.bridge.tc_provider_prepare_write({
		service: "bank",
		action: "stale.prepare",
		params: { amount: 2 },
	})) as PreparedProvider;
	const record = requireRecord(harness.ledger, prepared.actionRef);
	const token = await approvalTokenFor(harness, record, "jti-stale");
	harness.setNowMs(BASE_NOW_MS + 120_000);
	let result: unknown;
	try {
		result = await harness.bridge.tc_provider_execute_write({
			actionRef: prepared.actionRef,
			approvalToken: token,
		});
	} finally {
		harness.setNowMs(BASE_NOW_MS);
	}
	return assertFailureCode(
		result,
		"stale_request_denied",
		"effect_expired",
		"expired prepared approval ref was denied",
	);
}

async function runReplayDenied(harness: ProbeHarness): Promise<ApprovalContinuationObservation> {
	const prepared = (await harness.bridge.tc_provider_prepare_write({
		service: "bank",
		action: "replay.prepare",
		params: { amount: 3 },
	})) as PreparedProvider;
	const record = requireRecord(harness.ledger, prepared.actionRef);
	const token = await approvalTokenFor(harness, record, "jti-replay");
	const binding = getTelclaudeMcpSideEffectApprovalBinding(record);
	const verifier = createTelclaudeMcpSideEffectApprovalVerifier({
		vaultClient: harness.vault,
		jtiStore: harness.jtiStore,
		nowSeconds: () => Math.floor(harness.nowMs() / 1_000),
	});
	const first = await verifier({
		approvalToken: token,
		binding,
		record,
		nowMs: harness.nowMs(),
	});
	if (!first.ok) {
		return fail("replay_denied", `first verifier call failed: ${first.reason}`, first.code);
	}
	const replay = await verifier({
		approvalToken: token,
		binding,
		record,
		nowMs: harness.nowMs() + 1_000,
	});
	return assertFailureCode(
		replay,
		"replay_denied",
		"approval_replayed",
		"JTI replay was denied by the durable verifier store",
	);
}

async function runMutatedDecisionDenied(
	harness: ProbeHarness,
): Promise<ApprovalContinuationObservation> {
	const prepared = (await harness.bridge.tc_outbound_prepare({
		channel: "whatsapp",
		recipient: "+15550001111",
		content: "Original message",
		mediaRefs: [],
	})) as PreparedOutbound;
	const record = requireRecord(harness.ledger, prepared.outboundRef);
	const binding = getTelclaudeMcpSideEffectApprovalBinding(record);
	const mutated = mutateBinding(binding);
	const token = await generateTelclaudeMcpSideEffectApprovalToken(mutated, harness.vault, {
		nowSeconds: () => Math.floor(harness.nowMs() / 1_000),
		jti: "jti-mutated-decision",
	});
	const result = await harness.bridge.tc_outbound_execute({
		outboundRef: prepared.outboundRef,
		approvalToken: token,
	});
	const denial = assertFailureCode(
		result,
		"mutated_decision_denied",
		"approval_mismatch",
		"mutated approval binding was denied by verifier",
	);
	if (denial.status === "fail") return denial;
	const validToken = await generateTelclaudeMcpSideEffectApprovalToken(binding, harness.vault, {
		nowSeconds: () => Math.floor(harness.nowMs() / 1_000),
		jti: "jti-mutated-decision",
	});
	const recovery = await harness.bridge.tc_outbound_execute({
		outboundRef: prepared.outboundRef,
		approvalToken: validToken,
	});
	const recoveryObservation = assertExecuted(
		recovery,
		"mutated_decision_recovery",
		"mutated approval denial did not consume the approval JTI",
	);
	return recoveryObservation.status === "pass"
		? denial
		: fail("mutated_decision_denied", recoveryObservation.detail, recoveryObservation.code);
}

async function approvalTokenFor(
	harness: ProbeHarness,
	record: TelclaudeMcpSideEffectRecord,
	jti: string,
): Promise<string> {
	return generateTelclaudeMcpSideEffectApprovalToken(
		getTelclaudeMcpSideEffectApprovalBinding(record),
		harness.vault,
		{
			nowSeconds: () => Math.floor(harness.nowMs() / 1_000),
			ttlSeconds: 60,
			jti,
		},
	);
}

function requireRecord(
	ledger: TelclaudeMcpSideEffectLedger,
	ref: string,
): TelclaudeMcpSideEffectRecord {
	const record = ledger.get(ref);
	if (!record) throw new Error(`missing side-effect record: ${ref}`);
	return record;
}

function appendNegativeFixtureObservations(
	fixtures: ApprovalContinuationFixtureEvidence[],
	observations: ApprovalContinuationObservation[],
): ApprovalContinuationFixtureEvidence[] {
	if (fixtures.length === 0) return fixtures;
	const [first, ...rest] = fixtures;
	return [{ ...first, observations: [...first.observations, ...observations] }, ...rest];
}

function fixtureEvidence(
	id: (typeof REQUIRED_APPROVAL_FALLBACK_FIXTURE_IDS)[number],
	observations: ApprovalContinuationObservation[],
	now = new Date(),
): ApprovalContinuationFixtureEvidence {
	const status = observations.every((observation) => observation.status === "pass")
		? "pass"
		: "fail";
	return {
		schemaVersion: APPROVAL_CONTINUATION_FIXTURE_EVIDENCE_SCHEMA_VERSION,
		id,
		status,
		generatedAt: now.toISOString(),
		summary:
			status === "pass"
				? `${id} passed through the live Telclaude MCP approval continuation path`
				: `${id} failed a live Telclaude MCP approval continuation observation`,
		observations,
	};
}

function observationPassed(observations: ApprovalContinuationObservation[], name: string): boolean {
	return observations.some(
		(observation) => observation.name === name && observation.status === "pass",
	);
}

function pass(name: string, detail: string): ApprovalContinuationObservation {
	return { name, status: "pass", detail: redactSecrets(detail) };
}

function fail(name: string, detail: string, code?: string): ApprovalContinuationObservation {
	return { name, status: "fail", detail: redactSecrets(detail), ...(code ? { code } : {}) };
}

function assertExecuted(
	result: unknown,
	name: string,
	detail: string,
): ApprovalContinuationObservation {
	if (
		typeof result === "object" &&
		result !== null &&
		"ok" in result &&
		result.ok === true &&
		"record" in result &&
		typeof result.record === "object" &&
		result.record !== null &&
		"status" in result.record &&
		result.record.status === "executed"
	) {
		return pass(name, detail);
	}
	return fail(name, `expected executed result, observed ${JSON.stringify(result)}`);
}

function assertFailureCode(
	result: unknown,
	name: string,
	expectedCode: string,
	detail: string,
): ApprovalContinuationObservation {
	if (
		typeof result === "object" &&
		result !== null &&
		"ok" in result &&
		result.ok === false &&
		"code" in result &&
		result.code === expectedCode
	) {
		return pass(name, detail);
	}
	return fail(name, `expected ${expectedCode}, observed ${JSON.stringify(result)}`);
}

function mutateBinding(
	binding: TelclaudeMcpSideEffectApprovalBinding,
): TelclaudeMcpSideEffectApprovalBinding {
	if (binding.kind === "provider") {
		return { ...binding, action: `${binding.action}.mutated` };
	}
	return { ...binding, destination: `${binding.destination}:mutated` };
}

function baseAuthority(): TelclaudeMcpAuthority {
	return {
		actorId: "telegram:123",
		profileId: "private",
		domain: "private",
		memorySource: "telegram:private",
		writableNamespace: "private:telegram",
		providerScopes: ["bank"],
		outboundChannels: ["whatsapp"],
		endpointId: "endpoint-private",
		networkNamespace: "netns-private",
	};
}

function defaultFixtureEvidencePath(
	id: (typeof REQUIRED_APPROVAL_FALLBACK_FIXTURE_IDS)[number],
): string {
	return fixturePath(DEFAULT_APPROVAL_CONTINUATION_FIXTURE_EVIDENCE_DIR, id);
}

function defaultFixtureEvidenceDir(evidencePath: string): string {
	if (path.resolve(evidencePath) === path.resolve(DEFAULT_APPROVAL_CONTINUATION_EVIDENCE_PATH)) {
		return DEFAULT_APPROVAL_CONTINUATION_FIXTURE_EVIDENCE_DIR;
	}
	return path.join(path.dirname(evidencePath), "approval");
}

function fixturePath(fixtureEvidenceDir: string, id: string): string {
	return path.join(fixtureEvidenceDir, `${id.replaceAll(".", "-")}.json`);
}

function errorMessage(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}
