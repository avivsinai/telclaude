import { Command } from "commander";
import { describe, expect, it } from "vitest";
import { registerHermesCommand } from "../../src/commands/hermes.js";
import type { TelclaudeConfig } from "../../src/config/config.js";
import {
	buildHermesDoctorReport,
	buildHermesGenerateDryRun,
	type CompatibilityLockfile,
	type CutoverInputBundle,
	evaluateCutoverCheck,
	type FeatureProbeMatrix,
	parseHermesPin,
	validateCompatibilityLockfile,
	validateFeatureProbeMatrix,
} from "../../src/hermes/foundation.js";
import {
	buildHermesInventorySnapshot,
	type HermesQueueSnapshot,
} from "../../src/hermes/inventory.js";

const hermesPin = { version: "0.15.1" };
const requiredNetworkProbeIds = [
	"network.direct-provider-denied",
	"network.direct-vault-denied",
	"network.direct-model-provider-denied",
	"network.dns-exfil-denied",
];

const featureProbeMatrix: FeatureProbeMatrix = {
	schemaVersion: 1,
	probes: [
		{
			surface_id: "edge.whatsapp.plugin-adapter",
			hermes_pin: hermesPin,
			documented_seam: "Hermes platform plugin adapter",
			probe_command: "pnpm dev hermes parity --whatsapp --edge-adapter",
			expected_result: "sanitized inbound and prepared outbound pass",
			negative_probe: "native WhatsApp credential access fails",
			evidence_path: "artifacts/hermes/whatsapp-edge.json",
			lockfile_key: "featureProbes.edge.whatsapp",
			failure_outcome: "disable",
			status: "pass",
		},
	],
};

const compatLockfile: CompatibilityLockfile = {
	schemaVersion: 1,
	hermes: hermesPin,
	featureProbeMatrixDigest: "sha256:feature-probes",
	featureProbes: [
		{
			surface_id: "edge.whatsapp.plugin-adapter",
			status: "pass",
			evidence_path: "artifacts/hermes/whatsapp-edge.json",
		},
	],
	adapterApiSignatures: {
		"edge.whatsapp": "sha256:adapter-signature",
	},
	capabilities: {
		plugins: ["platform-adapter"],
		mcp: ["stdio"],
		modelProviders: ["custom-provider"],
		memoryProviders: ["custom-memory"],
	},
	requiredUpgradeTests: ["pnpm dev hermes prove --upstream-clean --p0"],
	generatedProfileSchemaVersion: "1",
	wrapperPackageVersion: "0.7.1",
	paritySuiteDigests: {
		p0: "sha256:p0",
	},
	noForkProofEvidencePath: "artifacts/hermes/no-fork.json",
	sourceDriftSignals: {
		sourceCommit: "abcdef1",
		docsCommit: "1234567",
	},
};

const emptyQueues: HermesQueueSnapshot = {
	approvals: { pending: 0, expired: 0 },
	planApprovals: { pending: 0, expired: 0 },
	cards: { active: 0, expired: 0, byStatus: {} },
	backgroundJobs: { active: 0, byStatus: {} },
	pairing: { pendingRequests: 0, activePairs: 0, activeLockouts: 0 },
	allowlist: { active: 0, total: 0 },
	curator: { open: 0, byStatus: {} },
	social: { activeItems: 0 },
	webhooks: { enabled: 0, total: 0 },
	memory: { entries: 0, episodes: 0 },
};

function safeCutoverBundle(overrides: Partial<CutoverInputBundle> = {}): CutoverInputBundle {
	return {
		schemaVersion: 1,
		inventory: {
			generatedAt: "2026-05-29T00:00:00Z",
			workflows: [
				{
					workflow_id: "private.telegram.basic",
					owner: "operator",
					trust_domain: "private",
					active: true,
				},
			],
		},
		scopeManifest: {
			workflows: [
				{
					workflow_id: "private.telegram.basic",
					owner: "operator",
					trust_domain: "private",
					current_behavior: "Telclaude handles a private Telegram chat through the relay.",
					hermes_target_behavior: "Hermes runs behind the Telclaude edge with relay-owned secrets.",
					cutover_class: "P0",
					cutover_requirement: "Pinned Hermes wrapper parity fixture must pass.",
					status: "included",
					rollback_owner: "operator",
					fixture_ids: ["fixture.private.telegram.basic"],
					negative_fixture_ids: ["fixture.private.telegram.basic.deny"],
					required_surface_ids: ["edge.whatsapp.plugin-adapter"],
					unresolved_decision_ids: [],
				},
			],
		},
		decisionLog: { decisions: [] },
		lockfile: compatLockfile,
		featureProbeMatrix,
		fixtureResults: {
			results: [
				{
					id: "fixture.private.telegram.basic",
					status: "pass",
					evidence_path: "artifacts/hermes/private-telegram.json",
				},
				{
					id: "fixture.private.telegram.basic.deny",
					status: "pass",
					evidence_path: "artifacts/hermes/private-telegram-deny.json",
				},
			],
		},
		noForkProof: { hermesCheckoutClean: true, evidence_path: "artifacts/hermes/no-fork.json" },
		networkProbes: {
			probes: requiredNetworkProbeIds.map((id) => ({
				id,
				status: "pass",
				evidence_path: `artifacts/hermes/${id}.json`,
			})),
		},
		queueSnapshot: { unownedActiveCount: 0 },
		rollbackRehearsal: { passed: true, evidence_path: "artifacts/hermes/rollback.json" },
		...overrides,
	};
}

describe("Hermes wrapper foundation", () => {
	it("parses explicit Hermes pins without accepting an empty pin", () => {
		expect(parseHermesPin(undefined)).toBeNull();
		expect(parseHermesPin("abcdef1")).toEqual({ commit: "abcdef1" });
		expect(parseHermesPin("sha256:abc")).toEqual({ imageDigest: "sha256:abc" });
		expect(parseHermesPin("0.15.1")).toEqual({ version: "0.15.1" });
	});

	it("validates feature-probe and compatibility lockfile schemas", () => {
		expect(validateFeatureProbeMatrix(featureProbeMatrix)).toEqual({ valid: true, errors: [] });
		expect(validateCompatibilityLockfile(compatLockfile)).toEqual({ valid: true, errors: [] });

		const invalidProbe = validateFeatureProbeMatrix({
			schemaVersion: 1,
			probes: [{ surface_id: "" }],
		});
		expect(invalidProbe.valid).toBe(false);
		expect(invalidProbe.errors.join("\n")).toContain("hermes_pin");
	});

	it("fails doctor when no pinned Hermes artifact is supplied", () => {
		const report = buildHermesDoctorReport({ pin: null, featureProbeMatrix });
		expect(report.status).toBe("fail");
		expect(report.checks.find((check) => check.name === "hermes.pin")?.status).toBe("fail");
	});

	it("passes doctor with a pin and valid probe and lockfile artifacts", () => {
		const report = buildHermesDoctorReport({
			pin: hermesPin,
			featureProbeMatrix,
			lockfile: compatLockfile,
		});
		expect(report.status).toBe("pass");
	});

	it("fails doctor with a distinct missing-artifact reason", () => {
		const report = buildHermesDoctorReport({
			pin: hermesPin,
			featureProbeMatrixMissing: "required feature-probe matrix is missing: /missing.json",
		});
		expect(report.status).toBe("fail");
		expect(report.checks.find((check) => check.name === "hermes.featureProbes")?.detail).toContain(
			"required feature-probe matrix is missing",
		);
	});

	it("generates a dry-run profile manifest without raw secret values", () => {
		const manifest = buildHermesGenerateDryRun({
			pin: hermesPin,
			outDir: "/tmp/tc-hermes",
		});

		expect(manifest.outputs.some((output) => output.classification === "secret")).toBe(false);
		expect(JSON.stringify(manifest)).not.toContain("sk-");
		expect(manifest.secretManifest.map((secret) => secret.owner)).toEqual([
			"telclaude-vault",
			"telclaude-vault",
			"telclaude-edge",
		]);
	});

	it("returns cutover exit code 0 only when all strict evidence gates pass", () => {
		expect(evaluateCutoverCheck(safeCutoverBundle()).exitCode).toBe(0);

		const failed = evaluateCutoverCheck(
			safeCutoverBundle({
				noForkProof: {
					hermesCheckoutClean: false,
					evidence_path: "artifacts/hermes/no-fork.json",
				},
			}),
		);
		expect(failed.status).toBe("fail");
		expect(failed.exitCode).toBe(1);
		expect(failed.gates.find((gate) => gate.name === "nofork.clean")?.status).toBe("fail");
	});

	it("fails strict cutover when evidence bundles are empty", () => {
		const failed = evaluateCutoverCheck(
			safeCutoverBundle({
				featureProbeMatrix: { schemaVersion: 1, probes: [] },
				fixtureResults: { results: [] },
				networkProbes: { probes: [] },
			}),
		);

		expect(failed.status).toBe("fail");
		expect(failed.exitCode).toBe(1);
		expect(failed.gates.find((gate) => gate.name === "featureProbes.pass")?.status).toBe("fail");
		expect(failed.gates.find((gate) => gate.name === "fixtures.pass")?.status).toBe("fail");
		expect(failed.gates.find((gate) => gate.name === "networkProbes.pass")?.status).toBe("fail");
	});

	it("fails strict cutover when a required feature probe has no passing status", () => {
		const [probe] = featureProbeMatrix.probes;
		const failed = evaluateCutoverCheck(
			safeCutoverBundle({
				featureProbeMatrix: {
					schemaVersion: 1,
					probes: [{ ...probe, status: undefined }],
				},
			}),
		);

		expect(failed.status).toBe("fail");
		expect(failed.gates.find((gate) => gate.name === "featureProbes.pass")?.detail).toContain(
			"status is missing",
		);
	});

	it("fails strict cutover when active inventory workflows are not scoped", () => {
		const failed = evaluateCutoverCheck(
			safeCutoverBundle({
				inventory: {
					generatedAt: "2026-05-29T00:00:00Z",
					workflows: [
						{
							workflow_id: "private.telegram.basic",
							owner: "operator",
							trust_domain: "private",
							active: true,
						},
						{
							workflow_id: "provider.bank.read",
							owner: "operator",
							trust_domain: "provider-read",
							active: true,
						},
					],
				},
			}),
		);

		expect(failed.status).toBe("fail");
		expect(failed.gates.find((gate) => gate.name === "workflow.scope")?.detail).toContain(
			"provider.bank.read",
		);
	});

	it("accepts rich Hermes inventory workflow metadata in cutover input", () => {
		const bundle = safeCutoverBundle();
		const richBundle: unknown = {
			...bundle,
			inventory: {
				generatedAt: "2026-05-29T00:00:00Z",
				workflows: [
					{
						...bundle.inventory.workflows[0],
						current_surface: "Telclaude Telegram relay",
						hermes_target: "Hermes private profile behind Telclaude edge",
						status: "inventory_only",
						p_class: "P0",
						source_refs: ["config.telegram.allowedChats"],
						queue_refs: [],
						fixture_ids: [],
						unresolved_decision_ids: [],
						risk_notes: [],
					},
				],
			},
		};

		expect(evaluateCutoverCheck(richBundle).exitCode).toBe(0);
	});

	it("fails strict cutover when unresolved decisions affect included workflows", () => {
		const failed = evaluateCutoverCheck(
			safeCutoverBundle({
				decisionLog: {
					decisions: [
						{
							id: "D-private-execution",
							status: "unresolved",
							owner: "operator",
							deadline_phase: "Phase 1",
							affected_workflows: ["private.telegram.basic"],
							cutover_impact:
								"Private Telegram workflow cannot cut over until execution seam is chosen.",
						},
					],
				},
			}),
		);

		expect(failed.status).toBe("fail");
		expect(failed.gates.find((gate) => gate.name === "decisions.resolved")?.detail).toContain(
			"D-private-execution",
		);
	});

	it("fails strict cutover when feature probes are not tied to the lockfile pin", () => {
		const [probe] = featureProbeMatrix.probes;
		const failed = evaluateCutoverCheck(
			safeCutoverBundle({
				featureProbeMatrix: {
					schemaVersion: 1,
					probes: [{ ...probe, hermes_pin: { version: "0.15.0" } }],
				},
			}),
		);

		expect(failed.status).toBe("fail");
		expect(failed.gates.find((gate) => gate.name === "lockfile.consistent")?.detail).toContain(
			"not tied to the lockfile Hermes pin",
		);
	});

	it("returns cutover exit code 2 for malformed checker inputs", () => {
		const report = evaluateCutoverCheck({ schemaVersion: 1 });
		expect(report.status).toBe("input_error");
		expect(report.exitCode).toBe(2);
	});

	it("registers the top-level hermes command group", () => {
		const program = new Command();
		registerHermesCommand(program);
		expect(program.commands.map((command) => command.name())).toContain("hermes");
	});

	it("builds a real sanitized inventory snapshot with deterministic workflows", () => {
		const inventory = buildHermesInventorySnapshot({
			generatedAt: new Date("2026-05-29T00:00:00.000Z"),
			redactionSalt: "test-only-redaction-salt",
			source: {
				configPath: "/tmp/telclaude.json",
				runtimeConfigPath: "/tmp/telclaude.runtime.json",
				privateConfigPresent: true,
				dataDir: "/tmp/telclaude-data",
			},
			config: {
				security: {
					profile: "strict",
					permissions: { defaultTier: "READ_ONLY", users: {} },
					network: {
						privateEndpoints: [{ label: "provider", host: "provider.local", ports: [3000] }],
					},
				},
				telegram: {
					botToken: "12345:RAW_TELEGRAM_TOKEN",
					allowedChats: ["RAW_CHAT_ID_SHOULD_NOT_LEAK"],
					webhook: { secretToken: "RAW_WEBHOOK_SECRET" },
					heartbeatSeconds: 60,
					heartbeat: { enabled: true },
				},
				profiles: [
					{
						id: "family",
						label: "Family",
						allowedSkills: ["memory"],
						soulPath: "docs/soul.md",
					},
				],
				providers: [
					{
						id: "clalit",
						baseUrl: "http://clalit.internal:3000/api?token=RAW_PROVIDER_QUERY_SECRET",
						services: ["appointments"],
						description: "Health provider",
					},
					{
						id: "broken",
						baseUrl: "://RAW_MALFORMED_BASE_URL_SECRET",
						services: ["debug"],
					},
				],
				socialServices: [
					{
						id: "x",
						type: "xtwitter",
						enabled: true,
						apiKey: "RAW_SOCIAL_API_KEY",
						handle: "operator",
						displayName: "Operator",
						agentUrl: "http://agent.internal/private",
						heartbeatEnabled: true,
						heartbeatIntervalHours: 4,
						enableSkills: true,
						allowedSkills: ["social-posting"],
						agentSkillsAllowed: ["voice"],
						notifyOnHeartbeat: "activity",
					},
				],
				cron: { enabled: true, pollIntervalSeconds: 15, timeoutSeconds: 900 },
				dashboard: { enabled: true, port: 8787 },
				webhooks: { enabled: true, port: 8788 },
			} as unknown as TelclaudeConfig,
			sessions: [
				{
					key: "RAW_SESSION_KEY_SHOULD_NOT_LEAK",
					kind: "direct",
					sessionId: "RAW_SDK_SESSION_ID_SHOULD_NOT_LEAK",
					updatedAt: Date.parse("2026-05-29T00:00:00.000Z"),
					ageMs: 0,
					systemSent: true,
				},
			],
			cron: {
				enabled: true,
				pollIntervalSeconds: 15,
				timeoutSeconds: 900,
				summary: { totalJobs: 1, enabledJobs: 1, runningJobs: 0, nextRunAtMs: null },
				coverage: { allSocial: false, socialServiceIds: ["x"], hasPrivateHeartbeat: false },
				jobs: [
					{
						id: "daily-brief",
						name: "Daily brief",
						enabled: true,
						running: false,
						ownerId: "RAW_OWNER_ID_SHOULD_NOT_LEAK",
						deliveryTarget: { kind: "home" },
						schedule: { kind: "cron", expr: "0 8 * * *" },
						action: {
							kind: "agent-prompt",
							prompt: "RAW_CRON_PROMPT_SHOULD_NOT_LEAK",
							allowedSkills: ["daily-brief"],
							preprocess: { command: "RAW_PREPROCESS_COMMAND_SHOULD_NOT_LEAK" },
						},
						nextRunAtMs: null,
						lastRunAtMs: null,
						lastStatus: null,
						lastError: null,
						createdAtMs: 0,
						updatedAtMs: 0,
					},
				],
			},
			queues: {
				...emptyQueues,
				approvals: { pending: 1, expired: 0 },
				backgroundJobs: { active: 1, byStatus: { queued: 1 } },
				social: { activeItems: 1 },
			},
			socialActivity: [{ serviceId: "x", type: "drafted", count: 2 }],
		});

		expect(inventory.status).toBe("complete");
		expect(inventory.summary.workflows).toBeGreaterThan(0);
		expect(inventory.workflows.map((workflow) => workflow.workflow_id)).toEqual(
			[...inventory.workflows.map((workflow) => workflow.workflow_id)].sort(),
		);
		expect(inventory.config.telegram.botTokenPresent).toBe(true);
		expect(inventory.actors.find((actor) => actor.kind === "telegram-chat")?.id).toMatch(
			/^telegram-chat:/,
		);
		expect(
			inventory.workflows.find((workflow) =>
				workflow.source_refs.includes("config.telegram.allowedChats"),
			)?.owner,
		).toMatch(/^telegram-chat:/);
		expect(inventory.sessions.rows[0].keyRef).toMatch(/^session-key:/);
		expect(inventory.sessions.rows[0].sessionRef).toMatch(/^session:/);
		expect(inventory.cron.jobs[0].ownerRef).toMatch(/^owner:/);
		expect(inventory.cron.jobs[0].action).toMatchObject({
			kind: "agent-prompt",
			promptPresent: true,
			allowedSkillCount: 1,
			preprocessPresent: true,
		});
		expect(inventory.providers.find((provider) => provider.id === "broken")?.endpoint).toMatchObject(
			{
				scheme: null,
				host: null,
				parseError: "unparseable baseUrl",
			},
		);

		const serialized = JSON.stringify(inventory);
		for (const secret of [
			"RAW_TELEGRAM_TOKEN",
			"RAW_CHAT_ID_SHOULD_NOT_LEAK",
			"RAW_SESSION_KEY_SHOULD_NOT_LEAK",
			"RAW_OWNER_ID_SHOULD_NOT_LEAK",
			"RAW_WEBHOOK_SECRET",
			"RAW_PROVIDER_QUERY_SECRET",
			"RAW_MALFORMED_BASE_URL_SECRET",
			"RAW_SOCIAL_API_KEY",
			"RAW_SDK_SESSION_ID_SHOULD_NOT_LEAK",
			"RAW_CRON_PROMPT_SHOULD_NOT_LEAK",
			"RAW_PREPROCESS_COMMAND_SHOULD_NOT_LEAK",
			"/api?token=",
			"/private",
		]) {
			expect(serialized).not.toContain(secret);
		}
	});
});
