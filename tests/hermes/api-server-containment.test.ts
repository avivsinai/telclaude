import { describe, expect, it, vi } from "vitest";
import {
	buildHermesApiServerLaunchPlan,
	createEphemeralHermesApiServerKey,
	DEFAULT_HERMES_API_SERVER_DOCKER_IMAGE,
	findHermesApiServerLaunchSecretFindings,
	type HermesApiServerContainmentObservation,
	runHermesApiServerContainmentProbe,
} from "../../src/hermes/api-server-containment.js";

describe("Hermes API-server containment", () => {
	const pinnedHermesImage =
		"nousresearch/hermes-agent@sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7";

	it("builds a contained Docker launch with a fresh ephemeral API auth key only in env", () => {
		const priorOpenAi = process.env.OPENAI_API_KEY;
		try {
			process.env.OPENAI_API_KEY = "sk-process-env-must-not-leak";
			const plan = buildHermesApiServerLaunchPlan({
				apiKey: "ephemeral-api-key-for-test",
				cwd: "/tmp/telclaude",
				image: pinnedHermesImage,
				containerName: "tc-hermes-test",
				network: "relay-only",
			});

			expect(plan.invocation.command).toBe("docker");
			expect(plan.invocation.args).toContain("run");
			expect(plan.invocation.args).toContain("--network");
			expect(plan.invocation.args).toContain("relay-only");
			expect(plan.invocation.args).toContain("--user");
			expect(plan.invocation.args).toContain("10000:10000");
			expect(plan.invocation.args).toContain("--cap-drop");
			expect(plan.invocation.args).toContain("ALL");
			expect(plan.invocation.args).not.toContain("--cap-add");
			expect(plan.invocation.args).toContain("--security-opt");
			expect(plan.invocation.args).toContain("no-new-privileges");
			expect(plan.invocation.args).toContain("--read-only");
			expect(plan.invocation.args).toContain("--tmpfs");
			expect(plan.invocation.args).toContain("/home/hermes:size=512m,uid=10000,gid=10000,mode=0700");
			expect(plan.invocation.args).not.toContain("NET_ADMIN");
			expect(plan.invocation.args.slice(-2)).toEqual(["gateway", "run"]);
			expect(plan.invocation.args).toContain(pinnedHermesImage);
			expect(plan.invocation.args).not.toContain("ephemeral-api-key-for-test");
			expect(plan.invocation.env).toEqual({
				API_SERVER_ENABLED: "true",
				API_SERVER_HOST: "0.0.0.0",
				API_SERVER_PORT: "8642",
				API_SERVER_KEY: "ephemeral-api-key-for-test",
				HERMES_HOME: "/home/hermes/.hermes",
				HOME: "/home/hermes",
				TELCLAUDE_INTERNAL_HOSTS: "telclaude",
				NO_COLOR: "1",
			});
			expect(plan.invocation.env).not.toHaveProperty("TELCLAUDE_FIREWALL");
			expect(plan.invocation.env).not.toHaveProperty("TELCLAUDE_FIREWALL_SENTINEL");
			expect(JSON.stringify(plan.invocation.env)).not.toContain("sk-process-env-must-not-leak");
			expect(findHermesApiServerLaunchSecretFindings(plan)).toEqual([]);
		} finally {
			if (priorOpenAi === undefined) {
				delete process.env.OPENAI_API_KEY;
			} else {
				process.env.OPENAI_API_KEY = priorOpenAi;
			}
		}
	});

	it("defaults to the verified v0.15.1 image digest and rejects tags", () => {
		expect(DEFAULT_HERMES_API_SERVER_DOCKER_IMAGE).toBe(pinnedHermesImage);
		expect(() =>
			buildHermesApiServerLaunchPlan({
				cwd: "/tmp/telclaude",
				image: "nousresearch/hermes-agent:latest",
			}),
		).toThrow("Hermes API-server image must be pinned by sha256 digest");
		expect(() =>
			buildHermesApiServerLaunchPlan({
				cwd: "/tmp/telclaude",
				image: "nousresearch/hermes-agent:v2026.5.29@sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7",
			}),
		).toThrow("Hermes API-server image must be pinned as repository@sha256:digest");
	});

	it("generates high-entropy launch keys per call", () => {
		const first = createEphemeralHermesApiServerKey();
		const second = createEphemeralHermesApiServerKey();

		expect(first).toMatch(/^[A-Za-z0-9_-]{40,}$/);
		expect(second).toMatch(/^[A-Za-z0-9_-]{40,}$/);
		expect(first).not.toBe(second);
	});

	it("fails closed before invoking the runner when launch env contains standing credentials", async () => {
		const plan = buildHermesApiServerLaunchPlan({
			apiKey: "ephemeral-api-key-for-test",
			cwd: "/tmp/telclaude",
		});
		plan.invocation.env.OPENAI_API_KEY = "sk-standing-provider-key";
		const runner = vi.fn(async () => passingObservation());

		const report = await runHermesApiServerContainmentProbe({
			allowRun: true,
			launch: plan,
			runner,
		});

		expect(runner).not.toHaveBeenCalled();
		expect(report).toMatchObject({
			status: "fail",
			ran: false,
			findings: [
				{
					location: "env.OPENAI_API_KEY",
					reason: "forbidden standing credential environment key",
				},
			],
		});
		expect(JSON.stringify(report)).not.toContain("ephemeral-api-key-for-test");
		expect(JSON.stringify(report)).not.toContain("sk-standing-provider-key");
	});

	it("does not run without explicit allow-run", async () => {
		const plan = buildHermesApiServerLaunchPlan({
			apiKey: "ephemeral-api-key-for-test",
			cwd: "/tmp/telclaude",
		});
		const runner = vi.fn(async () => passingObservation());

		const report = await runHermesApiServerContainmentProbe({
			allowRun: false,
			launch: plan,
			runner,
		});

		expect(runner).not.toHaveBeenCalled();
		expect(report).toMatchObject({
			status: "pending",
			ran: false,
			invocation: {
				envKeys: expect.arrayContaining(["API_SERVER_KEY"]),
				ephemeralAuth: {
					envKey: "API_SERVER_KEY",
					classification: "ephemeral_api_auth",
				},
			},
		});
		expect(JSON.stringify(report)).not.toContain("ephemeral-api-key-for-test");
	});

	it("passes only with observed lifecycle, readiness, topology, tamper, and relay-only evidence", async () => {
		const plan = buildHermesApiServerLaunchPlan({
			apiKey: "ephemeral-api-key-for-test",
			cwd: "/tmp/telclaude",
		});

		const report = await runHermesApiServerContainmentProbe({
			allowRun: true,
			launch: plan,
			runner: async () => ({
				...passingObservation(),
				health: {
					ok: true,
					status: "ok",
					detail: "ready with ephemeral-api-key-for-test",
				},
				network: {
					...passingNetworkObservation(),
					tamper: {
						runtimeUid: "10000",
						runtimeUser: "hermes",
						runtimeNonRoot: true,
						firewallFlushDenied: false,
						routeAddDenied: false,
						tamperCommandSucceeded: true,
						forbiddenReachableAfterTamper: false,
						detail:
							"non-root runtime user ran a tamper command but topology still denied forbidden egress",
					},
				},
			}),
		});

		expect(report.status).toBe("pass");
		expect(report.ran).toBe(true);
		expect(report.gates.every((gate) => gate.status === "pass")).toBe(true);
		expect(JSON.stringify(report)).not.toContain("ephemeral-api-key-for-test");
		expect(JSON.stringify(report)).toContain("[REDACTED:ephemeral_api_auth]");
	});

	it("fails closed when any containment evidence is missing", async () => {
		const plan = buildHermesApiServerLaunchPlan({
			apiKey: "ephemeral-api-key-for-test",
			cwd: "/tmp/telclaude",
		});

		const report = await runHermesApiServerContainmentProbe({
			allowRun: true,
			launch: plan,
			runner: async () => ({
				...passingObservation(),
				network: {
					...passingNetworkObservation(),
					relayControlReachable: true,
					directProviderDenied: false,
					detail: "provider was reachable",
				},
			}),
		});

		expect(report.status).toBe("fail");
		expect(report.gates).toContainEqual({
			name: "network.relay_only",
			status: "fail",
			detail: "provider was reachable",
		});
	});

	it("fails closed when the dedicated internal network is not exclusive to Hermes and relay", async () => {
		const plan = buildHermesApiServerLaunchPlan({
			apiKey: "ephemeral-api-key-for-test",
			cwd: "/tmp/telclaude",
		});

		const report = await runHermesApiServerContainmentProbe({
			allowRun: true,
			launch: plan,
			runner: async () => ({
				...passingObservation(),
				network: {
					...passingNetworkObservation(),
					unexpectedPeers: ["pivot-container"],
					attachedContainers: ["tc-hermes-contained", "telclaude", "pivot-container"],
					detail: "unexpected peer attached",
				},
			}),
		});

		expect(report.status).toBe("fail");
		expect(report.gates).toContainEqual({
			name: "network.topology",
			status: "fail",
			detail: "unexpected peer attached",
		});
	});

	it("fails closed when forbidden egress becomes reachable after a tamper attempt", async () => {
		const plan = buildHermesApiServerLaunchPlan({
			apiKey: "ephemeral-api-key-for-test",
			cwd: "/tmp/telclaude",
		});

		const report = await runHermesApiServerContainmentProbe({
			allowRun: true,
			launch: plan,
			runner: async () => ({
				...passingObservation(),
				network: {
					...passingNetworkObservation(),
					tamper: {
						runtimeUid: "10000",
						runtimeUser: "hermes",
						runtimeNonRoot: true,
						firewallFlushDenied: false,
						routeAddDenied: false,
						tamperCommandSucceeded: true,
						forbiddenReachableAfterTamper: true,
						detail: "forbidden host reachable after tamper",
					},
				},
			}),
		});

		expect(report.status).toBe("fail");
		expect(report.gates).toContainEqual({
			name: "network.tamper_resistant",
			status: "fail",
			detail: "forbidden host reachable after tamper",
		});
	});
});

function passingObservation(): HermesApiServerContainmentObservation {
	return {
		lifecycle: {
			started: true,
			stopped: true,
			containerId: "container-1",
			detail: "started and stopped",
		},
		health: {
			ok: true,
			status: "ok",
			detail: "GET /health returned ok",
		},
		capabilities: {
			ok: true,
			runSubmission: true,
			runEventsSse: true,
			runStop: true,
			runApprovalResponse: true,
			bearerAuthRequired: true,
			serverToolExecution: true,
			splitRuntime: false,
			detail: "required capabilities present",
		},
		network: passingNetworkObservation(),
	};
}

function passingNetworkObservation(): NonNullable<
	HermesApiServerContainmentObservation["network"]
> {
	return {
		topologyInternal: true,
		relayContainerPresent: true,
		unexpectedPeers: [],
		attachedContainers: ["tc-hermes-contained", "telclaude"],
		relayControlReachable: true,
		directProviderDenied: true,
		directVaultDenied: true,
		directModelProviderDenied: true,
		dnsPrivateDenied: true,
		authoritativeBoundary: "docker_internal_network",
		networkName: "telclaude-hermes-relay",
		tamper: {
			runtimeUid: "10000",
			runtimeUser: "hermes",
			runtimeNonRoot: true,
			firewallFlushDenied: true,
			routeAddDenied: true,
			tamperCommandSucceeded: false,
			forbiddenReachableAfterTamper: false,
			detail:
				"non-root runtime user could not modify firewall/routes and forbidden egress stayed denied",
		},
		detail: "relay-only egress evidence passed",
	};
}
