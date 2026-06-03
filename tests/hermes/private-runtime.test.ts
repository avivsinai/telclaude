import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createTelclaudeMcpAuthorityRegistry } from "../../src/hermes/mcp/authority-registry.js";
import {
	buildHermesPrivateRuntimeAdapterFromEnv,
	executeHermesPrivateQuery,
	setHermesPrivateRuntimeAdapterForTest,
	shouldUseHermesPrivateRuntime,
} from "../../src/hermes/private-execute.js";
import {
	buildHermesCliProbeInvocation,
	executeHermesPrivateRuntime,
	findHermesLaunchSecretFindings,
	type HermesRuntimeAdapter,
	type HermesRuntimeRequest,
	redactHermesRuntimeText,
	runHermesCliHeadlessProbe,
	runHermesLaunchInvocation,
} from "../../src/hermes/private-runtime.js";
import { HermesSessionMap } from "../../src/hermes/session-map.js";
import { generateKeyPair } from "../../src/internal-auth.js";
import {
	type OpenAiCodexRelayProof,
	type OpenAiCodexRelayProofSignedFields,
	openAiCodexRelayProofTokenSha256,
	signOpenAiCodexRelayProof,
} from "../../src/relay/openai-codex-relay-proof.js";

const ORIGINAL_ENV = {
	OPERATOR_RPC_RELAY_PRIVATE_KEY: process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY,
	OPERATOR_RPC_RELAY_PUBLIC_KEY: process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY,
	TELCLAUDE_HERMES_RELAY_IP: process.env.TELCLAUDE_HERMES_RELAY_IP,
	TELCLAUDE_HERMES_CONTAINED_IP: process.env.TELCLAUDE_HERMES_CONTAINED_IP,
};

const TEST_HERMES_RELAY_IP = "10.88.92.10";
const TEST_HERMES_CONTAINED_IP = "10.88.92.11";

type TestContainedDockerRuntime = {
	kind: "contained-docker";
	containerName: string;
	networkName: "telclaude-hermes-relay";
	containerId: string;
	image: string;
	imageDigest: `sha256:${string}`;
	hostname: string;
	relayHost: "telclaude";
	relayResolvedAddress: string;
	containerIpAddress: string;
	observedPeerAddress: string;
	provenanceSource: "docker-inspect-container-dns-and-relay-peer";
};

type TestRelayProof = OpenAiCodexRelayProof;

describe("Hermes private runtime seam", () => {
	beforeEach(() => {
		const relayKeys = generateKeyPair();
		process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = relayKeys.privateKey;
		process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = relayKeys.publicKey;
		process.env.TELCLAUDE_HERMES_RELAY_IP = TEST_HERMES_RELAY_IP;
		process.env.TELCLAUDE_HERMES_CONTAINED_IP = TEST_HERMES_CONTAINED_IP;
	});

	afterEach(() => {
		restoreEnv("OPERATOR_RPC_RELAY_PRIVATE_KEY");
		restoreEnv("OPERATOR_RPC_RELAY_PUBLIC_KEY");
		restoreEnv("TELCLAUDE_HERMES_RELAY_IP");
		restoreEnv("TELCLAUDE_HERMES_CONTAINED_IP");
	});

	it("normalizes Hermes runtime events into Telclaude StreamChunks", async () => {
		const sessions = new HermesSessionMap(() => "tc-session-1");
		const runtime: HermesRuntimeAdapter = {
			run: async function* () {
				yield { type: "session", hermesSessionId: "hermes-session-1" };
				yield { type: "text_delta", text: "hello " };
				yield { type: "tool_use", toolName: "tc_memory_search", input: { query: "family" } };
				yield { type: "tool_result", toolName: "tc_memory_search", output: { count: 0 } };
				yield { type: "text_delta", text: "world" };
			},
		};

		const chunks = await collect(
			executeHermesPrivateRuntime({
				runtime,
				sessions,
				request: baseRequest(),
				now: () => 1000,
			}),
		);

		expect(chunks).toEqual([
			{ type: "text", content: "hello " },
			{ type: "tool_use", toolName: "tc_memory_search", input: { query: "family" } },
			{ type: "tool_result", toolName: "tc_memory_search", output: { count: 0 } },
			{ type: "text", content: "world" },
			{
				type: "done",
				result: {
					response: "hello world",
					success: true,
					costUsd: 0,
					numTurns: 1,
					durationMs: 0,
				},
			},
		]);
		expect(sessions.get("tg:123", "ops")?.hermesSessionId).toBe("hermes-session-1");
	});

	it("redacts Hermes private runtime stream text, tool payloads, and final errors", async () => {
		const token = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi";
		const sessions = new HermesSessionMap(() => "tc-session-1");
		const runtime: HermesRuntimeAdapter = {
			run: async function* () {
				yield { type: "text_delta", text: `hello ${token}` };
				yield {
					type: "tool_use",
					toolName: "tc_provider",
					input: { nested: [`send ${token}`] },
				};
				yield {
					type: "tool_result",
					toolName: "tc_provider",
					output: { response: `done ${token}` },
				};
				yield { type: "done", response: `final ${token}`, error: `warn ${token}` };
			},
		};

		const chunks = await collect(
			executeHermesPrivateRuntime({
				runtime,
				sessions,
				request: baseRequest(),
				now: () => 1000,
			}),
		);

		expect(JSON.stringify(chunks)).not.toContain(token);
		expect(chunks).toEqual([
			{ type: "text", content: "hello [REDACTED:telegram_bot_token]" },
			{
				type: "tool_use",
				toolName: "tc_provider",
				input: { nested: ["send [REDACTED:telegram_bot_token]"] },
			},
			{
				type: "tool_result",
				toolName: "tc_provider",
				output: { response: "done [REDACTED:telegram_bot_token]" },
			},
			{
				type: "done",
				result: {
					response: "final [REDACTED:telegram_bot_token]",
					success: true,
					error: "warn [REDACTED:telegram_bot_token]",
					costUsd: 0,
					numTurns: 1,
					durationMs: 0,
				},
			},
		]);
	});

	it("mints private MCP authority out-of-band for the runtime and revokes it on completion", async () => {
		const registry = createTelclaudeMcpAuthorityRegistry();
		const sessions = new HermesSessionMap(() => "tc-session-1");
		let seenAuthority: HermesRuntimeRequest["mcpAuthority"];
		const runtime: HermesRuntimeAdapter = {
			run: async function* (request) {
				seenAuthority = request.mcpAuthority;
				expect(seenAuthority?.handle).toMatch(/^tc_mcp_/);
				expect(
					registry.resolve({
						handle: seenAuthority?.handle ?? "",
						connection: seenAuthority?.connection ?? {
							sessionKey: "",
							profileId: "",
							endpointId: "",
							networkNamespace: "",
						},
						nowMs: 1_001,
					}),
				).toMatchObject({
					ok: true,
					authority: {
						actorId: "456",
						profileId: "ops",
						domain: "private",
						memorySource: "telegram:ops",
						writableNamespace: "private:ops",
						providerScopes: ["calendar"],
						outboundChannels: ["whatsapp"],
						endpointId: "endpoint-private",
						networkNamespace: "netns-private",
					},
				});
				yield { type: "done", response: "ok" };
			},
		};

		const chunks = await collect(
			executeHermesPrivateRuntime({
				runtime,
				sessions,
				mcpAuthorityRegistry: registry,
				request: baseRequest({
					mcpAuthority: {
						providerScopes: ["calendar"],
						outboundChannels: ["whatsapp"],
						endpointId: "endpoint-private",
						networkNamespace: "netns-private",
						ttlMs: 5_000,
					},
				}),
				now: () => 1_000,
			}),
		);

		expect(chunks.at(-1)).toEqual({
			type: "done",
			result: {
				response: "ok",
				success: true,
				costUsd: 0,
				numTurns: 1,
				durationMs: expect.any(Number),
			},
		});
		expect(seenAuthority).toBeDefined();
		expect(
			registry.resolve({
				handle: seenAuthority?.handle ?? "",
				connection: seenAuthority?.connection ?? {
					sessionKey: "",
					profileId: "",
					endpointId: "",
					networkNamespace: "",
				},
				nowMs: 1_001,
			}),
		).toMatchObject({
			ok: false,
			code: "mcp_authority_revoked",
		});
	});

	it("resumes the mapped Hermes session and clears it for /new", async () => {
		const sessions = new HermesSessionMap(() => "tc-session-1");
		sessions.getOrCreate({ sessionKey: "tg:123", profileId: "ops", now: 1000 });
		sessions.updateHermesSessionId("tg:123", "ops", "hermes-session-1", 1100);

		let resumedSessionId: string | undefined;
		const runtime: HermesRuntimeAdapter = {
			run: async function* (request) {
				resumedSessionId = request.resumeHermesSessionId;
				yield { type: "text_delta", text: "resumed" };
			},
		};

		await collect(
			executeHermesPrivateRuntime({
				runtime,
				sessions,
				request: baseRequest({ isNewSession: false }),
				now: () => 1200,
			}),
		);

		expect(resumedSessionId).toBe("hermes-session-1");
		expect(sessions.clearSessionKey("tg:123")).toBe(1);
		expect(sessions.get("tg:123", "ops")).toBeNull();
	});

	it("reports runtime failures as a failed done chunk", async () => {
		const runtime: HermesRuntimeAdapter = {
			run: async function* () {
				yield { type: "text_delta", text: "started" };
				throw new Error("aborted by test");
			},
		};

		const chunks = await collect(
			executeHermesPrivateRuntime({
				runtime,
				sessions: new HermesSessionMap(() => "tc-session-1"),
				request: baseRequest(),
				now: () => 1000,
			}),
		);

		expect(chunks.at(-1)).toEqual({
			type: "done",
			result: {
				response: "started",
				success: false,
				error: "aborted by test",
				costUsd: 0,
				numTurns: 1,
				durationMs: 0,
			},
		});
	});

	it("exposes a disabled-by-default private query bridge", async () => {
		expect(shouldUseHermesPrivateRuntime({ TELCLAUDE_HERMES_PRIVATE_RUNTIME: "1" })).toBe(true);
		expect(shouldUseHermesPrivateRuntime({ TELCLAUDE_HERMES_PRIVATE_RUNTIME: "0" })).toBe(false);
		setHermesPrivateRuntimeAdapterForTest(null);

		const chunks = await collect(
			executeHermesPrivateQuery("hello", {
				cwd: "/repo",
				tier: "READ_ONLY",
				poolKey: "tg:123",
				telclaudeSessionId: "tc-session-1",
				profileId: "ops",
				enableSkills: false,
				timeoutMs: 60_000,
			}),
		);

		expect(chunks).toEqual([
			{
				type: "done",
				result: {
					response: "",
					success: false,
					error: "Hermes private runtime adapter is not configured",
					costUsd: 0,
					numTurns: 0,
					durationMs: 0,
				},
			},
		]);
	});

	it("builds the production API adapter only from explicit Hermes API env", () => {
		expect(buildHermesPrivateRuntimeAdapterFromEnv({})).toBeNull();
		expect(() =>
			buildHermesPrivateRuntimeAdapterFromEnv({
				TELCLAUDE_HERMES_API_BASE_URL: "http://hermes.local",
			}),
		).toThrow("TELCLAUDE_HERMES_API_KEY is required");
		expect(() =>
			buildHermesPrivateRuntimeAdapterFromEnv({
				TELCLAUDE_HERMES_API_KEY: "api-key",
			}),
		).toThrow("TELCLAUDE_HERMES_API_BASE_URL is required");
		expect(
			buildHermesPrivateRuntimeAdapterFromEnv({
				TELCLAUDE_HERMES_API_BASE_URL: "http://hermes.local",
				TELCLAUDE_HERMES_API_KEY: "api-key",
			}),
		).not.toBeNull();
	});

	it("reports Hermes API env misconfiguration as a failed private query", async () => {
		const priorBaseUrl = process.env.TELCLAUDE_HERMES_API_BASE_URL;
		const priorApiKey = process.env.TELCLAUDE_HERMES_API_KEY;
		try {
			process.env.TELCLAUDE_HERMES_API_BASE_URL = "http://hermes.local";
			delete process.env.TELCLAUDE_HERMES_API_KEY;
			setHermesPrivateRuntimeAdapterForTest(null);

			const chunks = await collect(
				executeHermesPrivateQuery("hello", {
					cwd: "/repo",
					tier: "READ_ONLY",
					poolKey: "tg:123",
					telclaudeSessionId: "tc-session-1",
					profileId: "ops",
					enableSkills: false,
					timeoutMs: 60_000,
				}),
			);

			expect(chunks).toEqual([
				{
					type: "done",
					result: {
						response: "",
						success: false,
						error: "TELCLAUDE_HERMES_API_KEY is required when TELCLAUDE_HERMES_API_BASE_URL is set",
						costUsd: 0,
						numTurns: 0,
						durationMs: 0,
					},
				},
			]);
		} finally {
			if (priorBaseUrl === undefined) {
				delete process.env.TELCLAUDE_HERMES_API_BASE_URL;
			} else {
				process.env.TELCLAUDE_HERMES_API_BASE_URL = priorBaseUrl;
			}
			if (priorApiKey === undefined) {
				delete process.env.TELCLAUDE_HERMES_API_KEY;
			} else {
				process.env.TELCLAUDE_HERMES_API_KEY = priorApiKey;
			}
		}
	});

	it("passes private query options into the configured runtime adapter", async () => {
		let seenRequest: Parameters<HermesRuntimeAdapter["run"]>[0] | undefined;
		const runtime: HermesRuntimeAdapter = {
			run: async function* (request) {
				seenRequest = request;
				yield { type: "done", response: "ok" };
			},
		};
		setHermesPrivateRuntimeAdapterForTest(runtime);

		const chunks = await collect(
			executeHermesPrivateQuery("hello", {
				cwd: "/repo",
				tier: "WRITE_LOCAL",
				poolKey: "tg:123",
				telclaudeSessionId: "tc-session-1",
				profileId: "ops",
				model: "anthropic/claude-sonnet",
				resumeSessionId: "existing",
				enableSkills: true,
				allowedSkills: ["external-provider"],
				systemPromptAppend: "<context />",
				compiledMemoryMd: "# Memory\n- family prefers WhatsApp",
				timeoutMs: 60_000,
				userId: "operator",
				chatId: 123,
				actorId: 456,
				threadId: 789,
			}),
		);

		expect(chunks.at(-1)).toEqual({
			type: "done",
			result: {
				response: "ok",
				success: true,
				costUsd: 0,
				numTurns: 1,
				durationMs: expect.any(Number),
			},
		});
		expect(seenRequest).toMatchObject({
			prompt: "hello",
			cwd: "/repo",
			tier: "WRITE_LOCAL",
			sessionKey: "tg:123",
			telclaudeSessionId: "tc-session-1",
			profileId: "ops",
			identity: {
				userId: "operator",
				chatId: 123,
				actorId: 456,
				threadId: 789,
			},
			memory: {
				compiledMemoryMd: "# Memory\n- family prefers WhatsApp",
			},
			model: "anthropic/claude-sonnet",
			allowedSkills: ["external-provider"],
			systemPromptAppend: "<context />",
			isNewSession: false,
			timeoutMs: 60_000,
		});
		setHermesPrivateRuntimeAdapterForTest(null);
	});

	it("blocks raw credentials in Hermes launch surfaces", () => {
		const telegramToken = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi";
		const githubToken = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
		const findings = findHermesLaunchSecretFindings({
			command: "hermes",
			args: ["-z", `hello ${telegramToken}`],
			cwd: "/repo",
			env: {
				HERMES_HOME: "/tmp/hermes",
				TELEGRAM_BOT_TOKEN: telegramToken,
				TELCLAUDE_RELAY_BASE_URL: "http://127.0.0.1:3010",
				TELCLAUDE_HINT: githubToken,
			},
		});

		expect(findings).toEqual([
			{
				location: "env.TELEGRAM_BOT_TOKEN",
				reason: "forbidden credential environment key",
			},
			{
				location: "env.TELCLAUDE_HINT",
				reason: "credential-like environment value",
			},
			{
				location: "argv[1]",
				reason: "credential-like process argument",
			},
		]);
	});

	it("redacts stdout/stderr before probe artifacts can persist them", () => {
		const telegramToken = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi";
		const githubToken = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
		const redacted = redactHermesRuntimeText(`ok ${telegramToken} ${githubToken}`);
		expect(redacted).not.toContain(telegramToken);
		expect(redacted).not.toContain(githubToken);
		expect(redacted).toContain("[REDACTED:telegram_bot_token]");
		expect(redacted).toContain("[REDACTED:github_pat]");
	});

	it("does not run a CLI probe without explicit execution approval", async () => {
		const invocation = buildHermesCliProbeInvocation({
			hermesBin: "/usr/local/bin/hermes",
			hermesHome: "/tmp/tc-hermes-probe",
			cwd: process.cwd(),
			env: cliRelayEnv(),
		});

		await expect(
			runHermesCliHeadlessProbe({
				allowRun: false,
				invocation,
				runProcess: async () => {
					throw new Error("should not run");
				},
			}),
		).resolves.toMatchObject({
			status: "pending",
			ran: false,
			summary: "Hermes CLI probe requires --allow-run",
		});
	});

	it("runs a safe CLI headless probe only with explicit execution enabled", async () => {
		const invocation = buildHermesCliProbeInvocation({
			hermesBin: "/usr/local/bin/hermes",
			hermesHome: "/tmp/tc-hermes-probe",
			cwd: process.cwd(),
			prompt: "Reply with exactly TELCLAUDE_HERMES_CLI_OK",
			env: cliRelayEnv({ HERMES_INFERENCE_MODEL: "gpt-5.3-codex" }),
		});
		const report = await runHermesCliHeadlessProbe({
			allowRun: true,
			invocation,
			runProcess: async (launch) => {
				expect(launch.args).toEqual(["-z", "Reply with exactly TELCLAUDE_HERMES_CLI_OK"]);
				expect(launch.env).toEqual({
					HERMES_HOME: "/tmp/tc-hermes-probe",
					NO_COLOR: "1",
					HERMES_CODEX_BASE_URL: "http://telclaude:8790/v1/openai-codex-proxy",
					HERMES_INFERENCE_PROVIDER: "openai-codex",
					HERMES_INFERENCE_MODEL: "gpt-5.3-codex",
				});
				expect(launch.authSetup).toEqual({
					openAiCodexRelayToken: "relay-scoped-proxy-token",
				});
				return {
					exitCode: 0,
					stdout: "TELCLAUDE_HERMES_CLI_OK\n",
					stderr: "token 123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi",
					runtime: containedDockerRuntime(),
					relayProof: relayProof({ model: "gpt-5.3-codex" }),
				};
			},
		});

		expect(report).toMatchObject({
			schemaVersion: "telclaude.hermes.probe-result.v1",
			probeId: "execution.cli_headless",
			status: "pass",
			ran: true,
			summary: "Hermes CLI oneshot probe completed successfully",
			invocation: {
				command: "/usr/local/bin/hermes",
				args: ["-z", "Reply with exactly TELCLAUDE_HERMES_CLI_OK"],
				cwd: process.cwd(),
				envKeys: [
					"HERMES_CODEX_BASE_URL",
					"HERMES_HOME",
					"HERMES_INFERENCE_MODEL",
					"HERMES_INFERENCE_PROVIDER",
					"NO_COLOR",
				],
			},
			exitCode: 0,
			stdoutPreview: "TELCLAUDE_HERMES_CLI_OK\n",
			stderrPreview: "token [REDACTED:telegram_bot_token]",
			runtime: containedDockerRuntime(),
			relayProof: expect.objectContaining({
				source: "telclaude-openai-codex-proxy",
				path: "/backend-api/codex/responses",
				observedPeerAddress: TEST_HERMES_CONTAINED_IP,
				upstreamStatus: 200,
				model: "gpt-5.3-codex",
			}),
			provenance: {
				runner: "telclaude-hermes-cli-probe",
				source: "live-allow-run",
				expectedProofToken: "TELCLAUDE_HERMES_CLI_OK",
				proofTokenObserved: true,
				invocationSha256: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
				stdoutSha256: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
				stderrSha256: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
				relayProofSha256: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
			},
			findings: [],
		});
	});

	it("does not inherit Anthropic API fallback credentials into CLI probes", () => {
		const invocation = buildHermesCliProbeInvocation({
			hermesBin: "/usr/local/bin/hermes",
			hermesHome: "/tmp/tc-hermes-probe",
			cwd: "/repo",
			env: {
				ANTHROPIC_BASE_URL: "http://telclaude:8790/v1/anthropic-proxy",
				ANTHROPIC_API_KEY: "relay-anthropic-token",
				HERMES_INFERENCE_MODEL: "gpt-5.3-codex",
			},
		});

		expect(invocation.env).toEqual({
			HERMES_HOME: "/tmp/tc-hermes-probe",
			NO_COLOR: "1",
			HERMES_INFERENCE_MODEL: "gpt-5.3-codex",
		});
	});

	it("does not let echo-only CLI output satisfy the headless model proof", async () => {
		const invocation = buildHermesCliProbeInvocation({
			hermesBin: "/usr/local/bin/hermes",
			hermesHome: "/tmp/tc-hermes-probe",
			cwd: process.cwd(),
			prompt: "Reply with exactly HERMES_OK_ECHO_ONLY",
			env: cliRelayEnv({ HERMES_INFERENCE_MODEL: "gpt-5.3-codex" }),
		});

		const report = await runHermesCliHeadlessProbe({
			allowRun: true,
			invocation,
			runProcess: async () => ({
				exitCode: 0,
				stdout: "HERMES_OK_ECHO_ONLY\n",
				stderr: "",
				runtime: containedDockerRuntime(),
			}),
		});

		expect(report).toMatchObject({
			status: "fail",
			summary: "Hermes CLI oneshot probe lacks relay-backed model proof: relay proof is missing",
		});
	});

	it("rejects relay proofs whose signed fields were tampered after relay signing", async () => {
		const signedProof = relayProof({ model: "gpt-5.3-codex" }, "HERMES_OK_SIGNED_PROOF");
		const invocation = buildHermesCliProbeInvocation({
			hermesBin: "/usr/local/bin/hermes",
			hermesHome: "/tmp/tc-hermes-probe",
			cwd: process.cwd(),
			prompt: "Reply with exactly HERMES_OK_SIGNED_PROOF",
			env: cliRelayEnv({ HERMES_INFERENCE_MODEL: "gpt-5.3-codex" }),
		});

		const report = await runHermesCliHeadlessProbe({
			allowRun: true,
			invocation,
			runProcess: async () => ({
				exitCode: 0,
				stdout: "HERMES_OK_SIGNED_PROOF\n",
				stderr: "",
				runtime: containedDockerRuntime(),
				relayProof: { ...signedProof, model: "gpt-5.5" },
			}),
		});

		expect(report).toMatchObject({
			status: "fail",
			summary: expect.stringContaining("relay proof signature is invalid"),
		});
	});

	it("rejects relay proofs not bound to the expected stdout proof token", async () => {
		const signedProof = relayProof({ model: "gpt-5.3-codex" }, "HERMES_OK_DIFFERENT_TOKEN");
		const invocation = buildHermesCliProbeInvocation({
			hermesBin: "/usr/local/bin/hermes",
			hermesHome: "/tmp/tc-hermes-probe",
			cwd: process.cwd(),
			prompt: "Reply with exactly HERMES_OK_TOKEN_BINDING",
			env: cliRelayEnv({ HERMES_INFERENCE_MODEL: "gpt-5.3-codex" }),
		});

		const report = await runHermesCliHeadlessProbe({
			allowRun: true,
			invocation,
			runProcess: async () => ({
				exitCode: 0,
				stdout: "HERMES_OK_TOKEN_BINDING\n",
				stderr: "",
				runtime: containedDockerRuntime(),
				relayProof: signedProof,
			}),
		});

		expect(report).toMatchObject({
			status: "fail",
			summary: expect.stringContaining(
				"relay proof proofTokenSha256 does not match expected proof token",
			),
		});
	});

	it("fails closed when the trusted operator relay public key is unavailable", async () => {
		const signedProof = relayProof({ model: "gpt-5.3-codex" }, "HERMES_OK_MISSING_KEY");
		delete process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
		const invocation = buildHermesCliProbeInvocation({
			hermesBin: "/usr/local/bin/hermes",
			hermesHome: "/tmp/tc-hermes-probe",
			cwd: process.cwd(),
			prompt: "Reply with exactly HERMES_OK_MISSING_KEY",
			env: cliRelayEnv({ HERMES_INFERENCE_MODEL: "gpt-5.3-codex" }),
		});

		const report = await runHermesCliHeadlessProbe({
			allowRun: true,
			invocation,
			runProcess: async () => ({
				exitCode: 0,
				stdout: "HERMES_OK_MISSING_KEY\n",
				stderr: "",
				runtime: containedDockerRuntime(),
				relayProof: signedProof,
			}),
		});

		expect(report).toMatchObject({
			status: "fail",
			summary: expect.stringContaining(
				"relay proof signature is invalid: missing relay public key env OPERATOR_RPC_RELAY_PUBLIC_KEY",
			),
		});
	});

	it("rejects relay proofs signed by a key other than the trusted operator relay key", async () => {
		const trustedPublicKey = process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
		const attackerKeys = generateKeyPair();
		process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = attackerKeys.privateKey;
		const forgedProof = relayProof({ model: "gpt-5.3-codex" }, "HERMES_OK_FORGED_KEY");
		if (trustedPublicKey) process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = trustedPublicKey;
		const invocation = buildHermesCliProbeInvocation({
			hermesBin: "/usr/local/bin/hermes",
			hermesHome: "/tmp/tc-hermes-probe",
			cwd: process.cwd(),
			prompt: "Reply with exactly HERMES_OK_FORGED_KEY",
			env: cliRelayEnv({ HERMES_INFERENCE_MODEL: "gpt-5.3-codex" }),
		});

		const report = await runHermesCliHeadlessProbe({
			allowRun: true,
			invocation,
			runProcess: async () => ({
				exitCode: 0,
				stdout: "HERMES_OK_FORGED_KEY\n",
				stderr: "",
				runtime: containedDockerRuntime(),
				relayProof: forgedProof,
			}),
		});

		expect(report).toMatchObject({
			status: "fail",
			summary: expect.stringContaining(
				"relay proof signature is invalid: signature verification failed",
			),
		});
	});

	it("passes only relay OpenAI Codex subscription model env into the CLI headless launch", async () => {
		const invocation = buildHermesCliProbeInvocation({
			hermesBin: "/usr/local/bin/hermes",
			hermesHome: "/tmp/tc-hermes-probe",
			cwd: process.cwd(),
			prompt: "Reply with exactly HERMES_OK_53822847",
			env: {
				...cliRelayEnv({ HERMES_INFERENCE_MODEL: "gpt-5.3-codex" }),
				OPENAI_API_KEY: "sk-proj-raw-provider-key",
			},
		});
		const report = await runHermesCliHeadlessProbe({
			allowRun: true,
			invocation,
			runProcess: async (launch) => {
				expect(launch.args).toEqual(["-z", "Reply with exactly HERMES_OK_53822847"]);
				expect(launch.env).toEqual({
					HERMES_HOME: "/tmp/tc-hermes-probe",
					NO_COLOR: "1",
					HERMES_CODEX_BASE_URL: "http://telclaude:8790/v1/openai-codex-proxy",
					HERMES_INFERENCE_PROVIDER: "openai-codex",
					HERMES_INFERENCE_MODEL: "gpt-5.3-codex",
				});
				expect(launch.authSetup).toEqual({
					openAiCodexRelayToken: "relay-scoped-proxy-token",
				});
				return {
					exitCode: 0,
					stdout: "HERMES_OK_53822847\n",
					stderr: "",
					runtime: containedDockerRuntime(),
					relayProof: relayProof({ model: "gpt-5.3-codex" }, "HERMES_OK_53822847"),
				};
			},
		});

		expect(report.invocation.envKeys).toEqual([
			"HERMES_CODEX_BASE_URL",
			"HERMES_HOME",
			"HERMES_INFERENCE_MODEL",
			"HERMES_INFERENCE_PROVIDER",
			"NO_COLOR",
		]);
		expect(report).toMatchObject({
			status: "pass",
			ran: true,
			modelProvider: {
				provider: "openai-codex",
				baseUrl: "http://telclaude:8790/v1/openai-codex-proxy",
				baseUrlHost: "telclaude",
				model: "gpt-5.3-codex",
				modelSource: "env:HERMES_INFERENCE_MODEL",
				authLocation: "hermes-auth-store:openai-codex",
				authScope: "relay-openai-codex-subscription-proxy",
				tokenScoping: "static-shared",
				auxiliaryAuthSource: "manual:telclaude-relay",
				auxiliaryBaseUrl: "http://telclaude:8790/v1/openai-codex-proxy",
				auxiliaryBaseUrlHost: "telclaude",
				refreshTokenPolicy: "non-refreshable-placeholder",
			},
			relayProof: expect.objectContaining({
				source: "telclaude-openai-codex-proxy",
				path: "/backend-api/codex/responses",
				observedPeerAddress: TEST_HERMES_CONTAINED_IP,
				upstreamStatus: 200,
				model: "gpt-5.3-codex",
			}),
			findings: [],
		});
		expect(JSON.stringify(report)).not.toContain("relay-scoped-proxy-token");
		expect(JSON.stringify(report)).not.toContain("sk-proj-raw-provider-key");
	});

	it("writes relay OpenAI Codex auth store with a relay credential pool entry", async () => {
		const hermesHome = fs.mkdtempSync(path.join(os.tmpdir(), "tc-hermes-auth-"));
		try {
			const result = await runHermesLaunchInvocation(
				{
					command: "/bin/sh",
					args: ["-c", 'cat "$HERMES_HOME/auth.json"'],
					cwd: hermesHome,
					env: {
						HERMES_HOME: hermesHome,
						HERMES_CODEX_BASE_URL: "http://telclaude:8790/v1/openai-codex-proxy",
					},
					authSetup: {
						openAiCodexRelayToken: "relay-scoped-proxy-token",
					},
				},
				{ timeoutMs: 5_000 },
			);

			expect(result.exitCode).toBe(0);
			const auth = JSON.parse(result.stdout) as {
				providers: { "openai-codex": { tokens: Record<string, string> } };
				credential_pool: {
					"openai-codex": Array<Record<string, unknown>>;
				};
			};
			expect(auth.providers["openai-codex"].tokens.access_token).toBe("relay-scoped-proxy-token");
			expect(auth.providers["openai-codex"].tokens.refresh_token).toBe(
				"telclaude-relay-token-is-not-refreshable",
			);
			expect(auth.credential_pool["openai-codex"][0]).toMatchObject({
				id: "telclaude-relay",
				label: "Telclaude OpenAI Codex relay",
				auth_type: "api_key",
				priority: 0,
				source: "manual:telclaude-relay",
				access_token: "relay-scoped-proxy-token",
				base_url: "http://telclaude:8790/v1/openai-codex-proxy",
			});
			expect(JSON.stringify(auth)).not.toContain("https://chatgpt.com");
		} finally {
			fs.rmSync(hermesHome, { recursive: true, force: true });
		}
	});

	it("attaches runtime evidence emitted by the contained Hermes launcher", async () => {
		const hermesHome = fs.mkdtempSync(path.join(os.tmpdir(), "tc-hermes-runtime-"));
		const runtime = containedDockerRuntime({
			containerId: "0e6b7d5fbff2",
			hostname: "0e6b7d5fbff2",
		});
		try {
			const result = await runHermesLaunchInvocation(
				{
					command: "/bin/sh",
					args: [
						"-c",
						`cat > "$HERMES_HOME/runtime-evidence.json" <<'JSON'\n${JSON.stringify(
							runtime,
						)}\nJSON\necho HERMES_OK_RUNTIME`,
					],
					cwd: hermesHome,
					env: {
						HERMES_HOME: hermesHome,
					},
				},
				{ timeoutMs: 5_000 },
			);

			expect(result).toMatchObject({
				exitCode: 0,
				stdout: "HERMES_OK_RUNTIME\n",
				stderr: "",
				runtime,
			});
		} finally {
			fs.rmSync(hermesHome, { recursive: true, force: true });
		}
	});

	it("rejects contained runtime evidence with a loopback observed peer", async () => {
		const hermesHome = fs.mkdtempSync(path.join(os.tmpdir(), "tc-hermes-runtime-"));
		const runtime = containedDockerRuntime({
			observedPeerAddress: "127.0.0.1",
		});
		try {
			const result = await runHermesLaunchInvocation(
				{
					command: "/bin/sh",
					args: [
						"-c",
						`cat > "$HERMES_HOME/runtime-evidence.json" <<'JSON'\n${JSON.stringify(
							runtime,
						)}\nJSON\necho HERMES_OK_RUNTIME`,
					],
					cwd: hermesHome,
					env: {
						HERMES_HOME: hermesHome,
					},
				},
				{ timeoutMs: 5_000 },
			);

			expect(result).toMatchObject({
				exitCode: 0,
				stdout: "HERMES_OK_RUNTIME\n",
			});
			expect(result.runtime).toBeUndefined();
			expect(result.stderr).toContain(
				"failed to read Hermes runtime evidence: runtime evidence observedPeerAddress is loopback",
			);
		} finally {
			fs.rmSync(hermesHome, { recursive: true, force: true });
		}
	});

	it("rejects contained runtime evidence with a host-gateway relay address", async () => {
		const hermesHome = fs.mkdtempSync(path.join(os.tmpdir(), "tc-hermes-runtime-"));
		const runtime = containedDockerRuntime({
			relayResolvedAddress: "192.168.5.2",
		});
		try {
			const result = await runHermesLaunchInvocation(
				{
					command: "/bin/sh",
					args: [
						"-c",
						`cat > "$HERMES_HOME/runtime-evidence.json" <<'JSON'\n${JSON.stringify(
							runtime,
						)}\nJSON\necho HERMES_OK_RUNTIME`,
					],
					cwd: hermesHome,
					env: {
						HERMES_HOME: hermesHome,
					},
				},
				{ timeoutMs: 5_000 },
			);

			expect(result.runtime).toBeUndefined();
			expect(result.stderr).toContain(
				`failed to read Hermes runtime evidence: runtime evidence relayResolvedAddress is 192.168.5.2, expected ${TEST_HERMES_RELAY_IP}`,
			);
		} finally {
			fs.rmSync(hermesHome, { recursive: true, force: true });
		}
	});

	it("blocks raw model-provider keys even when the relay proxy URL is configured", () => {
		const invocation = buildHermesCliProbeInvocation({
			hermesBin: "/usr/local/bin/hermes",
			hermesHome: "/tmp/tc-hermes-probe",
			cwd: "/repo",
			env: {
				HERMES_CODEX_BASE_URL: "http://telclaude:8790/v1/openai-codex-proxy",
				TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN: "sk-proj-rawProviderKey",
			},
		});

		expect(findHermesLaunchSecretFindings(invocation)).toEqual([
			{
				location: "authSetup.openAiCodexRelayToken",
				reason: "raw model-provider credential is forbidden",
			},
		]);
	});

	it("blocks relay model auth when the base URL only mimics the relay path on another host", () => {
		const invocation = buildHermesCliProbeInvocation({
			hermesBin: "/usr/local/bin/hermes",
			hermesHome: "/tmp/tc-hermes-probe",
			cwd: "/repo",
			env: {
				HERMES_CODEX_BASE_URL: "http://evil.internal:8790/v1/openai-codex-proxy",
				TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN: "relay-scoped-proxy-token",
			},
		});

		expect(findHermesLaunchSecretFindings(invocation)).toEqual([
			{
				location: "env.HERMES_CODEX_BASE_URL",
				reason: "model base URL must point at the relay OpenAI Codex proxy",
			},
		]);
	});

	it("blocks relay model auth when the base URL points at a direct provider", () => {
		const invocation = buildHermesCliProbeInvocation({
			hermesBin: "/usr/local/bin/hermes",
			hermesHome: "/tmp/tc-hermes-probe",
			cwd: "/repo",
			env: {
				HERMES_CODEX_BASE_URL: "https://chatgpt.com/backend-api/codex",
				TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN: "relay-scoped-proxy-token",
			},
		});

		expect(findHermesLaunchSecretFindings(invocation)).toEqual([
			{
				location: "env.HERMES_CODEX_BASE_URL",
				reason: "model base URL must point at the relay OpenAI Codex proxy",
			},
		]);
	});

	it("fails a CLI headless probe when Hermes exits zero with runtime failure text", async () => {
		const invocation = buildHermesCliProbeInvocation({
			hermesBin: "/usr/local/bin/hermes",
			hermesHome: "/tmp/tc-hermes-probe",
			cwd: process.cwd(),
			prompt: "Reply with exactly TELCLAUDE_HERMES_CLI_OK",
			env: cliRelayEnv(),
		});
		const report = await runHermesCliHeadlessProbe({
			allowRun: true,
			invocation,
			runProcess: async () => ({
				exitCode: 0,
				stdout:
					"API call failed after 3 retries: HTTP 500: {'error': 'Anthropic credentials not configured.'}\n",
				stderr: "",
			}),
		});

		expect(report).toMatchObject({
			status: "fail",
			ran: true,
			summary: "Hermes CLI oneshot probe reported runtime failure: model API call failed",
			exitCode: 0,
			stdoutPreview: expect.stringContaining("API call failed after 3 retries"),
			findings: [],
		});
	});

	it("fails a CLI headless probe that exits zero without the expected proof token", async () => {
		const invocation = buildHermesCliProbeInvocation({
			hermesBin: "/usr/local/bin/hermes",
			hermesHome: "/tmp/tc-hermes-probe",
			cwd: process.cwd(),
			env: cliRelayEnv(),
		});
		const report = await runHermesCliHeadlessProbe({
			allowRun: true,
			invocation,
			runProcess: async () => ({
				exitCode: 0,
				stdout: "generic assistant response\n",
				stderr: "",
			}),
		});

		expect(report).toMatchObject({
			status: "fail",
			ran: true,
			summary:
				"Hermes CLI oneshot probe did not return expected proof token: TELCLAUDE_HERMES_CLI_OK",
			exitCode: 0,
			stdoutPreview: "generic assistant response\n",
			findings: [],
		});
	});
});

function baseRequest(
	overrides: Partial<Parameters<typeof executeHermesPrivateRuntime>[0]["request"]> = {},
) {
	return {
		prompt: "hello",
		cwd: "/repo",
		tier: "WRITE_LOCAL" as const,
		sessionKey: "tg:123",
		telclaudeSessionId: "tc-session-1",
		profileId: "ops",
		identity: {
			userId: "operator",
			chatId: 123,
			actorId: 456,
			threadId: 789,
		},
		memory: {
			compiledMemoryMd: "# Memory\n- family prefers WhatsApp",
		},
		model: "anthropic/claude-sonnet",
		systemPromptAppend: "<context />",
		allowedSkills: ["external-provider"],
		isNewSession: true,
		timeoutMs: 60_000,
		signal: new AbortController().signal,
		...overrides,
	};
}

function cliRelayEnv(overrides: Record<string, string> = {}): NodeJS.ProcessEnv {
	return {
		HERMES_CODEX_BASE_URL: "http://telclaude:8790/v1/openai-codex-proxy",
		TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN: "relay-scoped-proxy-token",
		HERMES_INFERENCE_PROVIDER: "openai-codex",
		HERMES_INFERENCE_MODEL: "gpt-5.3-codex",
		...overrides,
	};
}

function containedDockerRuntime(
	overrides: Partial<TestContainedDockerRuntime> = {},
): TestContainedDockerRuntime {
	return {
		kind: "contained-docker" as const,
		containerName: "tc-hermes-contained",
		networkName: "telclaude-hermes-relay" as const,
		containerId: "b6d8f6c9a1d4",
		image:
			"nousresearch/hermes-agent@sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7",
		imageDigest: "sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7" as const,
		hostname: "b6d8f6c9a1d4",
		relayHost: "telclaude" as const,
		relayResolvedAddress: TEST_HERMES_RELAY_IP,
		containerIpAddress: TEST_HERMES_CONTAINED_IP,
		observedPeerAddress: TEST_HERMES_CONTAINED_IP,
		provenanceSource: "docker-inspect-container-dns-and-relay-peer" as const,
		...overrides,
	};
}

function relayProof(
	overrides: Partial<OpenAiCodexRelayProofSignedFields> = {},
	expectedProofToken = "TELCLAUDE_HERMES_CLI_OK",
): TestRelayProof {
	return signOpenAiCodexRelayProof({
		schemaVersion: "telclaude.hermes.cli-headless-relay-proof.v1",
		source: "telclaude-openai-codex-proxy",
		requestId: "codex-proof-1",
		method: "POST",
		path: "/backend-api/codex/responses",
		observedPeerAddress: TEST_HERMES_CONTAINED_IP,
		upstreamStatus: 200,
		model: "gpt-5.3-codex",
		requestBodySha256: `sha256:${"a".repeat(64)}`,
		proofTokenSha256: openAiCodexRelayProofTokenSha256(expectedProofToken),
		observedAt: new Date().toISOString(),
		...overrides,
	});
}

async function collect<T>(iterable: AsyncIterable<T>): Promise<T[]> {
	const values: T[] = [];
	for await (const value of iterable) values.push(value);
	return values;
}

function restoreEnv(key: keyof typeof ORIGINAL_ENV): void {
	const value = ORIGINAL_ENV[key];
	if (value === undefined) {
		delete process.env[key];
	} else {
		process.env[key] = value;
	}
}
