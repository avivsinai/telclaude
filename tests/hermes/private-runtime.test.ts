import { describe, expect, it } from "vitest";
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
} from "../../src/hermes/private-runtime.js";
import { HermesSessionMap } from "../../src/hermes/session-map.js";

describe("Hermes private runtime seam", () => {
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
			cwd: "/repo",
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
			cwd: "/repo",
			prompt: "Reply with exactly TELCLAUDE_HERMES_CLI_OK",
		});
		const report = await runHermesCliHeadlessProbe({
			allowRun: true,
			invocation,
			runProcess: async (launch) => {
				expect(launch.args).toEqual(["-z", "Reply with exactly TELCLAUDE_HERMES_CLI_OK"]);
				expect(launch.env).toEqual({ HERMES_HOME: "/tmp/tc-hermes-probe", NO_COLOR: "1" });
				return {
					exitCode: 0,
					stdout: "TELCLAUDE_HERMES_CLI_OK\n",
					stderr: "token 123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi",
				};
			},
		});

		expect(report).toEqual({
			schemaVersion: "telclaude.hermes.probe-result.v1",
			probeId: "execution.cli_headless",
			status: "pass",
			ran: true,
			summary: "Hermes CLI oneshot probe completed successfully",
			invocation: {
				command: "/usr/local/bin/hermes",
				args: ["-z", "Reply with exactly TELCLAUDE_HERMES_CLI_OK"],
				cwd: "/repo",
				envKeys: ["HERMES_HOME", "NO_COLOR"],
			},
			exitCode: 0,
			stdoutPreview: "TELCLAUDE_HERMES_CLI_OK\n",
			stderrPreview: "token [REDACTED:telegram_bot_token]",
			findings: [],
		});
	});

	it("passes only relay Anthropic proxy model env into the CLI headless launch", async () => {
		const invocation = buildHermesCliProbeInvocation({
			hermesBin: "/usr/local/bin/hermes",
			hermesHome: "/tmp/tc-hermes-probe",
			cwd: "/repo",
			prompt: "Reply with exactly HERMES_OK_53822847",
			env: {
				ANTHROPIC_BASE_URL: "http://telclaude:8790/v1/anthropic-proxy",
				ANTHROPIC_API_KEY: "relay-scoped-proxy-token",
				OPENAI_API_KEY: "sk-proj-raw-provider-key",
			},
		});
		const report = await runHermesCliHeadlessProbe({
			allowRun: true,
			invocation,
			runProcess: async (launch) => {
				expect(launch.env).toEqual({
					HERMES_HOME: "/tmp/tc-hermes-probe",
					NO_COLOR: "1",
					ANTHROPIC_BASE_URL: "http://telclaude:8790/v1/anthropic-proxy",
					ANTHROPIC_API_KEY: "relay-scoped-proxy-token",
				});
				return {
					exitCode: 0,
					stdout: "HERMES_OK_53822847\n",
					stderr: "",
				};
			},
		});

		expect(report).toMatchObject({
			status: "pass",
			ran: true,
			invocation: {
				envKeys: [
					"ANTHROPIC_API_KEY",
					"ANTHROPIC_BASE_URL",
					"HERMES_HOME",
					"NO_COLOR",
				],
			},
			modelProvider: {
				baseUrl: "http://telclaude:8790/v1/anthropic-proxy",
				baseUrlHost: "telclaude",
				authEnvKey: "ANTHROPIC_API_KEY",
				authScope: "relay-anthropic-proxy",
				tokenScoping: "static-shared",
			},
			findings: [],
		});
		expect(JSON.stringify(report)).not.toContain("relay-scoped-proxy-token");
		expect(JSON.stringify(report)).not.toContain("sk-proj-raw-provider-key");
	});

	it("blocks raw model-provider keys even when the relay proxy URL is configured", () => {
		const invocation = buildHermesCliProbeInvocation({
			hermesBin: "/usr/local/bin/hermes",
			hermesHome: "/tmp/tc-hermes-probe",
			cwd: "/repo",
			env: {
				ANTHROPIC_BASE_URL: "http://telclaude:8790/v1/anthropic-proxy",
				ANTHROPIC_API_KEY: "sk-ant-api03-rawProviderKey",
			},
		});

		expect(findHermesLaunchSecretFindings(invocation)).toEqual([
			{
				location: "env.ANTHROPIC_API_KEY",
				reason: "raw model-provider credential is forbidden",
			},
		]);
	});

	it("blocks relay model auth when the base URL points at a direct provider", () => {
		const invocation = buildHermesCliProbeInvocation({
			hermesBin: "/usr/local/bin/hermes",
			hermesHome: "/tmp/tc-hermes-probe",
			cwd: "/repo",
			env: {
				ANTHROPIC_BASE_URL: "https://api.anthropic.com/v1/anthropic-proxy",
				ANTHROPIC_API_KEY: "relay-scoped-proxy-token",
			},
		});

		expect(findHermesLaunchSecretFindings(invocation)).toEqual([
			{
				location: "env.ANTHROPIC_BASE_URL",
				reason: "model base URL must point at the relay Anthropic proxy",
			},
			{
				location: "env.ANTHROPIC_API_KEY",
				reason: "forbidden credential environment key",
			},
		]);
	});

	it("fails a CLI headless probe when Hermes exits zero with runtime failure text", async () => {
		const invocation = buildHermesCliProbeInvocation({
			hermesBin: "/usr/local/bin/hermes",
			hermesHome: "/tmp/tc-hermes-probe",
			cwd: "/repo",
			prompt: "Reply with exactly TELCLAUDE_HERMES_CLI_OK",
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
			cwd: "/repo",
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

async function collect<T>(iterable: AsyncIterable<T>): Promise<T[]> {
	const values: T[] = [];
	for await (const value of iterable) values.push(value);
	return values;
}
