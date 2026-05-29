import { describe, expect, it, vi } from "vitest";
import {
	executeHermesPrivateQuery,
	setHermesPrivateRuntimeAdapterForTest,
	shouldUseHermesPrivateRuntime,
} from "../../src/hermes/private-execute.js";
import {
	buildHermesCliProbeInvocation,
	executeHermesPrivateRuntime,
	findHermesLaunchSecretFindings,
	type HermesRuntimeAdapter,
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
				timeoutMs: 60_000,
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
			sessionKey: "tg:123",
			telclaudeSessionId: "tc-session-1",
			profileId: "ops",
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
			prompt: "telclaude probe ok",
		});
		const report = await runHermesCliHeadlessProbe({
			allowRun: true,
			invocation,
			runProcess: async (launch) => {
				expect(launch.args).toEqual(["-z", "telclaude probe ok"]);
				expect(launch.env).toEqual({ HERMES_HOME: "/tmp/tc-hermes-probe", NO_COLOR: "1" });
				return {
					exitCode: 0,
					stdout: "ok",
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
			exitCode: 0,
			stdoutPreview: "ok",
			stderrPreview: "token [REDACTED:telegram_bot_token]",
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
		sessionKey: "tg:123",
		telclaudeSessionId: "tc-session-1",
		profileId: "ops",
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
