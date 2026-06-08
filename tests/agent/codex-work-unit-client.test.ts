import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Capture what the hosted runner forwards to startBackgroundRunner.
const startBackgroundRunnerMock = vi.hoisted(() => vi.fn(() => ({ stop: vi.fn() })));

vi.mock("../../src/background/index.js", () => ({
	startBackgroundRunner: (...args: unknown[]) => startBackgroundRunnerMock(...args),
	markInterruptedOnStartup: vi.fn(() => []),
	emitCompletionNotification: vi.fn(),
}));
vi.mock("../../src/logging.js", () => ({
	getChildLogger: () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }),
}));

import { remoteCodexWorkUnitExecutor } from "../../src/agent/codex-work-unit-client.js";
import { startHostedBackgroundRunner } from "../../src/background/host.js";
import type { BackgroundJob } from "../../src/background/types.js";
import { generateKeyPair } from "../../src/internal-auth.js";

function codexJob(overrides: Partial<BackgroundJob> = {}): BackgroundJob {
	return {
		id: "job-1",
		shortId: "abcd1234",
		userId: "u1",
		chatId: 1,
		threadId: null,
		tier: "FULL_ACCESS",
		title: "codex",
		description: null,
		status: "running",
		payload: { kind: "codex-work-unit", prompt: "do it", sandbox: "read-only" },
		result: null,
		error: null,
		createdAtMs: 0,
		startedAtMs: 0,
		completedAtMs: null,
		cancelledAtMs: null,
		...overrides,
	};
}

describe("remoteCodexWorkUnitExecutor", () => {
	const ORIGINAL_URL = process.env.TELCLAUDE_AGENT_URL;
	const ORIGINAL_KEY = process.env.TELEGRAM_RPC_AGENT_PRIVATE_KEY;

	beforeEach(() => {
		process.env.TELCLAUDE_AGENT_URL = "http://agent:8788";
		process.env.TELEGRAM_RPC_AGENT_PRIVATE_KEY = generateKeyPair().privateKey;
	});

	afterEach(() => {
		vi.unstubAllGlobals();
		if (ORIGINAL_URL === undefined) delete process.env.TELCLAUDE_AGENT_URL;
		else process.env.TELCLAUDE_AGENT_URL = ORIGINAL_URL;
		if (ORIGINAL_KEY === undefined) delete process.env.TELEGRAM_RPC_AGENT_PRIVATE_KEY;
		else process.env.TELEGRAM_RPC_AGENT_PRIVATE_KEY = ORIGINAL_KEY;
	});

	it("POSTs to the agent endpoint with internal-auth and returns the result", async () => {
		const fetchMock = vi.fn(async () => ({
			ok: true,
			status: 200,
			statusText: "OK",
			json: async () => ({ ok: true, result: { message: "Codex completed: done" } }),
			text: async () => "",
		}));
		vi.stubGlobal("fetch", fetchMock);

		const result = await remoteCodexWorkUnitExecutor(codexJob(), new AbortController().signal);

		expect(result).toEqual({ ok: true, result: { message: "Codex completed: done" } });
		expect(fetchMock).toHaveBeenCalledTimes(1);
		const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit & { headers: Record<string, string> }];
		expect(url).toBe("http://agent:8788/v1/codex-work-unit");
		expect(init.method).toBe("POST");
		expect(init.headers["X-Telclaude-Signature"]).toBeTruthy();
		// Payload carries the job's tier + sandbox, not the durable creds.
		expect(JSON.parse(init.body as string)).toMatchObject({ tier: "FULL_ACCESS", prompt: "do it" });
	});

	it("surfaces a non-2xx agent response as a failed result", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn(async () => ({
				ok: false,
				status: 403,
				statusText: "Forbidden",
				json: async () => ({}),
				text: async () => "SOCIAL tier cannot run Codex work units.",
			})),
		);
		const result = await remoteCodexWorkUnitExecutor(codexJob(), new AbortController().signal);
		expect(result.ok).toBe(false);
		expect(result.error).toContain("403");
	});

	it("returns Aborted when the runner signal is already aborted", async () => {
		const fetchMock = vi.fn(async () => {
			throw Object.assign(new Error("aborted"), { name: "AbortError" });
		});
		vi.stubGlobal("fetch", fetchMock);
		const controller = new AbortController();
		controller.abort();
		const result = await remoteCodexWorkUnitExecutor(codexJob(), controller.signal);
		expect(result).toEqual({ ok: false, error: "Aborted" });
	});

	it("fails closed when TELCLAUDE_AGENT_URL is unset", async () => {
		delete process.env.TELCLAUDE_AGENT_URL;
		const result = await remoteCodexWorkUnitExecutor(codexJob(), new AbortController().signal);
		expect(result).toEqual({ ok: false, error: "TELCLAUDE_AGENT_URL is not configured" });
	});
});

describe("startHostedBackgroundRunner codex delegation", () => {
	const ORIGINAL_URL = process.env.TELCLAUDE_AGENT_URL;

	beforeEach(() => startBackgroundRunnerMock.mockClear());
	afterEach(() => {
		if (ORIGINAL_URL === undefined) delete process.env.TELCLAUDE_AGENT_URL;
		else process.env.TELCLAUDE_AGENT_URL = ORIGINAL_URL;
	});

	it("delegates codex work units to the agent when TELCLAUDE_AGENT_URL is set", () => {
		process.env.TELCLAUDE_AGENT_URL = "http://agent:8788";
		startHostedBackgroundRunner({});
		const opts = startBackgroundRunnerMock.mock.calls[0][0] as {
			executors?: Record<string, unknown>;
		};
		expect(opts.executors?.["codex-work-unit"]).toBe(remoteCodexWorkUnitExecutor);
	});

	it("does not delegate when TELCLAUDE_AGENT_URL is unset (relay runs locally)", () => {
		delete process.env.TELCLAUDE_AGENT_URL;
		startHostedBackgroundRunner({});
		const opts = startBackgroundRunnerMock.mock.calls[0][0] as {
			executors?: Record<string, unknown>;
		};
		expect(opts.executors?.["codex-work-unit"]).toBeUndefined();
	});

	it("lets an explicit executor override win over delegation", () => {
		process.env.TELCLAUDE_AGENT_URL = "http://agent:8788";
		const custom = vi.fn();
		startHostedBackgroundRunner({ executors: { "codex-work-unit": custom } });
		const opts = startBackgroundRunnerMock.mock.calls[0][0] as {
			executors?: Record<string, unknown>;
		};
		expect(opts.executors?.["codex-work-unit"]).toBe(custom);
	});
});
