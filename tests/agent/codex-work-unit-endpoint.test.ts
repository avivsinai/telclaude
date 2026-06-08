import { once } from "node:events";
import path from "node:path";
import type { AddressInfo } from "node:net";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// The endpoint must delegate to the executor without spawning real Codex.
const codexExecImpl = vi.hoisted(() => vi.fn());

vi.mock("../../src/agent-runtime/codex-work-unit.js", () => ({
	codexWorkUnitExecutor: (...args: unknown[]) => codexExecImpl(...args),
}));

// Server pulls these in at import; stub them like tests/agent/server.test.ts.
vi.mock("../../src/sdk/client.js", () => ({
	executePooledQuery: vi.fn(),
}));
vi.mock("../../src/soul.js", () => ({ loadSoul: vi.fn(() => "") }));
vi.mock("../../src/social-contract.js", () => ({ loadSocialContractPrompt: vi.fn(() => "") }));
vi.mock("../../src/relay/capabilities-client.js", () => ({ relayGetProviders: vi.fn() }));
vi.mock("../../src/providers/provider-skill.js", () => ({
	getCachedProviderSummary: () => null,
	writeProviderSchemaFromRelay: vi.fn(),
	clearProviderSkillState: vi.fn(),
}));
vi.mock("../../src/logging.js", () => ({
	getChildLogger: () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }),
}));

import { startAgentServer } from "../../src/agent/server.js";
import { buildInternalAuthHeaders, generateKeyPair } from "../../src/internal-auth.js";

const PATH = "/v1/codex-work-unit";

// Snapshot RPC env so we can restore it; the suite owns telegram + social keys.
const ENV_KEYS = [
	"TELEGRAM_RPC_AGENT_PRIVATE_KEY",
	"TELEGRAM_RPC_AGENT_PUBLIC_KEY",
	"SOCIAL_RPC_AGENT_PRIVATE_KEY",
	"SOCIAL_RPC_AGENT_PUBLIC_KEY",
] as const;

describe("agent codex-work-unit endpoint", () => {
	let server: ReturnType<typeof startAgentServer> | null = null;
	let baseUrl = "";
	const original: Record<string, string | undefined> = {};

	beforeEach(async () => {
		for (const key of ENV_KEYS) original[key] = process.env[key];
		const telegram = generateKeyPair();
		process.env.TELEGRAM_RPC_AGENT_PRIVATE_KEY = telegram.privateKey;
		process.env.TELEGRAM_RPC_AGENT_PUBLIC_KEY = telegram.publicKey;
		const social = generateKeyPair();
		process.env.SOCIAL_RPC_AGENT_PRIVATE_KEY = social.privateKey;
		process.env.SOCIAL_RPC_AGENT_PUBLIC_KEY = social.publicKey;

		server = startAgentServer({ port: 0, host: "127.0.0.1" });
		await once(server, "listening");
		baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
	});

	afterEach(() => {
		server?.close();
		server = null;
		codexExecImpl.mockReset();
		for (const key of ENV_KEYS) {
			if (original[key] === undefined) delete process.env[key];
			else process.env[key] = original[key];
		}
	});

	function post(body: string, scope: "telegram" | "social") {
		return fetch(`${baseUrl}${PATH}`, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				...buildInternalAuthHeaders("POST", PATH, body, { scope }),
			},
			body,
		});
	}

	it("runs a telegram codex work unit and returns the executor result", async () => {
		codexExecImpl.mockResolvedValueOnce({ ok: true, result: { message: "Codex completed: ok" } });
		const body = JSON.stringify({ prompt: "audit src/", tier: "WRITE_LOCAL" });

		const res = await post(body, "telegram");
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ ok: true, result: { message: "Codex completed: ok" } });

		expect(codexExecImpl).toHaveBeenCalledTimes(1);
		const [job, signal, options] = codexExecImpl.mock.calls[0] as [
			{ tier: string; payload: { kind: string; prompt: string } },
			AbortSignal,
			{ rootCwd: string },
		];
		expect(job.payload.kind).toBe("codex-work-unit");
		expect(job.payload.prompt).toBe("audit src/");
		expect(job.tier).toBe("WRITE_LOCAL");
		expect(signal).toBeInstanceOf(AbortSignal);
		expect(options.rootCwd).toBe(path.resolve(process.cwd()));
	});

	it("rejects READ_ONLY tier with 403 (parity with the Telegram queue)", async () => {
		const body = JSON.stringify({ prompt: "x", tier: "READ_ONLY" });
		const res = await post(body, "telegram");
		expect(res.status).toBe(403);
		expect(codexExecImpl).not.toHaveBeenCalled();
	});

	it("forwards model + sandbox to the executor", async () => {
		codexExecImpl.mockResolvedValueOnce({ ok: true, result: { message: "ok" } });
		const body = JSON.stringify({
			prompt: "fix it",
			tier: "FULL_ACCESS",
			sandbox: "workspace-write",
			model: "gpt-5.5",
		});

		await post(body, "telegram");
		const [job] = codexExecImpl.mock.calls[0] as [
			{ payload: { sandbox: string; model?: string } },
		];
		expect(job.payload.sandbox).toBe("workspace-write");
		expect(job.payload.model).toBe("gpt-5.5");
	});

	it("rejects SOCIAL tier with 403 and never runs the executor", async () => {
		const body = JSON.stringify({ prompt: "x", tier: "SOCIAL" });
		const res = await post(body, "telegram");
		expect(res.status).toBe(403);
		expect(codexExecImpl).not.toHaveBeenCalled();
	});

	it("rejects a non-telegram (social) scope with 403", async () => {
		const body = JSON.stringify({ prompt: "x", tier: "READ_ONLY" });
		const res = await post(body, "social");
		expect(res.status).toBe(403);
		expect(codexExecImpl).not.toHaveBeenCalled();
	});

	it("rejects a missing prompt with 400", async () => {
		const body = JSON.stringify({ tier: "READ_ONLY" });
		const res = await post(body, "telegram");
		expect(res.status).toBe(400);
		expect(codexExecImpl).not.toHaveBeenCalled();
	});

	it("rejects unsigned requests with 401", async () => {
		const body = JSON.stringify({ prompt: "x", tier: "READ_ONLY" });
		const res = await fetch(`${baseUrl}${PATH}`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body,
		});
		expect(res.status).toBe(401);
		expect(codexExecImpl).not.toHaveBeenCalled();
	});
});
