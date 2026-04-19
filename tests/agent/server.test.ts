import { once } from "node:events";
import type { AddressInfo } from "node:net";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const executePooledQueryImpl = vi.hoisted(() => vi.fn());
const loadSoulImpl = vi.hoisted(() => vi.fn(() => ""));
const loadSocialContractImpl = vi.hoisted(() => vi.fn(() => ""));
const relayGetProvidersImpl = vi.hoisted(() => vi.fn());
const providerSummaryState = vi.hoisted(() => ({ summary: null as string | null }));
const refreshExternalProviderSkillImpl = vi.hoisted(() =>
	vi.fn(async (providers: Array<{ id: string }>) => {
		providerSummaryState.summary =
			providers.length > 0 ? `summary:${providers.map((provider) => provider.id).join(",")}` : null;
	}),
);
const writeProviderSchemaFromRelayImpl = vi.hoisted(() =>
	vi.fn(async (providers: Array<{ id: string }>) => {
		providerSummaryState.summary =
			providers.length > 0 ? `summary:${providers.map((provider) => provider.id).join(",")}` : null;
	}),
);
const clearProviderSkillStateImpl = vi.hoisted(() =>
	vi.fn(async () => {
		providerSummaryState.summary = null;
	}),
);

vi.mock("../../src/sdk/client.js", () => ({
	executePooledQuery: (...args: unknown[]) => executePooledQueryImpl(...args),
}));

vi.mock("../../src/soul.js", () => ({
	loadSoul: (...args: unknown[]) => loadSoulImpl(...args),
}));

vi.mock("../../src/social-contract.js", () => ({
	loadSocialContractPrompt: (...args: unknown[]) => loadSocialContractImpl(...args),
}));

vi.mock("../../src/relay/capabilities-client.js", () => ({
	relayGetProviders: (...args: unknown[]) => relayGetProvidersImpl(...args),
}));

vi.mock("../../src/providers/provider-skill.js", () => ({
	getCachedProviderSummary: () => providerSummaryState.summary,
	refreshExternalProviderSkill: (...args: unknown[]) => refreshExternalProviderSkillImpl(...args),
	writeProviderSchemaFromRelay: (...args: unknown[]) => writeProviderSchemaFromRelayImpl(...args),
	clearProviderSkillState: (...args: unknown[]) => clearProviderSkillStateImpl(...args),
}));

vi.mock("../../src/logging.js", () => ({
	getChildLogger: () => ({
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		debug: vi.fn(),
	}),
}));

import { startAgentServer } from "../../src/agent/server.js";
import { buildInternalAuthHeaders, generateKeyPair } from "../../src/internal-auth.js";

const ORIGINAL_SOCIAL_AGENT_PRIVATE_KEY = process.env.SOCIAL_RPC_AGENT_PRIVATE_KEY;
const ORIGINAL_SOCIAL_AGENT_PUBLIC_KEY = process.env.SOCIAL_RPC_AGENT_PUBLIC_KEY;

describe("agent server social userId normalization", () => {
	let server: ReturnType<typeof startAgentServer> | null = null;
	let baseUrl = "";

	beforeEach(async () => {
		// Generate Ed25519 key pair for social asymmetric auth (agent keypair for test)
		const { privateKey, publicKey } = generateKeyPair();
		process.env.SOCIAL_RPC_AGENT_PRIVATE_KEY = privateKey;
		process.env.SOCIAL_RPC_AGENT_PUBLIC_KEY = publicKey;

		server = startAgentServer({ port: 0, host: "127.0.0.1" });
		await once(server, "listening");
		const address = server.address() as AddressInfo;
		baseUrl = `http://127.0.0.1:${address.port}`;
	});

	afterEach(() => {
		if (server) {
			server.close();
			server = null;
		}
		executePooledQueryImpl.mockReset();
		relayGetProvidersImpl.mockReset();
		refreshExternalProviderSkillImpl.mockReset();
		writeProviderSchemaFromRelayImpl.mockReset();
		clearProviderSkillStateImpl.mockReset();
		providerSummaryState.summary = null;
		if (ORIGINAL_SOCIAL_AGENT_PRIVATE_KEY === undefined) {
			delete process.env.SOCIAL_RPC_AGENT_PRIVATE_KEY;
		} else {
			process.env.SOCIAL_RPC_AGENT_PRIVATE_KEY = ORIGINAL_SOCIAL_AGENT_PRIVATE_KEY;
		}
		if (ORIGINAL_SOCIAL_AGENT_PUBLIC_KEY === undefined) {
			delete process.env.SOCIAL_RPC_AGENT_PUBLIC_KEY;
		} else {
			process.env.SOCIAL_RPC_AGENT_PUBLIC_KEY = ORIGINAL_SOCIAL_AGENT_PUBLIC_KEY;
		}
	});

	it("returns health metadata", async () => {
		const res = await fetch(`${baseUrl}/health`, { method: "GET" });
		expect(res.status).toBe(200);
		const payload = (await res.json()) as {
			ok?: boolean;
			service?: string;
			runtime?: { version: string; revision: string; startedAt: string; uptimeSeconds: number };
		};
		expect(payload.ok).toBe(true);
		expect(payload.service).toBe("agent");
		expect(payload.runtime).toBeTypeOf("object");
		expect(typeof payload.runtime?.version).toBe("string");
		expect(typeof payload.runtime?.revision).toBe("string");
		expect(typeof payload.runtime?.startedAt).toBe("string");
		expect(typeof payload.runtime?.uptimeSeconds).toBe("number");
	});

	it("forces social prefix for social scope userId", async () => {
		executePooledQueryImpl.mockReturnValueOnce(
			(async function* () {
				yield {
					type: "done",
					result: {
						response: "ok",
						success: true,
						error: undefined,
						costUsd: 0,
						numTurns: 0,
						durationMs: 1,
					},
				};
			})(),
		);

		const body = JSON.stringify({
			prompt: "hi",
			tier: "READ_ONLY",
			poolKey: "pool-1",
			userId: "user-1",
		});
		const headers = buildInternalAuthHeaders("POST", "/v1/query", body, { scope: "social" });

		const res = await fetch(`${baseUrl}/v1/query`, {
			method: "POST",
			headers: { "Content-Type": "application/json", ...headers },
			body,
		});
		await res.text();

		expect(executePooledQueryImpl).toHaveBeenCalledTimes(1);
		const [, options] = executePooledQueryImpl.mock.calls[0] as [string, { userId?: string }];
		expect(options.userId).toBe("social:user-1");
	});

	it("passes compiled relay memory through to pooled queries", async () => {
		executePooledQueryImpl.mockReturnValueOnce(
			(async function* () {
				yield {
					type: "done",
					result: {
						response: "ok",
						success: true,
						error: undefined,
						costUsd: 0,
						numTurns: 0,
						durationMs: 1,
					},
				};
			})(),
		);

		const body = JSON.stringify({
			prompt: "hi",
			tier: "READ_ONLY",
			poolKey: "pool-1",
			userId: "user-1",
			compiledMemoryMd: "# Memory\nhello",
		});
		const headers = buildInternalAuthHeaders("POST", "/v1/query", body, { scope: "social" });

		const res = await fetch(`${baseUrl}/v1/query`, {
			method: "POST",
			headers: { "Content-Type": "application/json", ...headers },
			body,
		});
		await res.text();

		const [, options] = executePooledQueryImpl.mock.calls[0] as [
			string,
			{ compiledMemoryMd?: string },
		];
		expect(options.compiledMemoryMd).toBe("# Memory\nhello");
	});
});

describe("agent server soul + social contract prompt assembly", () => {
	let server: ReturnType<typeof startAgentServer> | null = null;
	let baseUrl = "";

	const ORIGINAL_TELEGRAM_PRIVATE_KEY = process.env.TELEGRAM_RPC_AGENT_PRIVATE_KEY;
	const ORIGINAL_TELEGRAM_PUBLIC_KEY = process.env.TELEGRAM_RPC_AGENT_PUBLIC_KEY;
	const ORIGINAL_CAPABILITIES_URL = process.env.TELCLAUDE_CAPABILITIES_URL;

	function mockDoneResponse() {
		executePooledQueryImpl.mockReturnValueOnce(
			(async function* () {
				yield {
					type: "done",
					result: {
						response: "ok",
						success: true,
						error: undefined,
						costUsd: 0,
						numTurns: 0,
						durationMs: 1,
					},
				};
			})(),
		);
	}

	beforeEach(async () => {
		// Set up both telegram and social keypairs
		const telegramKeys = generateKeyPair();
		process.env.TELEGRAM_RPC_AGENT_PRIVATE_KEY = telegramKeys.privateKey;
		process.env.TELEGRAM_RPC_AGENT_PUBLIC_KEY = telegramKeys.publicKey;
		const socialKeys = generateKeyPair();
		process.env.SOCIAL_RPC_AGENT_PRIVATE_KEY = socialKeys.privateKey;
		process.env.SOCIAL_RPC_AGENT_PUBLIC_KEY = socialKeys.publicKey;
		process.env.TELCLAUDE_CAPABILITIES_URL = "http://relay.test";

		loadSoulImpl.mockReturnValue("test soul content");
		loadSocialContractImpl.mockReturnValue("test social contract");

		server = startAgentServer({ port: 0, host: "127.0.0.1" });
		await once(server, "listening");
		const address = server.address() as AddressInfo;
		baseUrl = `http://127.0.0.1:${address.port}`;
	});

	afterEach(() => {
		if (server) {
			server.close();
			server = null;
		}
		executePooledQueryImpl.mockReset();
		loadSoulImpl.mockReset();
		loadSocialContractImpl.mockReset();
		relayGetProvidersImpl.mockReset();
		refreshExternalProviderSkillImpl.mockReset();
		writeProviderSchemaFromRelayImpl.mockReset();
		clearProviderSkillStateImpl.mockReset();
		providerSummaryState.summary = null;

		for (const [key, original] of [
			["TELEGRAM_RPC_AGENT_PRIVATE_KEY", ORIGINAL_TELEGRAM_PRIVATE_KEY],
			["TELEGRAM_RPC_AGENT_PUBLIC_KEY", ORIGINAL_TELEGRAM_PUBLIC_KEY],
			["SOCIAL_RPC_AGENT_PRIVATE_KEY", ORIGINAL_SOCIAL_AGENT_PRIVATE_KEY],
			["SOCIAL_RPC_AGENT_PUBLIC_KEY", ORIGINAL_SOCIAL_AGENT_PUBLIC_KEY],
			["TELCLAUDE_CAPABILITIES_URL", ORIGINAL_CAPABILITIES_URL],
		] as const) {
			if (original === undefined) {
				delete process.env[key];
			} else {
				process.env[key] = original;
			}
		}
	});

	it("injects soul exactly once for telegram scope", async () => {
		mockDoneResponse();

		const body = JSON.stringify({
			prompt: "hi",
			tier: "WRITE_LOCAL",
			poolKey: "pool-1",
			userId: "op-1",
		});
		const headers = buildInternalAuthHeaders("POST", "/v1/query", body, { scope: "telegram" });
		const res = await fetch(`${baseUrl}/v1/query`, {
			method: "POST",
			headers: { "Content-Type": "application/json", ...headers },
			body,
		});
		await res.text();

		expect(executePooledQueryImpl).toHaveBeenCalledTimes(1);
		const [, options] = executePooledQueryImpl.mock.calls[0] as [
			string,
			{ systemPromptAppend?: string },
		];
		const append = options.systemPromptAppend ?? "";

		// Soul appears exactly once
		const soulMatches = append.match(/<soul>/g);
		expect(soulMatches).toHaveLength(1);
		expect(append).toContain("test soul content");
		expect(append).toContain("</soul>");

		// Social contract also present with private persona
		expect(append).toContain("<social-contract>");
		expect(append).toContain("<active-persona>private</active-persona>");
	});

	it("injects soul exactly once for social scope", async () => {
		mockDoneResponse();

		const body = JSON.stringify({
			prompt: "hi",
			tier: "SOCIAL",
			poolKey: "pool-social",
			userId: "agent",
		});
		const headers = buildInternalAuthHeaders("POST", "/v1/query", body, { scope: "social" });
		const res = await fetch(`${baseUrl}/v1/query`, {
			method: "POST",
			headers: { "Content-Type": "application/json", ...headers },
			body,
		});
		await res.text();

		expect(executePooledQueryImpl).toHaveBeenCalledTimes(1);
		const [, options] = executePooledQueryImpl.mock.calls[0] as [
			string,
			{ systemPromptAppend?: string },
		];
		const append = options.systemPromptAppend ?? "";

		// Soul appears exactly once
		const soulMatches = append.match(/<soul>/g);
		expect(soulMatches).toHaveLength(1);
		expect(append).toContain("test soul content");

		// Social contract present with public persona
		expect(append).toContain("<social-contract>");
		expect(append).toContain("<active-persona>public</active-persona>");
	});

	it("soul appears before social contract in prompt order", async () => {
		mockDoneResponse();

		const body = JSON.stringify({
			prompt: "hi",
			tier: "WRITE_LOCAL",
			poolKey: "pool-1",
			userId: "op-1",
		});
		const headers = buildInternalAuthHeaders("POST", "/v1/query", body, { scope: "telegram" });
		const res = await fetch(`${baseUrl}/v1/query`, {
			method: "POST",
			headers: { "Content-Type": "application/json", ...headers },
			body,
		});
		await res.text();

		const [, options] = executePooledQueryImpl.mock.calls[0] as [
			string,
			{ systemPromptAppend?: string },
		];
		const append = options.systemPromptAppend ?? "";

		const soulIdx = append.indexOf("<soul>");
		const contractIdx = append.indexOf("<social-contract>");
		expect(soulIdx).toBeLessThan(contractIdx);
	});

	it("omits soul block when loadSoul returns empty", async () => {
		loadSoulImpl.mockReturnValue("");
		mockDoneResponse();

		const body = JSON.stringify({
			prompt: "hi",
			tier: "WRITE_LOCAL",
			poolKey: "pool-1",
			userId: "op-1",
		});
		const headers = buildInternalAuthHeaders("POST", "/v1/query", body, { scope: "telegram" });
		const res = await fetch(`${baseUrl}/v1/query`, {
			method: "POST",
			headers: { "Content-Type": "application/json", ...headers },
			body,
		});
		await res.text();

		const [, options] = executePooledQueryImpl.mock.calls[0] as [
			string,
			{ systemPromptAppend?: string },
		];
		const append = options.systemPromptAppend ?? "";

		expect(append).not.toContain("<soul>");
		// Social contract should still be present
		expect(append).toContain("<social-contract>");
	});

	it("refreshes provider summary from the relay before each telegram query", async () => {
		relayGetProvidersImpl.mockResolvedValueOnce({
			ok: true,
			providers: [
				{
					id: "israel-services",
					baseUrl: "http://israel-services.local:3001",
					services: ["gov-api"],
					description: "Citizen services",
				},
			],
			schemaMarkdown: "# schema",
			providersEpoch: "epoch-1",
		});
		mockDoneResponse();

		const body = JSON.stringify({
			prompt: "hi",
			tier: "WRITE_LOCAL",
			poolKey: "pool-1",
			userId: "op-1",
		});
		const headers = buildInternalAuthHeaders("POST", "/v1/query", body, { scope: "telegram" });
		const res = await fetch(`${baseUrl}/v1/query`, {
			method: "POST",
			headers: { "Content-Type": "application/json", ...headers },
			body,
		});
		await res.text();

		expect(relayGetProvidersImpl.mock.calls.length).toBeGreaterThan(0);
		expect(writeProviderSchemaFromRelayImpl.mock.calls.length).toBeGreaterThan(0);
		const [, options] = executePooledQueryImpl.mock.calls[0] as [
			string,
			{ systemPromptAppend?: string },
		];
		expect(options.systemPromptAppend).toContain("<available-providers>");
		expect(options.systemPromptAppend).toContain("summary:israel-services");
	});

	it("skips schema rewrite when the relay epoch is unchanged", async () => {
		const providers = [
			{
				id: "israel-services",
				baseUrl: "http://israel-services.local:3001",
				services: ["gov-api"],
				description: "Citizen services",
			},
		];
		relayGetProvidersImpl
			.mockResolvedValueOnce({
				ok: true,
				providers,
				schemaMarkdown: "# schema",
				providersEpoch: "epoch-stable",
			})
			.mockResolvedValueOnce({
				ok: true,
				providers,
				schemaMarkdown: "# changed-but-same-epoch",
				providersEpoch: "epoch-stable",
			});
		mockDoneResponse();
		mockDoneResponse();

		const body = JSON.stringify({
			prompt: "hi",
			tier: "WRITE_LOCAL",
			poolKey: "pool-1",
			userId: "op-1",
		});

		const first = await fetch(`${baseUrl}/v1/query`, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				...buildInternalAuthHeaders("POST", "/v1/query", body, { scope: "telegram" }),
			},
			body,
		});
		expect(first.status).toBe(200);
		await first.text();

		const second = await fetch(`${baseUrl}/v1/query`, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				...buildInternalAuthHeaders("POST", "/v1/query", body, { scope: "telegram" }),
			},
			body,
		});
		expect(second.status).toBe(200);
		await second.text();

		expect(relayGetProvidersImpl).toHaveBeenCalledTimes(2);
		expect(writeProviderSchemaFromRelayImpl).toHaveBeenCalledTimes(1);
	});

	it("coalesces concurrent telegram queries behind a single relay sync", async () => {
		let resolveProviders: ((value: {
			ok: boolean;
			providers: Array<{
				id: string;
				baseUrl: string;
				services: string[];
				description: string;
			}>;
			schemaMarkdown: string;
			providersEpoch: string;
		}) => void) | null = null;
		relayGetProvidersImpl.mockImplementationOnce(
			() =>
				new Promise((resolve) => {
					resolveProviders = resolve;
				}),
		);
		mockDoneResponse();
		mockDoneResponse();

		const body = JSON.stringify({
			prompt: "hi",
			tier: "WRITE_LOCAL",
			poolKey: "pool-1",
			userId: "op-1",
		});

		const first = fetch(`${baseUrl}/v1/query`, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				...buildInternalAuthHeaders("POST", "/v1/query", body, { scope: "telegram" }),
			},
			body,
		}).then(async (response) => {
			expect(response.status).toBe(200);
			return response.text();
		});
		const second = fetch(`${baseUrl}/v1/query`, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				...buildInternalAuthHeaders("POST", "/v1/query", body, { scope: "telegram" }),
			},
			body,
		}).then(async (response) => {
			expect(response.status).toBe(200);
			return response.text();
		});

		await new Promise((resolve) => setTimeout(resolve, 10));
		expect(relayGetProvidersImpl).toHaveBeenCalledTimes(1);

		resolveProviders?.({
			ok: true,
			providers: [
				{
					id: "israel-services",
					baseUrl: "http://israel-services.local:3001",
					services: ["gov-api"],
					description: "Citizen services",
				},
			],
			schemaMarkdown: "# schema",
			providersEpoch: "epoch-single-flight",
		});
		await Promise.all([first, second]);

		expect(writeProviderSchemaFromRelayImpl).toHaveBeenCalledTimes(1);
	});

	it("omits provider summary when the relay still lacks schema markdown", async () => {
		relayGetProvidersImpl.mockResolvedValueOnce({
			ok: true,
			providers: [
				{
					id: "israel-services",
					baseUrl: "http://israel-services.local:3001",
					services: ["gov-api"],
					description: "Citizen services",
				},
			],
			providersEpoch: "epoch-2",
		});
		mockDoneResponse();

		const body = JSON.stringify({
			prompt: "hi",
			tier: "WRITE_LOCAL",
			poolKey: "pool-1",
			userId: "op-1",
		});
		const headers = buildInternalAuthHeaders("POST", "/v1/query", body, { scope: "telegram" });
		const res = await fetch(`${baseUrl}/v1/query`, {
			method: "POST",
			headers: { "Content-Type": "application/json", ...headers },
			body,
		});
		await res.text();

		expect(writeProviderSchemaFromRelayImpl).not.toHaveBeenCalled();
		expect(refreshExternalProviderSkillImpl).not.toHaveBeenCalled();
		const [, options] = executePooledQueryImpl.mock.calls[0] as [
			string,
			{ systemPromptAppend?: string },
		];
		expect(options.systemPromptAppend ?? "").not.toContain("<available-providers>");
	});

	it("clears stale provider summary when the relay reports no configured providers", async () => {
		providerSummaryState.summary = "summary:stale-provider";
		relayGetProvidersImpl.mockResolvedValueOnce({
			ok: true,
			providers: [],
			schemaMarkdown: null,
			providersEpoch: "epoch-empty",
		});
		mockDoneResponse();

		const body = JSON.stringify({
			prompt: "hi",
			tier: "WRITE_LOCAL",
			poolKey: "pool-1",
			userId: "op-1",
		});
		const headers = buildInternalAuthHeaders("POST", "/v1/query", body, { scope: "telegram" });
		const res = await fetch(`${baseUrl}/v1/query`, {
			method: "POST",
			headers: { "Content-Type": "application/json", ...headers },
			body,
		});
		await res.text();

		expect(clearProviderSkillStateImpl).toHaveBeenCalledTimes(1);
		const [, options] = executePooledQueryImpl.mock.calls[0] as [
			string,
			{ systemPromptAppend?: string },
		];
		expect(options.systemPromptAppend ?? "").not.toContain("<available-providers>");
	});
});
