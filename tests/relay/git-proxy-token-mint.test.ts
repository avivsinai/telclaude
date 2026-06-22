import { once } from "node:events";
import http from "node:http";
import type { AddressInfo } from "node:net";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { buildInternalAuthHeaders, generateKeyPair } from "../../src/internal-auth.js";
import { startCapabilityServer } from "../../src/relay/capabilities.js";
import { verifyGitProxyToken } from "../../src/relay/git-proxy-auth.js";

const ENV_KEYS = [
	"TELEGRAM_RPC_AGENT_PRIVATE_KEY",
	"TELEGRAM_RPC_AGENT_PUBLIC_KEY",
	"OPERATOR_RPC_AGENT_PRIVATE_KEY",
	"OPERATOR_RPC_AGENT_PUBLIC_KEY",
	"TELCLAUDE_GIT_PROXY_SECRET",
	"TELCLAUDE_GIT_PROXY_ALLOWED_REPOS",
	"TELCLAUDE_GIT_PROXY_PERMISSIONS",
	"TELCLAUDE_GIT_PROXY_ALLOWED_PUSH_REFS",
	"TELCLAUDE_GIT_PROXY_DENIED_PUSH_REFS",
] as const;

describe("git proxy token mint capability", () => {
	let server: http.Server | null = null;
	let baseUrl = "";
	let originalEnv: Record<(typeof ENV_KEYS)[number], string | undefined>;

	beforeEach(async () => {
		originalEnv = Object.fromEntries(ENV_KEYS.map((key) => [key, process.env[key]])) as Record<
			(typeof ENV_KEYS)[number],
			string | undefined
		>;

		const telegramKeys = generateKeyPair();
		process.env.TELEGRAM_RPC_AGENT_PRIVATE_KEY = telegramKeys.privateKey;
		process.env.TELEGRAM_RPC_AGENT_PUBLIC_KEY = telegramKeys.publicKey;
		process.env.TELCLAUDE_GIT_PROXY_SECRET = "git-proxy-route-secret";
		process.env.TELCLAUDE_GIT_PROXY_ALLOWED_REPOS = "owner/repo";
		process.env.TELCLAUDE_GIT_PROXY_PERMISSIONS = "fetch,push";
		process.env.TELCLAUDE_GIT_PROXY_ALLOWED_PUSH_REFS = "refs/heads/codex/*";
		process.env.TELCLAUDE_GIT_PROXY_DENIED_PUSH_REFS = "refs/heads/main,refs/heads/master";

		server = startCapabilityServer({ port: 0, host: "127.0.0.1" });
		await once(server, "listening");
		const address = server.address() as AddressInfo;
		baseUrl = `http://127.0.0.1:${address.port}`;
	});

	afterEach(async () => {
		if (server) {
			await new Promise<void>((resolve, reject) => {
				server?.close((error) => (error ? reject(error) : resolve()));
			});
			server = null;
		}
		for (const key of ENV_KEYS) {
			const value = originalEnv[key];
			if (value === undefined) delete process.env[key];
			else process.env[key] = value;
		}
	});

	it("mints a fetch-only scoped git token for authenticated telegram runtimes", async () => {
		const path = "/v1/git-proxy-token";
		const body = JSON.stringify({ runId: "job-1", ttlMs: 120_000 });
		const response = await fetch(`${baseUrl}${path}`, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				...buildInternalAuthHeaders("POST", path, body, { scope: "telegram" }),
			},
			body,
		});

		expect(response.status).toBe(200);
		const payload = (await response.json()) as {
			token: string;
			expiresInMs: number;
			policy: {
				repositories: string[];
				permissions: string[];
				allowedRefs: string[];
				deniedRefs: string[];
			};
		};

		expect(payload.expiresInMs).toBe(120_000);
			expect(payload.policy).toEqual({
				repositories: ["owner/repo"],
				permissions: ["fetch"],
				allowedRefs: ["refs/heads/codex/*"],
				deniedRefs: ["refs/heads/main", "refs/heads/master"],
			});

		const verified = verifyGitProxyToken(payload.token, {
			secret: "git-proxy-route-secret",
			peerAddress: "127.0.0.1",
		});
		expect(verified.ok).toBe(true);
		if (verified.ok) {
				expect(verified.sessionId).toBe("job-1");
				expect(verified.repositories).toEqual(["owner/repo"]);
				expect(verified.permissions).toEqual(["fetch"]);
			}
		});

	it("rejects runtime git token minting when policy does not allow fetch", async () => {
		process.env.TELCLAUDE_GIT_PROXY_PERMISSIONS = "push";
		const path = "/v1/git-proxy-token";
		const body = JSON.stringify({ runId: "job-1" });

		const response = await fetch(`${baseUrl}${path}`, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				...buildInternalAuthHeaders("POST", path, body, { scope: "telegram" }),
			},
			body,
		});

		expect(response.status).toBe(500);
		await expect(response.json()).resolves.toEqual({
			error: "Git proxy token policy is not usable for runtime fetch.",
		});
	});

	it("rejects invalid run ids before minting unusable tokens", async () => {
		const path = "/v1/git-proxy-token";
		const body = JSON.stringify({ runId: "x".repeat(161) });
		const response = await fetch(`${baseUrl}${path}`, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				...buildInternalAuthHeaders("POST", path, body, { scope: "telegram" }),
			},
			body,
		});

		expect(response.status).toBe(400);
		await expect(response.json()).resolves.toEqual({ error: "Invalid runId." });
	});

	it("keeps the git token mint endpoint unavailable to non-telegram scopes", async () => {
		const operatorKeys = generateKeyPair();
		process.env.OPERATOR_RPC_AGENT_PRIVATE_KEY = operatorKeys.privateKey;
		process.env.OPERATOR_RPC_AGENT_PUBLIC_KEY = operatorKeys.publicKey;
		const path = "/v1/git-proxy-token";
		const body = JSON.stringify({ runId: "job-1" });

		const response = await fetch(`${baseUrl}${path}`, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				...buildInternalAuthHeaders("POST", path, body, { scope: "operator" }),
			},
			body,
		});

		expect(response.status).toBe(403);
	});
});
