import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import { once } from "node:events";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const isVaultAvailableMock = vi.hoisted(() => vi.fn());
const vaultClientMock = vi.hoisted(() => ({
	getToken: vi.fn(),
	getSecret: vi.fn(),
}));
const loggerMock = vi.hoisted(() => ({
	info: vi.fn(),
	warn: vi.fn(),
	error: vi.fn(),
	debug: vi.fn(),
}));

vi.mock("../../src/logging.js", () => ({
	getChildLogger: () => loggerMock,
}));

vi.mock("../../src/vault-daemon/client.js", () => ({
	getVaultClient: () => vaultClientMock,
	isVaultAvailable: isVaultAvailableMock,
}));

import { MODEL_RELAY_OBSERVED_PEER_HEADER } from "../../src/hermes/model-relay.js";
import { generateKeyPair } from "../../src/internal-auth.js";
import { startCapabilityServer } from "../../src/relay/capabilities.js";
import {
	isOpenAiCodexProxyAllowedClientAddress,
	mintOpenAiCodexPeerBoundProxyToken,
	resetOpenAiCodexProxyState,
	verifyOpenAiCodexPeerBoundProxyToken,
} from "../../src/relay/openai-codex-proxy.js";
import {
	type OpenAiCodexRelayProof,
	openAiCodexRelayProofSignatureFailure,
	openAiCodexRelayProofTokenSha256,
} from "../../src/relay/openai-codex-relay-proof.js";

const ORIGINAL_ENV = {
	OPERATOR_RPC_RELAY_PRIVATE_KEY: process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY,
	OPERATOR_RPC_RELAY_PUBLIC_KEY: process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY,
	TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN: process.env.TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN,
	TELCLAUDE_OPENAI_CODEX_OAUTH_TOKEN: process.env.TELCLAUDE_OPENAI_CODEX_OAUTH_TOKEN,
};

describe("OpenAI Codex relay proxy", () => {
	let server: ReturnType<typeof startCapabilityServer> | null = null;
	let baseUrl = "";

	beforeEach(async () => {
		const relayKeys = generateKeyPair();
		process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = relayKeys.privateKey;
		process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = relayKeys.publicKey;
		process.env.TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN = "relay-proxy-token";
		process.env.TELCLAUDE_OPENAI_CODEX_OAUTH_TOKEN = fakeCodexJwt("acct_123");
		isVaultAvailableMock.mockReset().mockResolvedValue(false);
		vaultClientMock.getToken.mockReset();
		vaultClientMock.getSecret.mockReset();
		loggerMock.info.mockReset();
		loggerMock.warn.mockReset();
		loggerMock.error.mockReset();
		loggerMock.debug.mockReset();
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
		restoreEnv("OPERATOR_RPC_RELAY_PRIVATE_KEY");
		restoreEnv("OPERATOR_RPC_RELAY_PUBLIC_KEY");
		restoreEnv("TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN");
		restoreEnv("TELCLAUDE_OPENAI_CODEX_OAUTH_TOKEN");
		resetOpenAiCodexProxyState();
		vi.unstubAllGlobals();
	});

	it("proxies Codex subscription requests with relay-owned OAuth and peer evidence", async () => {
		const fetchSpy = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			expect(String(input)).toBe(
				"https://chatgpt.com/backend-api/codex/models?client_version=1.0.0",
			);
			const headers = new Headers(init?.headers);
			expect(headers.get("authorization")).toBe(
				`Bearer ${process.env.TELCLAUDE_OPENAI_CODEX_OAUTH_TOKEN}`,
			);
			expect(headers.get("cookie")).toBeNull();
			expect(headers.get("x-api-key")).toBeNull();
			expect(headers.get("openai-organization")).toBeNull();
			expect(headers.get("openai-project")).toBeNull();
			expect(headers.get("origin")).toBeNull();
			expect(headers.get("referer")).toBeNull();
			expect(headers.get("originator")).toBe("codex_cli_rs");
			expect(headers.get("user-agent")).toContain("codex_cli_rs");
			expect(headers.get("chatgpt-account-id")).toBe("acct_123");
			return new Response(JSON.stringify({ data: [{ id: "gpt-5.3-codex" }] }), {
				status: 200,
				headers: { "Content-Type": "application/json", "Set-Cookie": "raw=secret" },
			});
		});
		vi.stubGlobal("fetch", fetchSpy);

		const result = await makeRequest(
			baseUrl,
			"/v1/openai-codex-proxy/models?client_version=1.0.0",
			undefined,
			"GET",
			relayAuthHeaders({
				Cookie: "raw=inbound",
				"ChatGPT-Account-ID": "attacker-account",
				"OpenAI-Organization": "attacker-org",
				"OpenAI-Project": "attacker-project",
				Origin: "https://evil.example",
				Referer: "https://evil.example/session",
			}),
		);

		expect(result.status).toBe(200);
		expect(result.headers[MODEL_RELAY_OBSERVED_PEER_HEADER]).toBe("127.0.0.1");
		expect(result.headers["set-cookie"]).toBeUndefined();
		expect(result.body).toContain("gpt-5.3-codex");
		expect(fetchSpy).toHaveBeenCalledTimes(1);
		expect(
			loggerMock.info.mock.calls.some(
				([meta, message]) =>
					message === "proxying to OpenAI Codex subscription backend" &&
					(meta as { authSource?: string }).authSource === "relay-codex-env-static-fallback",
			),
		).toBe(true);
		expect(
			loggerMock.warn.mock.calls.some(
				([meta, message]) =>
					String(message).includes("using static Codex access-token fallback") &&
					(meta as { source?: string }).source === "env-static-fallback",
			),
		).toBe(true);
	});

	it("prefers refreshable vault OAuth over static Codex fallback", async () => {
		isVaultAvailableMock.mockResolvedValue(true);
		vaultClientMock.getToken.mockResolvedValue({
			ok: true,
			token: fakeCodexJwt("acct_123"),
			expiresAt: Date.now() + 3600_000,
		});
		const fetchSpy = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
			const headers = new Headers(init?.headers);
			expect(headers.get("authorization")).toMatch(/^Bearer /);
			return new Response(JSON.stringify({ data: [{ id: "gpt-5.3-codex" }] }), {
				status: 200,
				headers: { "Content-Type": "application/json" },
			});
		});
		vi.stubGlobal("fetch", fetchSpy);

		const result = await makeRequest(
			baseUrl,
			"/v1/openai-codex-proxy/models?client_version=1.0.0",
			undefined,
			"GET",
			relayAuthHeaders(),
		);

		expect(result.status).toBe(200);
		expect(vaultClientMock.getSecret).not.toHaveBeenCalled();
		expect(
			loggerMock.info.mock.calls.some(
				([meta, message]) =>
					message === "proxying to OpenAI Codex subscription backend" &&
					(meta as { authSource?: string }).authSource === "relay-codex-vault-oauth2-refreshable",
			),
		).toBe(true);
		expect(
			loggerMock.warn.mock.calls.some(([_meta, message]) =>
				String(message).includes("using static Codex access-token fallback"),
			),
		).toBe(false);
	});

	it("records a non-secret relay proof for the latest Codex response request from the peer", async () => {
		const expectedProofToken = "HERMES_OK_RELAY_PROOF_BINDING";
		const requestBody = JSON.stringify({
			model: "gpt-5.5",
			input: `private prompt text; reply with ${expectedProofToken}`,
		});
		const fetchSpy = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			expect(String(input)).toBe("https://chatgpt.com/backend-api/codex/responses");
			expect(Buffer.isBuffer(init?.body)).toBe(true);
			expect((init?.body as Buffer).toString("utf8")).toBe(requestBody);
			return new Response(JSON.stringify({ output_text: "ok" }), {
				status: 200,
				headers: { "Content-Type": "application/json" },
			});
		});
		vi.stubGlobal("fetch", fetchSpy);

		const response = await makeRequest(
			baseUrl,
			"/v1/openai-codex-proxy/responses",
			requestBody,
			"POST",
			relayAuthHeaders(),
		);
		const proof = await makeRequest(
			baseUrl,
			"/v1/openai-codex-proxy/_telclaude/relay-proof/latest",
			undefined,
			"GET",
			relayAuthHeaders(),
		);

		expect(response.status).toBe(200);
		expect(proof.status).toBe(200);
		const parsed = JSON.parse(proof.body) as Record<string, unknown>;
		expect(parsed).toMatchObject({
			schemaVersion: "telclaude.hermes.cli-headless-relay-proof.v1",
			source: "telclaude-openai-codex-proxy",
			method: "POST",
			path: "/backend-api/codex/responses",
			observedPeerAddress: "127.0.0.1",
			upstreamStatus: 200,
			model: "gpt-5.5",
			requestBodySha256: `sha256:${crypto.createHash("sha256").update(requestBody).digest("hex")}`,
			proofTokenSha256: openAiCodexRelayProofTokenSha256(expectedProofToken),
		});
		expect(parsed.requestId).toEqual(expect.any(String));
		expect(parsed.observedAt).toEqual(expect.any(String));
		expect(parsed.signature).toMatchObject({
			version: "v1",
			scope: "operator",
			method: "POST",
			path: "/backend-api/codex/responses",
			signature: expect.any(String),
		});
		expect(openAiCodexRelayProofSignatureFailure(parsed as OpenAiCodexRelayProof)).toBeNull();
		expect(proof.body).not.toContain("private prompt text");
		expect(fetchSpy).toHaveBeenCalledTimes(1);
	});

	it("does not serve a stale relay proof when proof signing fails", async () => {
		const requestBody = JSON.stringify({ model: "gpt-5.5", input: "private prompt text" });
		const fetchSpy = vi.fn(async () => {
			return new Response(JSON.stringify({ output_text: "ok" }), {
				status: 200,
				headers: { "Content-Type": "application/json" },
			});
		});
		vi.stubGlobal("fetch", fetchSpy);

		const first = await makeRequest(
			baseUrl,
			"/v1/openai-codex-proxy/responses",
			requestBody,
			"POST",
			relayAuthHeaders(),
		);
		const firstProof = await makeRequest(
			baseUrl,
			"/v1/openai-codex-proxy/_telclaude/relay-proof/latest",
			undefined,
			"GET",
			relayAuthHeaders(),
		);
		delete process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
		const second = await makeRequest(
			baseUrl,
			"/v1/openai-codex-proxy/responses",
			requestBody,
			"POST",
			relayAuthHeaders(),
		);
		const staleProof = await makeRequest(
			baseUrl,
			"/v1/openai-codex-proxy/_telclaude/relay-proof/latest",
			undefined,
			"GET",
			relayAuthHeaders(),
		);

		expect(first.status).toBe(200);
		expect(firstProof.status).toBe(200);
		expect(second.status).toBe(200);
		expect(staleProof.status).toBe(404);
		expect(fetchSpy).toHaveBeenCalledTimes(2);
	});

	it("rejects invalid relay tokens before reaching ChatGPT", async () => {
		const fetchSpy = vi.fn();
		vi.stubGlobal("fetch", fetchSpy);

		const result = await makeRequest(baseUrl, "/v1/openai-codex-proxy/responses", "{}", "POST", {
			Authorization: "Bearer wrong-token",
		});

		expect(result.status).toBe(401);
		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it("rejects the reusable static proxy token before reaching ChatGPT", async () => {
		const fetchSpy = vi.fn();
		vi.stubGlobal("fetch", fetchSpy);

		const result = await makeRequest(baseUrl, "/v1/openai-codex-proxy/responses", "{}", "POST", {
			Authorization: "Bearer relay-proxy-token",
		});

		expect(result.status).toBe(401);
		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it("rejects expired peer-bound relay tokens before reaching ChatGPT", async () => {
		const fetchSpy = vi.fn();
		vi.stubGlobal("fetch", fetchSpy);
		const secret = process.env.TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN;
		if (!secret) throw new Error("missing test relay proxy token secret");
		const expiredToken = mintOpenAiCodexPeerBoundProxyToken({
			secret,
			peerAddress: "127.0.0.1",
			runId: "expired-test-run",
			now: new Date(Date.now() - 120_000),
			ttlMs: 1_000,
		});

		const result = await makeRequest(baseUrl, "/v1/openai-codex-proxy/responses", "{}", "POST", {
			Authorization: `Bearer ${expiredToken}`,
		});

		expect(result.status).toBe(401);
		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it("rejects peer-bound relay tokens for the wrong peer before reaching ChatGPT", async () => {
		const fetchSpy = vi.fn();
		vi.stubGlobal("fetch", fetchSpy);
		const token = peerBoundToken({ peerAddress: "10.10.0.7", runId: "wrong-peer-test-run" });

		const result = await makeRequest(baseUrl, "/v1/openai-codex-proxy/responses", "{}", "POST", {
			Authorization: `Bearer ${token}`,
		});

		expect(result.status).toBe(401);
		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it("rejects future-issued peer-bound relay tokens before reaching ChatGPT", async () => {
		const fetchSpy = vi.fn();
		vi.stubGlobal("fetch", fetchSpy);
		const token = peerBoundToken({
			runId: "future-issued-test-run",
			now: new Date(Date.now() + 10_000),
		});

		const result = await makeRequest(baseUrl, "/v1/openai-codex-proxy/responses", "{}", "POST", {
			Authorization: `Bearer ${token}`,
		});

		expect(result.status).toBe(401);
		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it("rejects peer-bound relay tokens with a bad signature before reaching ChatGPT", async () => {
		const fetchSpy = vi.fn();
		vi.stubGlobal("fetch", fetchSpy);
		const token = peerBoundToken({ runId: "bad-signature-test-run" });
		const badSignatureToken = `${token.slice(0, -1)}${token.endsWith("A") ? "B" : "A"}`;

		const result = await makeRequest(baseUrl, "/v1/openai-codex-proxy/responses", "{}", "POST", {
			Authorization: `Bearer ${badSignatureToken}`,
		});

		expect(result.status).toBe(401);
		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it("rejects malformed peer-bound relay tokens before reaching ChatGPT", async () => {
		const fetchSpy = vi.fn();
		vi.stubGlobal("fetch", fetchSpy);

		for (const token of ["", "tc-openai-codex-relay-v1.only-two-parts", "not-peer-bound"]) {
			const result = await makeRequest(baseUrl, "/v1/openai-codex-proxy/responses", "{}", "POST", {
				Authorization: `Bearer ${token}`,
			});
			expect(result.status).toBe(401);
		}
		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it("normalizes IPv4-mapped peer addresses for peer-bound relay tokens", () => {
		const tokenFromMappedPeer = peerBoundToken({
			peerAddress: "::ffff:127.0.0.1",
			runId: "mapped-mint-test-run",
		});
		const tokenFromIpv4Peer = peerBoundToken({
			peerAddress: "127.0.0.1",
			runId: "mapped-verify-test-run",
		});
		const secret = process.env.TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN;
		if (!secret) throw new Error("missing test relay proxy token secret");

		expect(
			verifyOpenAiCodexPeerBoundProxyToken(tokenFromMappedPeer, {
				secret,
				peerAddress: "127.0.0.1",
			}),
		).toMatchObject({ ok: true, runId: "mapped-mint-test-run", tokenScope: "run" });
		expect(
			verifyOpenAiCodexPeerBoundProxyToken(tokenFromIpv4Peer, {
				secret,
				peerAddress: "::ffff:127.0.0.1",
			}),
		).toMatchObject({ ok: true, runId: "mapped-verify-test-run", tokenScope: "run" });
	});

	it("accepts server-scoped peer-bound relay tokens without wall-clock expiry", () => {
		const secret = process.env.TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN;
		if (!secret) throw new Error("missing test relay proxy token secret");
		const token = mintOpenAiCodexPeerBoundProxyToken({
			secret,
			peerAddress: "127.0.0.1",
			runId: "gateway-run-container",
			tokenScope: "server",
			now: new Date("2026-06-03T00:00:00.000Z"),
		});

		expect(
			verifyOpenAiCodexPeerBoundProxyToken(token, {
				secret,
				peerAddress: "127.0.0.1",
				now: new Date("2126-06-03T00:00:00.000Z"),
			}),
		).toMatchObject({ ok: true, runId: "gateway-run-container", tokenScope: "server" });
	});

	it("accepts peer-bound relay tokens minted by the contained entrypoint shell function", () => {
		const secret = process.env.TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN;
		if (!secret) throw new Error("missing test relay proxy token secret");

		for (const tokenScope of ["run", "server"] as const) {
			const token = mintEntrypointPeerBoundToken({
				secret,
				peerAddress: "172.30.92.11",
				tokenScope,
			});
			const payload = decodePeerBoundTokenPayload(token);

			expect(payload).toMatchObject({
				version: 1,
				tokenScope,
				peerAddress: "172.30.92.11",
			});
			expect(payload.runId).toEqual(expect.stringMatching(/^hermes-contained-/));
			expect(payload.nonce).toEqual(expect.any(String));
			if (tokenScope === "server") {
				expect(payload.expiresAt).toBeNull();
			} else {
				expect(typeof payload.expiresAt).toBe("number");
				expect(payload.expiresAt - payload.issuedAt).toBe(300_000);
			}
			expect(
				verifyOpenAiCodexPeerBoundProxyToken(token, {
					secret,
					peerAddress: "::ffff:172.30.92.11",
					now: new Date(payload.issuedAt),
				}),
			).toMatchObject({
				ok: true,
				runId: payload.runId,
				tokenScope,
			});
		}
	});

	it("rejects run-scoped peer-bound relay tokens without finite expiry", () => {
		const secret = process.env.TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN;
		if (!secret) throw new Error("missing test relay proxy token secret");

		expect(() =>
			mintOpenAiCodexPeerBoundProxyToken({
				secret,
				peerAddress: "127.0.0.1",
				runId: "run-without-expiry",
				tokenScope: "run",
				ttlMs: null,
			}),
		).toThrow("run-scoped OpenAI Codex relay tokens require a finite TTL");

		const runTokenWithoutExpiry = signPeerBoundTokenPayload(
			{
				version: 1,
				tokenScope: "run",
				runId: "crafted-run-without-expiry",
				peerAddress: "127.0.0.1",
				issuedAt: Date.now(),
				expiresAt: null,
				nonce: "nonce",
			},
			secret,
		);

		expect(
			verifyOpenAiCodexPeerBoundProxyToken(runTokenWithoutExpiry, {
				secret,
				peerAddress: "127.0.0.1",
			}),
		).toEqual({ ok: false, reason: "payload is invalid" });
	});

	it("rejects multi-valued relay tokens without throwing", async () => {
		const fetchSpy = vi.fn();
		vi.stubGlobal("fetch", fetchSpy);

		const wrongFirst = await makeRequest(
			baseUrl,
			"/v1/openai-codex-proxy/responses",
			"{}",
			"POST",
			{ "x-api-key": ["wrong-token", "relay-proxy-token"] },
		);
		const rightFirst = await makeRequest(
			baseUrl,
			"/v1/openai-codex-proxy/responses",
			"{}",
			"POST",
			{ "x-api-key": ["relay-proxy-token", "wrong-token"] },
		);

		expect(wrongFirst.status).toBe(401);
		expect(rightFirst.status).toBe(401);
		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it("rejects absolute and traversal proxy paths", async () => {
		const fetchSpy = vi.fn();
		vi.stubGlobal("fetch", fetchSpy);

		const absolute = await makeRequest(
			baseUrl,
			"/v1/openai-codex-proxy/https://evil.example/",
			"{}",
			"POST",
			relayAuthHeaders(),
		);
		const traversal = await makeRequest(
			baseUrl,
			"/v1/openai-codex-proxy/v1/../models",
			"{}",
			"POST",
			relayAuthHeaders(),
		);
		const doubleEncodedTraversal = await makeRequest(
			baseUrl,
			"/v1/openai-codex-proxy/v1/%252e%252e/models",
			"{}",
			"POST",
			relayAuthHeaders(),
		);

		expect(absolute.status).toBe(400);
		expect(traversal.status).toBe(400);
		expect(doubleEncodedTraversal.status).toBe(400);
		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it("rejects methods and paths outside the Codex inference allowlist", async () => {
		const fetchSpy = vi.fn();
		vi.stubGlobal("fetch", fetchSpy);

		const deleteModels = await makeRequest(
			baseUrl,
			"/v1/openai-codex-proxy/models",
			undefined,
			"DELETE",
			relayAuthHeaders(),
		);
		const getResponses = await makeRequest(
			baseUrl,
			"/v1/openai-codex-proxy/responses",
			undefined,
			"GET",
			relayAuthHeaders(),
		);
		const postSessions = await makeRequest(
			baseUrl,
			"/v1/openai-codex-proxy/sessions",
			"{}",
			"POST",
			relayAuthHeaders(),
		);

		expect(deleteModels.status).toBe(403);
		expect(getResponses.status).toBe(403);
		expect(postSessions.status).toBe(403);
		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it("rejects raw provider credentials from env fallback", async () => {
		process.env.TELCLAUDE_OPENAI_CODEX_OAUTH_TOKEN = "sk-proj-rawProviderKey12345678";
		const fetchSpy = vi.fn();
		vi.stubGlobal("fetch", fetchSpy);

		const result = await makeRequest(baseUrl, "/v1/openai-codex-proxy/models", undefined, "GET", {
			...relayAuthHeaders(),
		});

		expect(result.status).toBe(500);
		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it("does not accept api_key-shaped vault secrets as Codex subscription credentials", async () => {
		delete process.env.TELCLAUDE_OPENAI_CODEX_OAUTH_TOKEN;
		isVaultAvailableMock.mockResolvedValue(true);
		vaultClientMock.getToken.mockResolvedValue({ ok: false });
		vaultClientMock.getSecret.mockResolvedValue({
			ok: true,
			type: "get-secret",
			value: JSON.stringify({ api_key: "sk-proj-rawProviderKey12345678" }),
		});
		const fetchSpy = vi.fn();
		vi.stubGlobal("fetch", fetchSpy);

		const result = await makeRequest(baseUrl, "/v1/openai-codex-proxy/models", undefined, "GET", {
			...relayAuthHeaders(),
		});

		expect(result.status).toBe(500);
		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it("allows only loopback, RFC1918, and IPv6 ULA clients", () => {
		expect(isOpenAiCodexProxyAllowedClientAddress("127.0.0.1")).toBe(true);
		expect(isOpenAiCodexProxyAllowedClientAddress("::1")).toBe(true);
		expect(isOpenAiCodexProxyAllowedClientAddress("10.10.0.5")).toBe(true);
		expect(isOpenAiCodexProxyAllowedClientAddress("10.10.0.6")).toBe(true);
		expect(isOpenAiCodexProxyAllowedClientAddress("192.168.1.22")).toBe(true);
		expect(isOpenAiCodexProxyAllowedClientAddress("::ffff:10.10.0.6")).toBe(true);
		expect(isOpenAiCodexProxyAllowedClientAddress("fd00::10")).toBe(true);

		expect(isOpenAiCodexProxyAllowedClientAddress("100.64.1.5")).toBe(false);
		expect(isOpenAiCodexProxyAllowedClientAddress("169.254.1.5")).toBe(false);
		expect(isOpenAiCodexProxyAllowedClientAddress("fe80::1")).toBe(false);
		expect(isOpenAiCodexProxyAllowedClientAddress("8.8.8.8")).toBe(false);
	});
});

function makeRequest(
	baseUrl: string,
	requestPath: string,
	body?: string,
	method: string = "POST",
	headers: Record<string, string | string[]> = {},
): Promise<{ status: number; body: string; headers: Record<string, string> }> {
	return new Promise((resolve, reject) => {
		const url = new URL(baseUrl);
		const req = http.request(
			{
				hostname: url.hostname,
				port: Number(url.port),
				path: requestPath,
				method,
				headers: {
					"Content-Type": "application/json",
					"Content-Length": body ? Buffer.byteLength(body) : 0,
					...headers,
				},
			},
			(res) => {
				let data = "";
				res.on("data", (chunk) => {
					data += chunk.toString();
				});
				res.on("end", () => {
					resolve({
						status: res.statusCode ?? 0,
						body: data,
						headers: Object.fromEntries(
							Object.entries(res.headers).map(([key, value]) => [
								key,
								Array.isArray(value) ? value.join(",") : String(value ?? ""),
							]),
						),
					});
				});
			},
		);
		req.on("error", reject);
		if (body) req.write(body);
		req.end();
	});
}

function relayAuthHeaders(
	extra: Record<string, string | string[]> = {},
): Record<string, string | string[]> {
	return {
		Authorization: `Bearer ${peerBoundToken({ runId: "test-run" })}`,
		...extra,
	};
}

function peerBoundToken(input: { peerAddress?: string; runId: string; now?: Date }): string {
	const secret = process.env.TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN;
	if (!secret) throw new Error("missing test relay proxy token secret");
	return mintOpenAiCodexPeerBoundProxyToken({
		secret,
		peerAddress: input.peerAddress ?? "127.0.0.1",
		runId: input.runId,
		now: input.now,
	});
}

function mintEntrypointPeerBoundToken(input: {
	secret: string;
	peerAddress: string;
	tokenScope: "run" | "server";
}): string {
	const tempDir = mkdtempSync(path.join(tmpdir(), "tc-entrypoint-token-parity-"));
	try {
		const fakeHostname = path.join(tempDir, "hostname");
		writeFileSync(
			fakeHostname,
			[
				"#!/bin/sh",
				'if [ "$1" = "-i" ]; then',
				'  printf "%s\\n" "$ENTRYPOINT_TEST_PEER_ADDRESS"',
				"  exit 0",
				"fi",
				'exec /bin/hostname "$@"',
				"",
			].join("\n"),
		);
		chmodSync(fakeHostname, 0o755);

		return execFileSync("/bin/sh", ["-s", input.secret, input.tokenScope], {
			input: [
				"set -eu",
				entrypointMintFunction(),
				'mint_peer_bound_codex_relay_token "$1" "$2"',
				"",
			].join("\n"),
			encoding: "utf8",
			env: {
				...process.env,
				ENTRYPOINT_TEST_PEER_ADDRESS: input.peerAddress,
				PATH: `${tempDir}:${process.env.PATH ?? ""}`,
			},
		}).trim();
	} finally {
		rmSync(tempDir, { recursive: true, force: true });
	}
}

function entrypointMintFunction(): string {
	const entrypoint = readFileSync("docker/hermes-contained-entrypoint.sh", "utf8");
	const match = entrypoint.match(/mint_peer_bound_codex_relay_token\(\) \{\n[\s\S]*?\nNODE\n\}/);
	const mintFunction = match?.[0];
	if (!mintFunction) throw new Error("could not extract contained entrypoint token mint function");
	return mintFunction;
}

function decodePeerBoundTokenPayload(token: string): {
	version: 1;
	tokenScope: "run" | "server";
	runId: string;
	peerAddress: string;
	issuedAt: number;
	expiresAt: number | null;
	nonce: string;
} {
	const [, encodedPayload] = token.split(".");
	if (!encodedPayload) throw new Error("missing token payload");
	return JSON.parse(Buffer.from(encodedPayload, "base64url").toString("utf8"));
}

function signPeerBoundTokenPayload(payload: unknown, secret: string): string {
	const encodedPayload = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
	const signature = crypto.createHmac("sha256", secret).update(encodedPayload).digest("base64url");
	return `tc-openai-codex-relay-v1.${encodedPayload}.${signature}`;
}

function fakeCodexJwt(accountId: string): string {
	const payload = {
		"https://api.openai.com/auth": {
			chatgpt_account_id: accountId,
		},
	};
	return `header.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.sig`;
}

function restoreEnv(key: keyof typeof ORIGINAL_ENV): void {
	const value = ORIGINAL_ENV[key];
	if (value === undefined) {
		delete process.env[key];
	} else {
		process.env[key] = value;
	}
}
