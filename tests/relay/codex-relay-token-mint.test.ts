import type http from "node:http";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../src/logging.js", () => ({
	getChildLogger: () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }),
}));

import {
	handleCodexRelayTokenMint,
	OPENAI_CODEX_RELAY_TOKEN_MAX_TTL_MS,
	verifyOpenAiCodexPeerBoundProxyToken,
} from "../../src/relay/openai-codex-proxy.js";
import { redactSecrets } from "../../src/security/output-filter.js";

type CapturedRes = http.ServerResponse & { statusCode: number; body: string };

function mockReqRes(remoteAddress: string | undefined) {
	const req = { socket: { remoteAddress }, headers: {} } as unknown as http.IncomingMessage;
	const res = {
		statusCode: 0,
		body: "",
		writeHead(status: number) {
			(res as CapturedRes).statusCode = status;
			return res;
		},
		end(b?: string) {
			(res as CapturedRes).body = b ?? "";
			return res;
		},
	} as unknown as CapturedRes;
	return { req, res };
}

const ENV = "TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN";

describe("handleCodexRelayTokenMint", () => {
	const original = process.env[ENV];
	beforeEach(() => {
		process.env[ENV] = "test-hmac-secret";
	});
	afterEach(() => {
		if (original === undefined) delete process.env[ENV];
		else process.env[ENV] = original;
	});

	it("mints a peer-bound run token verifiable for the same peer, rejected for another", () => {
		const { req, res } = mockReqRes("172.20.0.7");
		handleCodexRelayTokenMint(req, res, JSON.stringify({ runId: "job-1", ttlMs: 120_000 }));
		expect(res.statusCode).toBe(200);
		const { token, expiresInMs } = JSON.parse(res.body) as { token: string; expiresInMs: number };
		expect(typeof token).toBe("string");
		expect(expiresInMs).toBe(120_000);

		const ok = verifyOpenAiCodexPeerBoundProxyToken(token, {
			secret: "test-hmac-secret",
			peerAddress: "172.20.0.7",
		});
		expect(ok.ok).toBe(true);
		if (ok.ok) expect(ok.runId).toBe("job-1");

		const wrongPeer = verifyOpenAiCodexPeerBoundProxyToken(token, {
			secret: "test-hmac-secret",
			peerAddress: "10.9.9.9",
		});
		expect(wrongPeer.ok).toBe(false);
	});

	it("clamps an over-long requested TTL to the max", () => {
		const { req, res } = mockReqRes("172.20.0.7");
		handleCodexRelayTokenMint(req, res, JSON.stringify({ runId: "job-1", ttlMs: 99_999_999 }));
		const { expiresInMs } = JSON.parse(res.body) as { expiresInMs: number };
		expect(expiresInMs).toBe(OPENAI_CODEX_RELAY_TOKEN_MAX_TTL_MS);
	});

	it("fails closed (500) when the proxy signing secret is not configured", () => {
		delete process.env[ENV];
		const { req, res } = mockReqRes("172.20.0.7");
		handleCodexRelayTokenMint(req, res, JSON.stringify({ runId: "job-1" }));
		expect(res.statusCode).toBe(500);
	});

	it("rejects a missing runId with 400", () => {
		const { req, res } = mockReqRes("172.20.0.7");
		handleCodexRelayTokenMint(req, res, JSON.stringify({}));
		expect(res.statusCode).toBe(400);
	});

	it("rejects an unknown peer address with 400", () => {
		const { req, res } = mockReqRes(undefined);
		handleCodexRelayTokenMint(req, res, JSON.stringify({ runId: "job-1" }));
		expect(res.statusCode).toBe(400);
	});
});

describe("codex relay token redaction", () => {
	it("redacts the relay proxy bearer from streamed output", () => {
		const token = "tc-openai-codex-relay-v1.eyJhYmMiOiJkZWY.c2lnbmF0dXJlMTIz";
		const out = redactSecrets(`the bearer is ${token} do not leak`);
		expect(out).not.toContain(token);
	});
});
