import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { once } from "node:events";
import type { AddressInfo } from "node:net";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

let startCapabilityServer: typeof import("../../src/relay/capabilities.js").startCapabilityServer;
let buildInternalAuthHeaders: typeof import("../../src/internal-auth.js").buildInternalAuthHeaders;
let generateMoltbookKeyPair: typeof import("../../src/internal-auth.js").generateMoltbookKeyPair;
let resetDatabase: typeof import("../../src/storage/db.js").resetDatabase;

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;
const ORIGINAL_TELEGRAM_SECRET = process.env.TELEGRAM_RPC_SECRET;
const ORIGINAL_MOLTBOOK_SECRET = process.env.MOLTBOOK_RPC_SECRET;
const ORIGINAL_MOLTBOOK_PRIVATE_KEY = process.env.MOLTBOOK_RPC_PRIVATE_KEY;
const ORIGINAL_MOLTBOOK_PUBLIC_KEY = process.env.MOLTBOOK_RPC_PUBLIC_KEY;

describe("memory rpc", () => {
	let tempDir: string;
	let server: ReturnType<typeof startCapabilityServer> | null = null;
	let baseUrl: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-memrpc-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		process.env.TELEGRAM_RPC_SECRET = "test-telegram-secret";
		// Generate Ed25519 key pair for moltbook asymmetric auth
		vi.resetModules();
		({ generateMoltbookKeyPair } = await import("../../src/internal-auth.js"));
		const { privateKey, publicKey } = generateMoltbookKeyPair();
		process.env.MOLTBOOK_RPC_PRIVATE_KEY = privateKey;
		process.env.MOLTBOOK_RPC_PUBLIC_KEY = publicKey;
		delete process.env.MOLTBOOK_RPC_SECRET; // Ensure no symmetric fallback

		vi.resetModules();
		({ startCapabilityServer } = await import("../../src/relay/capabilities.js"));
		({ buildInternalAuthHeaders } = await import("../../src/internal-auth.js"));
		({ resetDatabase } = await import("../../src/storage/db.js"));
		resetDatabase();

		server = startCapabilityServer({ port: 0, host: "127.0.0.1" });
		await once(server, "listening");
		const address = server.address() as AddressInfo;
		baseUrl = `http://127.0.0.1:${address.port}`;
	});

	afterEach(() => {
		if (server) {
			server.close();
			server = null;
		}
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) {
			delete process.env.TELCLAUDE_DATA_DIR;
		} else {
			process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
		}
		if (ORIGINAL_TELEGRAM_SECRET === undefined) {
			delete process.env.TELEGRAM_RPC_SECRET;
		} else {
			process.env.TELEGRAM_RPC_SECRET = ORIGINAL_TELEGRAM_SECRET;
		}
		if (ORIGINAL_MOLTBOOK_SECRET === undefined) {
			delete process.env.MOLTBOOK_RPC_SECRET;
		} else {
			process.env.MOLTBOOK_RPC_SECRET = ORIGINAL_MOLTBOOK_SECRET;
		}
		if (ORIGINAL_MOLTBOOK_PRIVATE_KEY === undefined) {
			delete process.env.MOLTBOOK_RPC_PRIVATE_KEY;
		} else {
			process.env.MOLTBOOK_RPC_PRIVATE_KEY = ORIGINAL_MOLTBOOK_PRIVATE_KEY;
		}
		if (ORIGINAL_MOLTBOOK_PUBLIC_KEY === undefined) {
			delete process.env.MOLTBOOK_RPC_PUBLIC_KEY;
		} else {
			process.env.MOLTBOOK_RPC_PUBLIC_KEY = ORIGINAL_MOLTBOOK_PUBLIC_KEY;
		}
	});

	it("accepts propose and returns snapshot (POST)", async () => {
		const proposeBody = JSON.stringify({
			entries: [{ id: "entry-1", category: "profile", content: "hello" }],
			userId: "tg:1",
		});
		const proposeHeaders = buildInternalAuthHeaders("POST", "/v1/memory.propose", proposeBody, {
			scope: "telegram",
		});

		const proposeRes = await fetch(`${baseUrl}/v1/memory.propose`, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				...proposeHeaders,
			},
			body: proposeBody,
		});

		expect(proposeRes.status).toBe(200);
		const proposeData = (await proposeRes.json()) as { accepted: number };
		expect(proposeData.accepted).toBe(1);

		const snapshotBody = JSON.stringify({ categories: ["profile"] });
		const snapshotHeaders = buildInternalAuthHeaders(
			"POST",
			"/v1/memory.snapshot",
			snapshotBody,
			{ scope: "telegram" },
		);
		const snapshotRes = await fetch(`${baseUrl}/v1/memory.snapshot`, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				...snapshotHeaders,
			},
			body: snapshotBody,
		});

		expect(snapshotRes.status).toBe(200);
		const snapshot = (await snapshotRes.json()) as { entries: Array<{ id: string }> };
		expect(snapshot.entries).toHaveLength(1);
		expect(snapshot.entries[0].id).toBe("entry-1");
	});

	it("supports signed GET snapshot requests", async () => {
		const proposeBody = JSON.stringify({
			entries: [{ id: "entry-get", category: "meta", content: "ping" }],
		});
		const proposeHeaders = buildInternalAuthHeaders("POST", "/v1/memory.propose", proposeBody, {
			scope: "telegram",
		});
		await fetch(`${baseUrl}/v1/memory.propose`, {
			method: "POST",
			headers: { "Content-Type": "application/json", ...proposeHeaders },
			body: proposeBody,
		});

		const queryPath = "/v1/memory.snapshot?limit=10";
		const getHeaders = buildInternalAuthHeaders("GET", queryPath, "", { scope: "telegram" });
		const getRes = await fetch(`${baseUrl}${queryPath}`, {
			method: "GET",
			headers: getHeaders,
		});
		expect(getRes.status).toBe(200);
	});

	it("scopes moltbook snapshot requests to moltbook entries only", async () => {
		const telegramBody = JSON.stringify({
			entries: [{ id: "entry-tg", category: "profile", content: "hello" }],
		});
		const telegramHeaders = buildInternalAuthHeaders("POST", "/v1/memory.propose", telegramBody, {
			scope: "telegram",
		});
		await fetch(`${baseUrl}/v1/memory.propose`, {
			method: "POST",
			headers: { "Content-Type": "application/json", ...telegramHeaders },
			body: telegramBody,
		});

		const moltbookBody = JSON.stringify({
			entries: [{ id: "entry-mb", category: "posts", content: "moltbook" }],
		});
		const moltbookHeaders = buildInternalAuthHeaders("POST", "/v1/memory.propose", moltbookBody, {
			scope: "moltbook",
		});
		await fetch(`${baseUrl}/v1/memory.propose`, {
			method: "POST",
			headers: { "Content-Type": "application/json", ...moltbookHeaders },
			body: moltbookBody,
		});

		const snapshotBody = JSON.stringify({ sources: ["telegram"] });
		const snapshotHeaders = buildInternalAuthHeaders(
			"POST",
			"/v1/memory.snapshot",
			snapshotBody,
			{ scope: "moltbook" },
		);
		const snapshotRes = await fetch(`${baseUrl}/v1/memory.snapshot`, {
			method: "POST",
			headers: { "Content-Type": "application/json", ...snapshotHeaders },
			body: snapshotBody,
		});
		expect(snapshotRes.status).toBe(200);
		const snapshot = (await snapshotRes.json()) as { entries: Array<{ id: string }> };
		expect(snapshot.entries.map((entry) => entry.id)).toEqual(["entry-mb"]);
	});

	it("assigns untrusted trust for moltbook scope", async () => {
		const proposeBody = JSON.stringify({
			entries: [{ id: "entry-mb", category: "posts", content: "hello" }],
		});
		const proposeHeaders = buildInternalAuthHeaders("POST", "/v1/memory.propose", proposeBody, {
			scope: "moltbook",
		});
		const proposeRes = await fetch(`${baseUrl}/v1/memory.propose`, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				...proposeHeaders,
			},
			body: proposeBody,
		});
		expect(proposeRes.status).toBe(200);

		const snapshotBody = JSON.stringify({ sources: ["moltbook"] });
		const snapshotHeaders = buildInternalAuthHeaders(
			"POST",
			"/v1/memory.snapshot",
			snapshotBody,
			{ scope: "telegram" },
		);
		const snapshotRes = await fetch(`${baseUrl}/v1/memory.snapshot`, {
			method: "POST",
			headers: { "Content-Type": "application/json", ...snapshotHeaders },
			body: snapshotBody,
		});
		const snapshot = (await snapshotRes.json()) as {
			entries: Array<{ id: string; _provenance: { trust: string } }>;
		};
		expect(snapshot.entries[0]._provenance.trust).toBe("untrusted");
	});

	it("rejects too many entries", async () => {
		const entries = Array.from({ length: 6 }).map((_, index) => ({
			id: `entry-${index}`,
			category: "profile",
			content: "hello",
		}));
		const proposeBody = JSON.stringify({ entries });
		const proposeHeaders = buildInternalAuthHeaders("POST", "/v1/memory.propose", proposeBody, {
			scope: "telegram",
		});
		const proposeRes = await fetch(`${baseUrl}/v1/memory.propose`, {
			method: "POST",
			headers: { "Content-Type": "application/json", ...proposeHeaders },
			body: proposeBody,
		});
		expect(proposeRes.status).toBe(400);
	});
});
