/**
 * Integration tests for the DM pairing inbound flow (W4 AC1 + AC10).
 *
 * We don't spin up grammy for this test — instead we drive the pairing state
 * machine via its public functions (same call sequence `tryEmitPairingCode`
 * performs inside monitorTelegramInbox) and assert:
 *
 *   AC1  Unknown-chat DM → pairing code emitted (reply captured).
 *   AC2  Second DM within 10 min → rate-limit notice instead of a fresh code.
 *   AC10 Chats in `allowedChats` bypass pairing entirely (no code emitted).
 *   AC + isChatPaired/getUserPermissionTier integration — once approved, the
 *        chat passes the same allow-check and gets the configured tier.
 */

import crypto from "node:crypto";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { PairingSigner } from "../../src/security/pairing.js";

// Full DB schema that both `pairing.ts` and `permissions.ts` depend on.
const SCHEMA = `
	CREATE TABLE IF NOT EXISTS pairing_requests (
		code_hash TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL,
		chat_id INTEGER NOT NULL,
		username TEXT,
		tier TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'pending',
		attempts INTEGER NOT NULL DEFAULT 0,
		created_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL,
		approved_at INTEGER,
		approved_by TEXT,
		signature TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS pairing_failed_attempts (
		user_id INTEGER PRIMARY KEY,
		attempts INTEGER NOT NULL DEFAULT 0,
		last_attempt_at INTEGER NOT NULL
	);
	CREATE TABLE IF NOT EXISTS pairing_lockouts (
		user_id INTEGER PRIMARY KEY,
		locked_until INTEGER NOT NULL
	);
	CREATE TABLE IF NOT EXISTS paired_chats (
		chat_id INTEGER PRIMARY KEY,
		user_id INTEGER NOT NULL,
		tier TEXT NOT NULL,
		paired_at INTEGER NOT NULL,
		approved_by TEXT NOT NULL,
		username TEXT
	);
	CREATE TABLE IF NOT EXISTS identity_links (
		chat_id INTEGER PRIMARY KEY,
		local_user_id TEXT NOT NULL,
		linked_at INTEGER NOT NULL,
		linked_by TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS totp_sessions (
		local_user_id TEXT PRIMARY KEY,
		verified_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL
	);
`;

vi.mock("../../src/storage/db.js", () => {
	let mockDb: Database.Database | null = null;
	return {
		getDb: () => {
			if (!mockDb) {
				mockDb = new Database(":memory:");
				mockDb.exec(SCHEMA);
			}
			return mockDb;
		},
		closeDb: () => {
			if (mockDb) {
				mockDb.close();
				mockDb = null;
			}
		},
	};
});

vi.mock("../../src/logging.js", () => ({
	getChildLogger: () => ({
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		debug: vi.fn(),
	}),
}));

vi.mock("../../src/sandbox/mode.js", () => ({
	shouldEnableSdkSandbox: () => true,
}));

import {
	approvePairingCode,
	checkPairingRate,
	createPairingCode,
	formatPairingPrompt,
	formatPairingRateNotice,
	isChatPaired,
	setPairingSigner,
	SIGNING_PREFIX,
} from "../../src/security/pairing.js";
import { getUserPermissionTier } from "../../src/security/permissions.js";

// ── Signer fixture (in-process; no filesystem writes) ─────────────────────────
function buildTestSigner(): PairingSigner {
	const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
	return {
		async sign(payload: string): Promise<string> {
			const msg = Buffer.from(`${SIGNING_PREFIX}\n${payload}`, "utf8");
			return crypto.sign(null, msg, privateKey).toString("base64url");
		},
		async verify(payload: string, signature: string): Promise<boolean> {
			try {
				const msg = Buffer.from(`${SIGNING_PREFIX}\n${payload}`, "utf8");
				return crypto.verify(null, msg, publicKey, Buffer.from(signature, "base64url"));
			} catch {
				return false;
			}
		},
	};
}

/**
 * Simulated inbound: caller asks "is this chat allowed?" given the two gates
 * (allowedChats + paired chats), and if not, we invoke the pairing emit path.
 *
 * This mirrors the logic inside `monitorTelegramInbox.buildInboundMessage`
 * without pulling in grammy.
 */
async function simulateInboundDm(args: {
	userId: number;
	chatId: number;
	username?: string;
	allowedChats: Array<number | string>;
	hasAdmin: boolean;
}): Promise<{
	allowed: boolean;
	replies: string[];
}> {
	const replies: string[] = [];

	const isAllowed =
		args.allowedChats.some((c) => String(c) === String(args.chatId)) || isChatPaired(args.chatId);

	if (isAllowed) {
		return { allowed: true, replies };
	}

	// Unknown chat — emit pairing (matches the `tryEmitPairingCode` body
	// inside src/telegram/inbound.ts).
	if (!args.hasAdmin) {
		// When there's no admin yet, pairing is not emitted — admin claim flow runs instead.
		return { allowed: false, replies };
	}

	const check = checkPairingRate(args.userId);
	if (!check.allowed) {
		replies.push(formatPairingRateNotice(check));
		return { allowed: false, replies };
	}

	const issued = await createPairingCode({
		userId: args.userId,
		chatId: args.chatId,
		username: args.username,
	});
	replies.push(formatPairingPrompt(issued.code, issued.expiresAt));
	return { allowed: false, replies };
}

describe("inbound — DM pairing flow", () => {
	beforeEach(async () => {
		const { closeDb, getDb } = await import("../../src/storage/db.js");
		closeDb();
		getDb();
		setPairingSigner(buildTestSigner());
	});

	afterEach(async () => {
		const { closeDb } = await import("../../src/storage/db.js");
		closeDb();
		setPairingSigner(null);
	});

	// AC1 — Unknown-chat DM replies with a pairing code + rate-limit notice.
	it("unknown-chat DM triggers a pairing-code reply", async () => {
		const result = await simulateInboundDm({
			userId: 9001,
			chatId: 9001,
			username: "stranger",
			allowedChats: [],
			hasAdmin: true,
		});

		expect(result.allowed).toBe(false);
		expect(result.replies).toHaveLength(1);
		expect(result.replies[0]).toMatch(/Pairing code/);
		expect(result.replies[0]).toMatch(/telclaude pairing approve/);
	});

	// AC2 — Second DM within 10 min → rate-limit notice, NOT a new code.
	it("second DM within cooldown replies with rate-limit notice instead of a new code", async () => {
		const userId = 9002;
		const chatId = 9002;
		const first = await simulateInboundDm({
			userId,
			chatId,
			allowedChats: [],
			hasAdmin: true,
		});
		expect(first.replies[0]).toMatch(/Pairing code/);

		const second = await simulateInboundDm({
			userId,
			chatId,
			allowedChats: [],
			hasAdmin: true,
		});
		expect(second.allowed).toBe(false);
		expect(second.replies).toHaveLength(1);
		expect(second.replies[0]).not.toMatch(/Pairing code/);
		expect(second.replies[0]).toMatch(/wait/i);
	});

	// AC10 — Chats in allowedChats bypass pairing entirely.
	it("chat in allowedChats bypasses pairing (no reply, treated as allowed)", async () => {
		const result = await simulateInboundDm({
			userId: 9003,
			chatId: 9003,
			allowedChats: [9003],
			hasAdmin: true,
		});

		expect(result.allowed).toBe(true);
		expect(result.replies).toHaveLength(0);
	});

	// Approved pairing → chat passes gate + gets configured tier.
	it("approved pairing augments allowedChats and grants the configured tier", async () => {
		const chatId = 9004;
		const userId = 9004;

		// Step 1: unknown chat, gets a code.
		const issued = await createPairingCode({ userId, chatId, tier: "READ_ONLY" });

		// Step 2: operator approves.
		const approval = await approvePairingCode(issued.code, "cli:aviv");
		expect(approval.success).toBe(true);

		// Step 3: the chat now passes the gate without needing allowedChats.
		const followup = await simulateInboundDm({
			userId,
			chatId,
			allowedChats: [],
			hasAdmin: true,
		});
		expect(followup.allowed).toBe(true);

		// And the permissions resolver picks up the paired tier.
		const tier = getUserPermissionTier(chatId);
		expect(tier).toBe("READ_ONLY");
	});

	// Sanity: no admin claimed → pairing is skipped (admin claim flow still runs).
	it("does not emit pairing when admin has not yet been claimed", async () => {
		const result = await simulateInboundDm({
			userId: 9005,
			chatId: 9005,
			allowedChats: [],
			hasAdmin: false,
		});
		expect(result.allowed).toBe(false);
		expect(result.replies).toHaveLength(0);
	});
});
