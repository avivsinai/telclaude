/**
 * DM pairing (Workstream W4) unit tests.
 *
 * Covers the 12 acceptance criteria enumerated in
 * docs/plans/2026-04-18-dx-ecosystem-review.md §W4:
 *   1. Unknown chat receives a code on first contact (covered in inbound tests).
 *   2. Subsequent contact within 10 min → rate-limited (tested below).
 *   3. Code is 8-char URL-safe, Ed25519-verified.
 *   4. `approve` validates, pairs, and consumes.
 *   5. `list` surfaces pending/approved/lockouts.
 *   6. `revoke` invalidates pending codes.
 *   7. `clear-pending` wipes expired rows.
 *   8. 5 failed attempts → 1h lockout.
 *   9. Codes expire in 1h.
 *  10. `allowedChats` still works (covered in inbound tests).
 *  11. Schema migration is idempotent.
 *  12. Domain separation with `pairing-v1`.
 */

import crypto from "node:crypto";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { PairingSigner } from "../../src/security/pairing.js";

const PAIRING_SCHEMA = `
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
	CREATE INDEX IF NOT EXISTS idx_pairing_requests_user ON pairing_requests(user_id, status);
	CREATE INDEX IF NOT EXISTS idx_pairing_requests_expires ON pairing_requests(status, expires_at);

	CREATE TABLE IF NOT EXISTS pairing_failed_attempts (
		user_id INTEGER PRIMARY KEY,
		attempts INTEGER NOT NULL DEFAULT 0,
		last_attempt_at INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS pairing_lockouts (
		user_id INTEGER PRIMARY KEY,
		locked_until INTEGER NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_pairing_lockouts_until ON pairing_lockouts(locked_until);

	CREATE TABLE IF NOT EXISTS paired_chats (
		chat_id INTEGER PRIMARY KEY,
		user_id INTEGER NOT NULL,
		tier TEXT NOT NULL,
		paired_at INTEGER NOT NULL,
		approved_by TEXT NOT NULL,
		username TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_paired_chats_user ON paired_chats(user_id);
`;

vi.mock("../../src/storage/db.js", () => {
	let mockDb: Database.Database | null = null;
	return {
		getDb: () => {
			if (!mockDb) {
				mockDb = new Database(":memory:");
				mockDb.exec(PAIRING_SCHEMA);
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

// We import AFTER the mocks so the module-level `getDb()` call resolves to the memory DB.
import {
	CODE_EXPIRY_MS,
	EMIT_COOLDOWN_MS,
	LOCKOUT_MS,
	MAX_FAILED_ATTEMPTS,
	MAX_PENDING_PER_USER,
	approvePairingCode,
	checkPairingRate,
	clearExpiredPending,
	createLocalPairingSigner,
	createPairingCode,
	formatPairingPrompt,
	formatPairingRateNotice,
	getPairedChat,
	getPairingSigner,
	isChatPaired,
	listActiveLockouts,
	listPairingRequests,
	listPairedChats,
	normalizeCode,
	removePairedChat,
	revokePendingForUser,
	setPairingSigner,
	SIGNING_PREFIX,
} from "../../src/security/pairing.js";

// In-process Ed25519 signer for tests — avoids writing the keypair file under
// the real CONFIG_DIR while still exercising the real crypto path.
function buildTestSigner(): PairingSigner & { publicKey: crypto.KeyObject } {
	const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
	return {
		publicKey,
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

describe("DM pairing", () => {
	let signer: ReturnType<typeof buildTestSigner>;

	beforeEach(async () => {
		const { closeDb, getDb } = await import("../../src/storage/db.js");
		closeDb();
		getDb();
		signer = buildTestSigner();
		setPairingSigner(signer);
	});

	afterEach(async () => {
		const { closeDb } = await import("../../src/storage/db.js");
		closeDb();
		setPairingSigner(null);
	});

	// ─── AC3: code shape + Ed25519 sig verification ────────────────────────────
	describe("code generation", () => {
		it("emits 8-char URL-safe codes (no 0/O/1/I/L)", async () => {
			const { code } = await createPairingCode({ userId: 1, chatId: 100 });
			expect(code).toHaveLength(8);
			expect(code).toMatch(/^[A-HJKMNPQRSTUVWXYZ23456789]+$/);
		});

		it("produces distinct codes across many invocations", async () => {
			const codes = new Set<string>();
			for (let i = 0; i < 64; i++) {
				const { code } = await createPairingCode({ userId: i + 1, chatId: 100 + i });
				codes.add(code);
			}
			expect(codes.size).toBe(64);
		});

		it("stores a SHA-256 hash, not the plaintext code", async () => {
			const userId = 42;
			const { code } = await createPairingCode({ userId, chatId: 200 });
			const requests = listPairingRequests({ status: "pending" });
			const found = requests.find((r) => r.userId === userId);
			expect(found).toBeDefined();
			expect(found!.codeHash).not.toBe(code);
			expect(found!.codeHash).toBe(
				crypto.createHash("sha256").update(code, "utf8").digest("hex"),
			);
		});

		it("signs with pairing-v1 domain separator", async () => {
			const userId = 7;
			const chatId = 700;
			const { code } = await createPairingCode({ userId, chatId });
			const request = listPairingRequests({ status: "pending" }).find(
				(r) => r.userId === userId,
			)!;
			const hash = crypto.createHash("sha256").update(code, "utf8").digest("hex");
			const payload = `${userId}:${chatId}:${hash}`;
			const okV1 = crypto.verify(
				null,
				Buffer.from(`${SIGNING_PREFIX}\n${payload}`, "utf8"),
				signer.publicKey,
				Buffer.from(request.signature, "base64url"),
			);
			expect(okV1).toBe(true);
			// Signature MUST NOT verify under a different domain (e.g. approval-v1).
			const okOtherDomain = crypto.verify(
				null,
				Buffer.from(`approval-v1\n${payload}`, "utf8"),
				signer.publicKey,
				Buffer.from(request.signature, "base64url"),
			);
			expect(okOtherDomain).toBe(false);
		});
	});

	// ─── AC2: cooldown + AC8 lockout rate limiting ─────────────────────────────
	describe("rate limiting", () => {
		it("allows the first code for a user", () => {
			const result = checkPairingRate(1);
			expect(result.allowed).toBe(true);
		});

		it("rate-limits a second emit within the cooldown window", async () => {
			await createPairingCode({ userId: 1, chatId: 10 });
			const check = checkPairingRate(1);
			expect(check.allowed).toBe(false);
			if (!check.allowed) {
				expect(check.reason).toBe("cooldown");
				expect(check.retryAfterMs).toBeGreaterThan(0);
				expect(check.retryAfterMs).toBeLessThanOrEqual(EMIT_COOLDOWN_MS);
			}
		});

		it("permits a second emit once cooldown elapses", async () => {
			const originalNow = Date.now;
			const start = originalNow();
			try {
				vi.spyOn(Date, "now").mockReturnValue(start);
				await createPairingCode({ userId: 2, chatId: 20 });
				vi.spyOn(Date, "now").mockReturnValue(start + EMIT_COOLDOWN_MS + 1);
				const check = checkPairingRate(2);
				expect(check.allowed).toBe(true);
			} finally {
				vi.restoreAllMocks();
			}
		});

		it("enforces MAX_PENDING_PER_USER", async () => {
			// First code creates the cooldown — simulate time moving forward each time.
			const originalNow = Date.now;
			const start = originalNow();
			try {
				for (let i = 0; i < MAX_PENDING_PER_USER; i++) {
					vi.spyOn(Date, "now").mockReturnValue(start + i * (EMIT_COOLDOWN_MS + 10));
					await createPairingCode({ userId: 3, chatId: 30 + i });
				}
				vi.spyOn(Date, "now").mockReturnValue(
					start + MAX_PENDING_PER_USER * (EMIT_COOLDOWN_MS + 10),
				);
				const check = checkPairingRate(3);
				expect(check.allowed).toBe(false);
				if (!check.allowed) {
					expect(check.reason).toBe("pending_limit");
				}
			} finally {
				vi.restoreAllMocks();
			}
		});
	});

	// ─── AC4: approve-happy-path + paired_chats insertion ──────────────────────
	describe("approve", () => {
		it("pairs the chat and marks the request approved", async () => {
			const { code } = await createPairingCode({
				userId: 10,
				chatId: 1000,
				username: "alice",
			});
			const result = await approvePairingCode(code, "cli:aviv");
			expect(result.success).toBe(true);
			if (result.success) {
				expect(result.data.paired.chatId).toBe(1000);
				expect(result.data.paired.userId).toBe(10);
				expect(result.data.paired.tier).toBe("READ_ONLY");
				expect(result.data.request.status).toBe("approved");
				expect(result.data.request.approvedBy).toBe("cli:aviv");
			}

			expect(isChatPaired(1000)).toBe(true);
			expect(getPairedChat(1000)?.username).toBe("alice");
		});

		it("accepts lowercase/dashed codes (normalization)", async () => {
			const { code } = await createPairingCode({ userId: 11, chatId: 1001 });
			const messy = `${code.slice(0, 4).toLowerCase()}-${code.slice(4).toLowerCase()}`;
			const result = await approvePairingCode(messy, "cli:test");
			expect(result.success).toBe(true);
		});

		it("rejects the same code on second approval (single-use)", async () => {
			const { code } = await createPairingCode({ userId: 12, chatId: 1002 });
			const first = await approvePairingCode(code, "cli:first");
			expect(first.success).toBe(true);
			const second = await approvePairingCode(code, "cli:second");
			expect(second.success).toBe(false);
			if (!second.success) {
				expect(second.error).toMatch(/already/);
			}
		});

		it("rejects unknown codes", async () => {
			const result = await approvePairingCode("ZZZZZZZZ", "cli:admin");
			expect(result.success).toBe(false);
		});

		it("rejects non-8-char input without touching the DB", async () => {
			const result = await approvePairingCode("ABC", "cli:admin");
			expect(result.success).toBe(false);
		});

		it("rejects tampered signatures", async () => {
			const userId = 13;
			const chatId = 1003;
			const { code } = await createPairingCode({ userId, chatId });
			const { getDb } = await import("../../src/storage/db.js");
			const db = getDb();
			// Corrupt the stored signature.
			db.prepare("UPDATE pairing_requests SET signature = 'aaaa' WHERE user_id = ?").run(userId);
			const result = await approvePairingCode(code, "cli:admin");
			expect(result.success).toBe(false);
			if (!result.success) {
				expect(result.error).toMatch(/signature/i);
			}
		});

		it("revokes other pending codes for the same user on approve", async () => {
			const user = 14;
			const originalNow = Date.now;
			const start = originalNow();
			try {
				vi.spyOn(Date, "now").mockReturnValue(start);
				const first = await createPairingCode({ userId: user, chatId: 1400 });
				vi.spyOn(Date, "now").mockReturnValue(start + EMIT_COOLDOWN_MS + 1);
				await createPairingCode({ userId: user, chatId: 1401 });
				vi.spyOn(Date, "now").mockReturnValue(start + 2 * (EMIT_COOLDOWN_MS + 1));
				await createPairingCode({ userId: user, chatId: 1402 });

				const approveResult = await approvePairingCode(first.code, "cli:admin");
				expect(approveResult.success).toBe(true);

				const stillPending = listPairingRequests({ status: "pending" }).filter(
					(r) => r.userId === user,
				);
				expect(stillPending).toHaveLength(0);

				const revoked = listPairingRequests({ status: "revoked" }).filter(
					(r) => r.userId === user,
				);
				expect(revoked).toHaveLength(2);
			} finally {
				vi.restoreAllMocks();
			}
		});
	});

	// ─── AC9: expiry ───────────────────────────────────────────────────────────
	describe("expiry", () => {
		it("rejects approval of an expired code", async () => {
			const originalNow = Date.now;
			const start = originalNow();
			try {
				vi.spyOn(Date, "now").mockReturnValue(start);
				const { code } = await createPairingCode({ userId: 20, chatId: 2000 });
				vi.spyOn(Date, "now").mockReturnValue(start + CODE_EXPIRY_MS + 1);
				const result = await approvePairingCode(code, "cli:admin");
				expect(result.success).toBe(false);
				if (!result.success) {
					expect(result.error).toMatch(/expired/i);
				}
			} finally {
				vi.restoreAllMocks();
			}
		});

		it("clearExpiredPending marks pending → expired", async () => {
			const originalNow = Date.now;
			const start = originalNow();
			try {
				vi.spyOn(Date, "now").mockReturnValue(start);
				await createPairingCode({ userId: 21, chatId: 2100 });
				vi.spyOn(Date, "now").mockReturnValue(start + CODE_EXPIRY_MS + 1);
				const changed = clearExpiredPending();
				expect(changed).toBeGreaterThan(0);
				const expired = listPairingRequests({ status: "expired" });
				expect(expired.length).toBeGreaterThan(0);
			} finally {
				vi.restoreAllMocks();
			}
		});
	});

	// ─── AC8: lockout after 5 failed attempts ─────────────────────────────────
	describe("lockout", () => {
		it("locks the user out after MAX_FAILED_ATTEMPTS failed attempts", async () => {
			const userId = 30;
			const chatId = 3000;
			const originalNow = Date.now;
			const start = originalNow();
			try {
				vi.spyOn(Date, "now").mockReturnValue(start);
				const { code } = await createPairingCode({ userId, chatId });

				// Jump past expiry so each approval attempt increments the failure counter.
				vi.spyOn(Date, "now").mockReturnValue(start + CODE_EXPIRY_MS + 1);
				for (let i = 0; i < MAX_FAILED_ATTEMPTS; i++) {
					const r = await approvePairingCode(code, "cli:admin");
					expect(r.success).toBe(false);
				}

				const lockouts = listActiveLockouts(start + CODE_EXPIRY_MS + 2);
				const ours = lockouts.find((l) => l.userId === userId);
				expect(ours).toBeDefined();
				expect(ours!.attempts).toBeGreaterThanOrEqual(MAX_FAILED_ATTEMPTS);
				expect(ours!.lockedUntil).toBeGreaterThan(start + CODE_EXPIRY_MS);
				expect(ours!.lockedUntil - (start + CODE_EXPIRY_MS + 1)).toBeLessThanOrEqual(
					LOCKOUT_MS + 100,
				);
			} finally {
				vi.restoreAllMocks();
			}
		});

		it("lockout is surfaced by checkPairingRate", async () => {
			const userId = 31;
			const originalNow = Date.now;
			const start = originalNow();
			try {
				vi.spyOn(Date, "now").mockReturnValue(start);
				const { code } = await createPairingCode({ userId, chatId: 3100 });
				vi.spyOn(Date, "now").mockReturnValue(start + CODE_EXPIRY_MS + 1);
				for (let i = 0; i < MAX_FAILED_ATTEMPTS; i++) {
					await approvePairingCode(code, "cli:admin");
				}
				const check = checkPairingRate(userId, start + CODE_EXPIRY_MS + 2);
				expect(check.allowed).toBe(false);
				if (!check.allowed) {
					expect(check.reason).toBe("lockout");
				}
			} finally {
				vi.restoreAllMocks();
			}
		});
	});

	// ─── AC6: revoke ──────────────────────────────────────────────────────────
	describe("revoke", () => {
		it("revokes pending codes for a user", async () => {
			const user = 40;
			const originalNow = Date.now;
			const start = originalNow();
			try {
				vi.spyOn(Date, "now").mockReturnValue(start);
				await createPairingCode({ userId: user, chatId: 4000 });
				vi.spyOn(Date, "now").mockReturnValue(start + EMIT_COOLDOWN_MS + 1);
				await createPairingCode({ userId: user, chatId: 4001 });

				const n = revokePendingForUser(user);
				expect(n).toBe(2);

				const stillPending = listPairingRequests({ status: "pending" }).filter(
					(r) => r.userId === user,
				);
				expect(stillPending).toHaveLength(0);
			} finally {
				vi.restoreAllMocks();
			}
		});

		it("revoked codes cannot be approved later", async () => {
			const { code } = await createPairingCode({ userId: 41, chatId: 4100 });
			revokePendingForUser(41);
			const result = await approvePairingCode(code, "cli:admin");
			expect(result.success).toBe(false);
		});
	});

	// ─── AC7: clear-pending ───────────────────────────────────────────────────
	describe("clear-pending", () => {
		it("prunes terminal rows older than 7 days", async () => {
			const { getDb } = await import("../../src/storage/db.js");
			const db = getDb();
			const eightDaysAgo = Date.now() - 8 * 24 * 60 * 60 * 1000;
			db.prepare(
				`INSERT INTO pairing_requests (code_hash, user_id, chat_id, tier, status,
					created_at, expires_at, signature)
				 VALUES (?, ?, ?, 'READ_ONLY', 'revoked', ?, ?, 'sig')`,
			).run("deadbeef", 50, 5000, eightDaysAgo, eightDaysAgo + 1);
			const before = listPairingRequests().length;
			clearExpiredPending();
			const after = listPairingRequests().length;
			expect(after).toBeLessThan(before);
		});
	});

	// ─── AC5: list — already covered by CLI tests, but we can assert the data ─
	describe("list helpers", () => {
		it("lists approved paired chats", async () => {
			const { code } = await createPairingCode({ userId: 60, chatId: 6000 });
			await approvePairingCode(code, "cli:admin");
			const list = listPairedChats();
			expect(list.some((p) => p.chatId === 6000)).toBe(true);
		});

		it("removePairedChat drops the row", async () => {
			const { code } = await createPairingCode({ userId: 61, chatId: 6100 });
			await approvePairingCode(code, "cli:admin");
			expect(isChatPaired(6100)).toBe(true);
			expect(removePairedChat(6100)).toBe(true);
			expect(isChatPaired(6100)).toBe(false);
		});
	});

	// ─── AC11: schema migration idempotency ──────────────────────────────────
	describe("schema idempotency", () => {
		it("re-running migration is a no-op", async () => {
			const { getDb } = await import("../../src/storage/db.js");
			const db = getDb();
			// Running the same CREATE TABLE IF NOT EXISTS a second time must not throw.
			expect(() => db.exec(PAIRING_SCHEMA)).not.toThrow();
			// And the pairing flow still works.
			const { code } = await createPairingCode({ userId: 70, chatId: 7000 });
			const r = await approvePairingCode(code, "cli:admin");
			expect(r.success).toBe(true);
		});
	});

	// ─── Utility helpers ─────────────────────────────────────────────────────
	describe("utilities", () => {
		it("normalizeCode strips whitespace and dashes and uppercases", () => {
			expect(normalizeCode(" ab-cd efgh ")).toBe("ABCDEFGH");
		});

		it("formatPairingPrompt surfaces the code and expiry", () => {
			const msg = formatPairingPrompt("ABCDEFGH", Date.now() + CODE_EXPIRY_MS);
			expect(msg).toContain("ABCDEFGH");
			expect(msg).toContain("pairing approve");
		});

		it("formatPairingRateNotice returns distinct text per reason", () => {
			expect(formatPairingRateNotice({ allowed: false, reason: "cooldown", retryAfterMs: 60_000 })).toContain(
				"wait",
			);
			expect(
				formatPairingRateNotice({ allowed: false, reason: "pending_limit", retryAfterMs: 60_000 }),
			).toContain("maximum");
			expect(formatPairingRateNotice({ allowed: false, reason: "lockout", retryAfterMs: 60_000 })).toContain(
				"failed",
			);
		});

		it("createLocalPairingSigner round-trips a sign/verify", async () => {
			const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519", {
				privateKeyEncoding: { type: "pkcs8", format: "pem" },
				publicKeyEncoding: { type: "spki", format: "pem" },
			});
			const localSigner = createLocalPairingSigner({
				privateKeyPem: privateKey.toString(),
				publicKeyPem: publicKey.toString(),
			});
			const sig = await localSigner.sign("hello");
			expect(await localSigner.verify("hello", sig)).toBe(true);
			expect(await localSigner.verify("hello2", sig)).toBe(false);
		});

		it("getPairingSigner is idempotent (cached)", () => {
			// With our mocked DB this will generate a keypair file under CONFIG_DIR.
			// Swap in the test signer first to avoid that; getPairingSigner now returns it.
			const s1 = getPairingSigner();
			const s2 = getPairingSigner();
			expect(s1).toBe(s2);
		});
	});
});
