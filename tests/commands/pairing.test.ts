/**
 * End-to-end CLI tests for `telclaude pairing` subcommands.
 *
 * We build a stand-alone Commander program, register only the pairing group,
 * and drive it via `parseAsync` while capturing stdout. This avoids pulling in
 * every other command in src/index.ts (each of which imports heavy modules).
 */

import crypto from "node:crypto";
import { Command } from "commander";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { PairingSigner } from "../../src/security/pairing.js";

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

import { registerPairingCommand } from "../../src/commands/pairing.js";
import {
	createPairingCode,
	isChatPaired,
	listPairedChats,
	listPairingRequests,
	setPairingSigner,
	SIGNING_PREFIX,
} from "../../src/security/pairing.js";

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
 * Build a one-shot commander program with only the pairing group registered.
 */
function buildProgram(): Command {
	const program = new Command();
	program.name("telclaude").exitOverride();
	registerPairingCommand(program);
	return program;
}

describe("telclaude pairing CLI", () => {
	let stdout: string[] = [];
	let stderr: string[] = [];
	let logSpy: ReturnType<typeof vi.spyOn>;
	let errSpy: ReturnType<typeof vi.spyOn>;
	let exitSpy: ReturnType<typeof vi.spyOn>;

	beforeEach(async () => {
		const { closeDb, getDb } = await import("../../src/storage/db.js");
		closeDb();
		getDb();
		setPairingSigner(buildTestSigner());
		stdout = [];
		stderr = [];
		logSpy = vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
			stdout.push(args.map(String).join(" "));
		});
		errSpy = vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
			stderr.push(args.map(String).join(" "));
		});
		exitSpy = vi.spyOn(process, "exit").mockImplementation(((_code?: number) => {
			throw new Error(`__process_exit__:${_code ?? 0}`);
		}) as never);
	});

	afterEach(async () => {
		const { closeDb } = await import("../../src/storage/db.js");
		closeDb();
		setPairingSigner(null);
		logSpy.mockRestore();
		errSpy.mockRestore();
		exitSpy.mockRestore();
	});

	// AC5: `pairing list` shows pending + recent-approved + lockouts.
	it("list (empty)", async () => {
		const program = buildProgram();
		await program.parseAsync(["node", "telclaude", "pairing", "list"]);
		const out = stdout.join("\n");
		expect(out).toMatch(/PENDING PAIRING CODES/);
		expect(out).toMatch(/APPROVED PAIRS/);
		expect(out).toMatch(/ACTIVE LOCKOUTS/);
		expect(out).toMatch(/\(none\)/);
	});

	it("list --json returns structured output", async () => {
		const program = buildProgram();
		await program.parseAsync(["node", "telclaude", "pairing", "list", "--json"]);
		const out = stdout.join("\n");
		const parsed = JSON.parse(out);
		expect(parsed).toHaveProperty("pending");
		expect(parsed).toHaveProperty("approved");
		expect(parsed).toHaveProperty("lockouts");
	});

	// AC4: `pairing approve <code>` validates and pairs.
	it("approve adds a paired_chat row", async () => {
		const { code } = await createPairingCode({
			userId: 111,
			chatId: 11100,
			username: "alice",
		});

		const program = buildProgram();
		await program.parseAsync(["node", "telclaude", "pairing", "approve", code]);

		expect(isChatPaired(11100)).toBe(true);
		const rows = listPairedChats();
		const row = rows.find((p) => p.chatId === 11100);
		expect(row).toBeDefined();
		expect(row!.tier).toBe("READ_ONLY");
		expect(row!.approvedBy).toBe("cli:admin");
		expect(stdout.join("\n")).toMatch(/Pairing approved/);
	});

	it("approve --tier upgrades the stored tier", async () => {
		const { code } = await createPairingCode({ userId: 112, chatId: 11200 });

		const program = buildProgram();
		await program.parseAsync([
			"node",
			"telclaude",
			"pairing",
			"approve",
			code,
			"--tier",
			"WRITE_LOCAL",
		]);

		const row = listPairedChats().find((p) => p.chatId === 11200);
		expect(row?.tier).toBe("WRITE_LOCAL");
	});

	it("approve rejects an unknown code with exit(1)", async () => {
		const program = buildProgram();
		await expect(
			program.parseAsync(["node", "telclaude", "pairing", "approve", "BOGUSXYZ"]),
		).rejects.toThrow(/__process_exit__:1/);
		expect(stderr.join("\n")).toMatch(/Pairing approval failed/);
	});

	it("approve rejects an invalid tier", async () => {
		const { code } = await createPairingCode({ userId: 113, chatId: 11300 });
		const program = buildProgram();
		await expect(
			program.parseAsync([
				"node",
				"telclaude",
				"pairing",
				"approve",
				code,
				"--tier",
				"SUPERUSER",
			]),
		).rejects.toThrow(/__process_exit__:1/);
		expect(stderr.join("\n")).toMatch(/Invalid tier/);
	});

	// AC6: `pairing revoke <user-id>` invalidates pending codes.
	it("revoke cancels pending codes", async () => {
		await createPairingCode({ userId: 114, chatId: 11400 });
		const program = buildProgram();
		await program.parseAsync(["node", "telclaude", "pairing", "revoke", "114"]);
		const pending = listPairingRequests({ status: "pending" }).filter((r) => r.userId === 114);
		expect(pending).toHaveLength(0);
		expect(stdout.join("\n")).toMatch(/Revoked 1/);
	});

	it("revoke with invalid user id exits 1", async () => {
		const program = buildProgram();
		await expect(
			program.parseAsync(["node", "telclaude", "pairing", "revoke", "not-a-number"]),
		).rejects.toThrow(/__process_exit__:1/);
	});

	// AC7: `pairing clear-pending` purges expired/unused codes.
	it("clear-pending is idempotent", async () => {
		const program = buildProgram();
		await program.parseAsync(["node", "telclaude", "pairing", "clear-pending"]);
		expect(stdout.join("\n")).toMatch(/Nothing to clear|Cleared/);
	});
});
