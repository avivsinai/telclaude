/**
 * Tests that W8's exec-policy pre-check is wired into
 * `decideToolApproval` for Bash tool calls.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

let TMP_DIR = "";
let ORIGINAL_DATA_DIR: string | undefined;

// Mock the database module — decideToolApproval consults
// lookupAllowlist which calls getDb(). We keep the schema minimal.
vi.mock("../../src/storage/db.js", () => {
	let mockDb: Database.Database | null = null;
	return {
		getDb: () => {
			if (!mockDb) {
				mockDb = new Database(":memory:");
				mockDb.exec(`
					CREATE TABLE IF NOT EXISTS approval_allowlist (
						id INTEGER PRIMARY KEY AUTOINCREMENT,
						user_id TEXT NOT NULL,
						tier TEXT NOT NULL,
						tool_key TEXT NOT NULL,
						scope TEXT NOT NULL,
						session_key TEXT,
						chat_id INTEGER NOT NULL,
						granted_at INTEGER NOT NULL,
						expires_at INTEGER,
						last_used_at INTEGER,
						UNIQUE(user_id, tool_key, scope)
					);
				`);
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

describe("pipeline ↔ exec-policy", () => {
	beforeEach(async () => {
		TMP_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-pipeline-exec-"));
		ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;
		process.env.TELCLAUDE_DATA_DIR = TMP_DIR;
		const { closeDb, getDb } = await import("../../src/storage/db.js");
		closeDb();
		getDb();
	});

	afterEach(async () => {
		const { closeDb } = await import("../../src/storage/db.js");
		closeDb();
		if (ORIGINAL_DATA_DIR === undefined) {
			delete process.env.TELCLAUDE_DATA_DIR;
		} else {
			process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
		}
		if (TMP_DIR && fs.existsSync(TMP_DIR)) {
			fs.rmSync(TMP_DIR, { recursive: true, force: true });
		}
		TMP_DIR = "";
	});

	it("safe-bin Bash shortcuts to allow in WRITE_LOCAL", async () => {
		const { decideToolApproval } = await import("../../src/security/pipeline.js");
		const d = decideToolApproval({
			userId: "tg:300",
			tier: "WRITE_LOCAL",
			toolName: "Bash",
			bashCommand: "grep foo",
			sessionKey: "tg:300",
			chatId: 300,
		});
		expect(d.decision).toBe("allow");
		expect(d.risk).toBe("low");
		expect(d.reason).toContain("safe-bin");
	});

	it("positional grep still requires approval", async () => {
		const { decideToolApproval } = await import("../../src/security/pipeline.js");
		const d = decideToolApproval({
			userId: "tg:301",
			tier: "WRITE_LOCAL",
			toolName: "Bash",
			bashCommand: "grep foo /etc/passwd",
			sessionKey: "tg:301",
			chatId: 301,
		});
		expect(d.decision).toBe("prompt");
		expect(d.risk).toBe("medium");
	});

	it("chat-specific glob shortcuts Bash to allow", async () => {
		const { decideToolApproval } = await import("../../src/security/pipeline.js");
		const { addExecPolicyGlob } = await import("../../src/security/exec-policy.js");
		addExecPolicyGlob(302, "npm test*");
		const d = decideToolApproval({
			userId: "tg:302",
			tier: "WRITE_LOCAL",
			toolName: "Bash",
			bashCommand: "npm test --watch",
			sessionKey: "tg:302",
			chatId: 302,
		});
		expect(d.decision).toBe("allow");
		expect(d.reason).toContain("allowlist match");
	});

	it("other chats' globs do not apply", async () => {
		const { decideToolApproval } = await import("../../src/security/pipeline.js");
		const { addExecPolicyGlob } = await import("../../src/security/exec-policy.js");
		addExecPolicyGlob(500, "npm test*");
		const d = decideToolApproval({
			userId: "tg:501",
			tier: "WRITE_LOCAL",
			toolName: "Bash",
			bashCommand: "npm test",
			sessionKey: "tg:501",
			chatId: 501,
		});
		expect(d.decision).toBe("prompt");
	});

	it("destructive Bash never shortcuts, even with a matching glob", async () => {
		const { decideToolApproval } = await import("../../src/security/pipeline.js");
		const { addExecPolicyGlob } = await import("../../src/security/exec-policy.js");
		addExecPolicyGlob(303, "rm*");
		const d = decideToolApproval({
			userId: "tg:303",
			tier: "WRITE_LOCAL",
			toolName: "Bash",
			bashCommand: "rm -rf /tmp/data",
			sessionKey: "tg:303",
			chatId: 303,
		});
		expect(d.risk).toBe("high");
		expect(d.decision).toBe("prompt-once");
	});

	it("safe-bin Bash still allow when chatId is omitted", async () => {
		const { decideToolApproval } = await import("../../src/security/pipeline.js");
		const d = decideToolApproval({
			userId: "tg:304",
			tier: "WRITE_LOCAL",
			toolName: "Bash",
			bashCommand: "wc -l",
			sessionKey: "tg:304",
		});
		expect(d.decision).toBe("allow");
	});

	it("non-Bash tools ignore exec-policy entirely", async () => {
		const { decideToolApproval } = await import("../../src/security/pipeline.js");
		const { addExecPolicyGlob } = await import("../../src/security/exec-policy.js");
		addExecPolicyGlob(305, "Write*");
		const d = decideToolApproval({
			userId: "tg:305",
			tier: "WRITE_LOCAL",
			toolName: "Write",
			sessionKey: "tg:305",
			chatId: 305,
		});
		// Write is medium-risk with no W1 grant → prompt.
		expect(d.decision).toBe("prompt");
	});

	it("admin bypass still wins over exec-policy", async () => {
		const { decideToolApproval } = await import("../../src/security/pipeline.js");
		const d = decideToolApproval({
			userId: "tg:306",
			tier: "FULL_ACCESS",
			toolName: "Bash",
			bashCommand: "rm -rf /",
			sessionKey: "tg:306",
			chatId: 306,
			isAdmin: true,
		});
		expect(d.decision).toBe("allow");
		expect(d.reason).toBe("admin bypass");
	});
});
