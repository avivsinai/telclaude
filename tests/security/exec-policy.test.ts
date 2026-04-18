/**
 * Tests for W8 exec-policy: safe-bin catalog, glob matcher,
 * per-chat allowlist persistence.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Tests redirect the policy file to a per-test temp dir via
// TELCLAUDE_DATA_DIR, which resolveExecPolicyPath() reads at call time.
let TMP_DIR = "";
let ORIGINAL_DATA_DIR: string | undefined;

vi.mock("../../src/logging.js", () => ({
	getChildLogger: () => ({
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		debug: vi.fn(),
	}),
}));

describe("exec-policy", () => {
	beforeEach(() => {
		TMP_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-exec-policy-"));
		ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;
		process.env.TELCLAUDE_DATA_DIR = TMP_DIR;
	});

	afterEach(() => {
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

	// ───────────────────────────────────────────────────────────────────────
	// Safe-bin catalog
	// ───────────────────────────────────────────────────────────────────────

	describe("isSafeBinCommand", () => {
		it("allows stdin-only grep", async () => {
			const { isSafeBinCommand } = await import("../../src/security/exec-policy.js");
			const result = isSafeBinCommand("grep foo");
			expect(result.safe).toBe(true);
			if (result.safe) {
				expect(result.binary).toBe("grep");
			}
		});

		it("allows all core safe bins without positional args", async () => {
			const { isSafeBinCommand } = await import("../../src/security/exec-policy.js");
			const commands = [
				"cut -d, -f1",
				"head -n 10",
				"tail -n 20",
				"wc -l",
				"grep -i foo",
				"sort -r",
				"uniq -c",
				"jq .",
				"rg foo",
			];
			for (const cmd of commands) {
				const result = isSafeBinCommand(cmd);
				expect(result.safe, `expected ${cmd} to be safe`).toBe(true);
			}
		});

		it("rejects grep with positional path argument", async () => {
			const { isSafeBinCommand } = await import("../../src/security/exec-policy.js");
			const result = isSafeBinCommand("grep foo /etc/passwd");
			expect(result.safe).toBe(false);
		});

		it("rejects cat with positional path", async () => {
			const { isSafeBinCommand } = await import("../../src/security/exec-policy.js");
			const result = isSafeBinCommand("cat /etc/passwd");
			expect(result.safe).toBe(false);
		});

		it("rejects commands with redirects", async () => {
			const { isSafeBinCommand } = await import("../../src/security/exec-policy.js");
			expect(isSafeBinCommand("grep foo > out.txt").safe).toBe(false);
			expect(isSafeBinCommand("grep foo >> out.txt").safe).toBe(false);
			expect(isSafeBinCommand("grep foo < input.txt").safe).toBe(false);
		});

		it("rejects commands with pipes", async () => {
			const { isSafeBinCommand } = await import("../../src/security/exec-policy.js");
			// Even a two-safe-bin pipe must bail out — we only inspect one
			// command at a time.
			expect(isSafeBinCommand("grep foo | wc -l").safe).toBe(false);
		});

		it("rejects commands with subshells, substitution, backticks", async () => {
			const { isSafeBinCommand } = await import("../../src/security/exec-policy.js");
			expect(isSafeBinCommand("grep $(whoami)").safe).toBe(false);
			expect(isSafeBinCommand("grep `whoami`").safe).toBe(false);
			expect(isSafeBinCommand("(grep foo)").safe).toBe(false);
		});

		it("rejects commands with logical operators", async () => {
			const { isSafeBinCommand } = await import("../../src/security/exec-policy.js");
			expect(isSafeBinCommand("grep foo && echo ok").safe).toBe(false);
			expect(isSafeBinCommand("grep foo || true").safe).toBe(false);
			expect(isSafeBinCommand("grep foo; echo ok").safe).toBe(false);
		});

		it("rejects unknown binaries", async () => {
			const { isSafeBinCommand } = await import("../../src/security/exec-policy.js");
			expect(isSafeBinCommand("ls -la").safe).toBe(false);
			expect(isSafeBinCommand("npm test").safe).toBe(false);
		});

		it("rejects destructive patterns even for safe-bin names", async () => {
			const { isSafeBinCommand } = await import("../../src/security/exec-policy.js");
			// Safe-bin name shouldn't help, but destructive pattern wins.
			expect(isSafeBinCommand("sudo grep foo").safe).toBe(false);
		});

		it("rejects jq --in-place", async () => {
			const { isSafeBinCommand } = await import("../../src/security/exec-policy.js");
			expect(isSafeBinCommand("jq --in-place .").safe).toBe(false);
			expect(isSafeBinCommand("jq -i .").safe).toBe(false);
		});

		it("accepts env assignments before a safe bin", async () => {
			const { isSafeBinCommand } = await import("../../src/security/exec-policy.js");
			expect(isSafeBinCommand("LC_ALL=C grep foo").safe).toBe(true);
		});

		it("rejects empty input", async () => {
			const { isSafeBinCommand } = await import("../../src/security/exec-policy.js");
			expect(isSafeBinCommand("").safe).toBe(false);
			expect(isSafeBinCommand("   ").safe).toBe(false);
			expect(isSafeBinCommand(undefined).safe).toBe(false);
		});

		it("rejects commands longer than 2048 chars", async () => {
			const { isSafeBinCommand } = await import("../../src/security/exec-policy.js");
			const long = `grep ${"a".repeat(2100)}`;
			expect(isSafeBinCommand(long).safe).toBe(false);
		});
	});

	// ───────────────────────────────────────────────────────────────────────
	// Glob matcher
	// ───────────────────────────────────────────────────────────────────────

	describe("matchGlob", () => {
		it("matches a literal pattern", async () => {
			const { matchGlob } = await import("../../src/security/exec-policy.js");
			expect(matchGlob("npm test", "npm test")).toBe(true);
			expect(matchGlob("npm test", "npm test --watch")).toBe(false);
		});

		it("supports * wildcard", async () => {
			const { matchGlob } = await import("../../src/security/exec-policy.js");
			expect(matchGlob("npm test*", "npm test")).toBe(true);
			expect(matchGlob("npm test*", "npm test --watch")).toBe(true);
			expect(matchGlob("npm *", "npm run build")).toBe(true);
			expect(matchGlob("npm *", "yarn run build")).toBe(false);
		});

		it("supports ? wildcard", async () => {
			const { matchGlob } = await import("../../src/security/exec-policy.js");
			expect(matchGlob("l?", "ls")).toBe(true);
			expect(matchGlob("l?", "lss")).toBe(false);
		});

		it("supports character classes", async () => {
			const { matchGlob } = await import("../../src/security/exec-policy.js");
			expect(matchGlob("[lh]s", "ls")).toBe(true);
			expect(matchGlob("[lh]s", "hs")).toBe(true);
			expect(matchGlob("[lh]s", "ms")).toBe(false);
		});

		it("escapes regex metacharacters in literal parts", async () => {
			const { matchGlob } = await import("../../src/security/exec-policy.js");
			expect(matchGlob("a.b", "a.b")).toBe(true);
			expect(matchGlob("a.b", "axb")).toBe(false);
			expect(matchGlob("a+b", "a+b")).toBe(true);
			expect(matchGlob("a+b", "ab")).toBe(false);
		});
	});

	// ───────────────────────────────────────────────────────────────────────
	// Persistence
	// ───────────────────────────────────────────────────────────────────────

	describe("persistence", () => {
		it("round-trips through the policy file", async () => {
			const { addExecPolicyGlob, listExecPolicy, loadExecPolicy } = await import(
				"../../src/security/exec-policy.js"
			);
			addExecPolicyGlob(12345, "npm test*");
			addExecPolicyGlob(12345, "pnpm build*");
			const entries = listExecPolicy({ chatId: 12345 });
			expect(entries).toHaveLength(1);
			expect(entries[0].globs).toEqual(["npm test*", "pnpm build*"]);

			const file = loadExecPolicy();
			expect(file.chats["12345"].globs).toEqual(["npm test*", "pnpm build*"]);
		});

		it("writes atomically (temp file removed after rename)", async () => {
			const { addExecPolicyGlob, resolveExecPolicyPath } = await import(
				"../../src/security/exec-policy.js"
			);
			addExecPolicyGlob(99, "grep foo*");
			const policyPath = resolveExecPolicyPath();
			// Confirm no leftover temp files in the dir.
			const leftovers = fs
				.readdirSync(path.dirname(policyPath))
				.filter((f) => f.startsWith("exec-policy.json.tmp"));
			expect(leftovers).toEqual([]);
			// File exists with mode 0600-ish (check it's readable; skip
			// strict mode check on platforms with umask surprises).
			expect(fs.existsSync(policyPath)).toBe(true);
		});

		it("is idempotent on add", async () => {
			const { addExecPolicyGlob } = await import("../../src/security/exec-policy.js");
			expect(addExecPolicyGlob(1, "foo*")).toBe(true);
			expect(addExecPolicyGlob(1, "foo*")).toBe(false);
		});

		it("revokes a single glob", async () => {
			const { addExecPolicyGlob, revokeExecPolicyGlob, listExecPolicy } = await import(
				"../../src/security/exec-policy.js"
			);
			addExecPolicyGlob(1, "a*");
			addExecPolicyGlob(1, "b*");
			expect(revokeExecPolicyGlob(1, "a*")).toBe(1);
			const entries = listExecPolicy({ chatId: 1 });
			expect(entries[0]?.globs).toEqual(["b*"]);
		});

		it("revokes the whole chat when glob omitted", async () => {
			const { addExecPolicyGlob, revokeExecPolicyGlob, listExecPolicy } = await import(
				"../../src/security/exec-policy.js"
			);
			addExecPolicyGlob(2, "a*");
			addExecPolicyGlob(2, "b*");
			expect(revokeExecPolicyGlob(2)).toBe(2);
			expect(listExecPolicy({ chatId: 2 })).toEqual([]);
		});

		it("revoke returns 0 when chat has no entries", async () => {
			const { revokeExecPolicyGlob } = await import("../../src/security/exec-policy.js");
			expect(revokeExecPolicyGlob(99999)).toBe(0);
			expect(revokeExecPolicyGlob(99999, "a*")).toBe(0);
		});

		it("treats malformed policy file as empty", async () => {
			const { loadExecPolicy, resolveExecPolicyPath } = await import(
				"../../src/security/exec-policy.js"
			);
			const policyPath = resolveExecPolicyPath();
			fs.mkdirSync(path.dirname(policyPath), { recursive: true });
			fs.writeFileSync(policyPath, "not valid json");
			const file = loadExecPolicy();
			expect(file.chats).toEqual({});
		});

		it("caps glob length", async () => {
			const { addExecPolicyGlob } = await import("../../src/security/exec-policy.js");
			expect(() => addExecPolicyGlob(1, "x".repeat(500))).toThrow(/exceeds/);
		});
	});

	// ───────────────────────────────────────────────────────────────────────
	// checkExecPolicy — integration of all layers
	// ───────────────────────────────────────────────────────────────────────

	describe("checkExecPolicy", () => {
		it("allows safe bins regardless of chat config", async () => {
			const { checkExecPolicy } = await import("../../src/security/exec-policy.js");
			const result = checkExecPolicy({ chatId: 42, command: "grep foo" });
			expect(result.decision).toBe("allow");
			if (result.decision === "allow") {
				expect(result.safeBin).toBe("grep");
			}
		});

		it("prompts for positional grep even with no allowlist", async () => {
			const { checkExecPolicy } = await import("../../src/security/exec-policy.js");
			const result = checkExecPolicy({
				chatId: 42,
				command: "grep foo /etc/passwd",
			});
			expect(result.decision).toBe("prompt");
		});

		it("allows a chat-specific glob match", async () => {
			const { addExecPolicyGlob, checkExecPolicy } = await import(
				"../../src/security/exec-policy.js"
			);
			addExecPolicyGlob(42, "npm test*");
			const result = checkExecPolicy({
				chatId: 42,
				command: "npm test --watch",
			});
			expect(result.decision).toBe("allow");
			if (result.decision === "allow") {
				expect(result.matchedGlob).toBe("npm test*");
			}
		});

		it("does not apply another chat's allowlist", async () => {
			const { addExecPolicyGlob, checkExecPolicy } = await import(
				"../../src/security/exec-policy.js"
			);
			addExecPolicyGlob(42, "npm test*");
			const result = checkExecPolicy({ chatId: 7, command: "npm test" });
			expect(result.decision).toBe("prompt");
		});

		it("never shortcuts destructive commands", async () => {
			const { addExecPolicyGlob, checkExecPolicy } = await import(
				"../../src/security/exec-policy.js"
			);
			addExecPolicyGlob(42, "rm*");
			const result = checkExecPolicy({ chatId: 42, command: "rm -rf /tmp" });
			expect(result.decision).toBe("prompt");
		});

		it("accepts missing chatId (safe-bin only)", async () => {
			const { checkExecPolicy } = await import("../../src/security/exec-policy.js");
			const ok = checkExecPolicy({ chatId: null, command: "wc -l" });
			expect(ok.decision).toBe("allow");
			const miss = checkExecPolicy({ chatId: null, command: "npm test" });
			expect(miss.decision).toBe("prompt");
		});
	});

	// ───────────────────────────────────────────────────────────────────────
	// deriveGlobFromCommand — used by the W1 integration hook
	// ───────────────────────────────────────────────────────────────────────

	describe("deriveGlobFromCommand", () => {
		it("derives glob with first positional arg", async () => {
			const { deriveGlobFromCommand } = await import(
				"../../src/security/exec-policy.js"
			);
			expect(deriveGlobFromCommand("npm test --watch")).toBe("npm test*");
			expect(deriveGlobFromCommand("pnpm build")).toBe("pnpm build*");
		});

		it("derives glob with just the binary when first arg is a flag", async () => {
			const { deriveGlobFromCommand } = await import(
				"../../src/security/exec-policy.js"
			);
			expect(deriveGlobFromCommand("grep -i foo")).toBe("grep*");
		});

		it("returns null for shell metacharacters", async () => {
			const { deriveGlobFromCommand } = await import(
				"../../src/security/exec-policy.js"
			);
			expect(deriveGlobFromCommand("grep foo | wc")).toBe(null);
		});

		it("strips env assignments", async () => {
			const { deriveGlobFromCommand } = await import(
				"../../src/security/exec-policy.js"
			);
			expect(deriveGlobFromCommand("FOO=1 npm test")).toBe("npm test*");
		});

		it("returns null for empty input", async () => {
			const { deriveGlobFromCommand } = await import(
				"../../src/security/exec-policy.js"
			);
			expect(deriveGlobFromCommand("")).toBe(null);
			expect(deriveGlobFromCommand("   ")).toBe(null);
		});
	});

	// ───────────────────────────────────────────────────────────────────────
	// recordAlwaysFromAllowlist — pending W1 merge wiring
	// ───────────────────────────────────────────────────────────────────────

	describe("recordAlwaysFromAllowlist", () => {
		it("records a safe command as a glob", async () => {
			const { recordAlwaysFromAllowlist, listExecPolicy } = await import(
				"../../src/security/exec-policy.js"
			);
			recordAlwaysFromAllowlist({ chatId: 42, bashCommand: "npm test --watch" });
			const entries = listExecPolicy({ chatId: 42 });
			expect(entries[0]?.globs).toEqual(["npm test*"]);
		});

		it("refuses to promote destructive commands", async () => {
			const { recordAlwaysFromAllowlist, listExecPolicy } = await import(
				"../../src/security/exec-policy.js"
			);
			recordAlwaysFromAllowlist({ chatId: 42, bashCommand: "rm -rf /" });
			expect(listExecPolicy({ chatId: 42 })).toEqual([]);
		});

		it("no-ops on empty command", async () => {
			const { recordAlwaysFromAllowlist, listExecPolicy } = await import(
				"../../src/security/exec-policy.js"
			);
			recordAlwaysFromAllowlist({ chatId: 42, bashCommand: "" });
			expect(listExecPolicy({ chatId: 42 })).toEqual([]);
		});
	});
});
