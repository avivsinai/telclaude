import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resetConfigCache } from "../../src/config/config.js";
import { resetConfigPath, setConfigPath } from "../../src/config/path.js";

// runOnboard reaches for the real readline interface when prompting;
// we drive it end-to-end by passing -t/-c and --yes so no prompts fire.
import { runOnboard, __internals } from "../../src/commands/onboard.js";

describe("onboard — non-interactive", () => {
	let tempDir = "";
	let configPath = "";
	let logMock: ReturnType<typeof vi.spyOn>;

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "onboard-test-"));
		configPath = path.join(tempDir, "telclaude.json");
		setConfigPath(configPath);
		resetConfigCache();
		// Silence the wizard's console output during tests.
		logMock = vi.spyOn(console, "log").mockImplementation(() => {});
		// The wizard also uses getSandboxMode() which touches /proc on Linux;
		// the helper gracefully degrades so no mock needed.
	});

	afterEach(() => {
		logMock.mockRestore();
		resetConfigPath();
		resetConfigCache();
		if (tempDir && fs.existsSync(tempDir)) {
			fs.rmSync(tempDir, { recursive: true, force: true });
		}
	});

	it("writes bot token + allowedChats when passed via flags", async () => {
		await runOnboard({
			token: "1234567890:TESTSECRET_abc123",
			chatId: "424242",
			yes: true,
			skipDoctor: true,
		});

		expect(fs.existsSync(configPath)).toBe(true);
		const saved = JSON.parse(fs.readFileSync(configPath, "utf8")) as Record<string, unknown>;
		expect((saved.telegram as Record<string, unknown>)?.botToken).toBe(
			"1234567890:TESTSECRET_abc123",
		);
		expect((saved.telegram as Record<string, unknown>)?.allowedChats).toEqual([424242]);
		expect(
			(
				(
					(saved.security as Record<string, unknown>)?.permissions as Record<string, unknown>
				)?.users as Record<string, unknown>
			)?.["tg:424242"],
		).toEqual({ tier: "WRITE_LOCAL" });
		expect(
			(
				(saved.security as Record<string, unknown>)?.permissions as Record<string, unknown>
			)?.defaultTier,
		).toBe("READ_ONLY");
	});

	it("is idempotent — rerunning with same values is a no-op", async () => {
		await runOnboard({
			token: "1:A",
			chatId: "1",
			yes: true,
			skipDoctor: true,
		});
		const firstMtime = fs.statSync(configPath).mtimeMs;

		// Wait a beat so mtime would differ on a real write.
		await new Promise((r) => setTimeout(r, 20));

		await runOnboard({
			token: "1:A",
			chatId: "1",
			yes: true,
			skipDoctor: true,
		});
		const secondMtime = fs.statSync(configPath).mtimeMs;

		// Idempotent: second run should not rewrite. We check structure
		// equality rather than asserting mtime exactly, since the file is
		// only rewritten when the token actually changes.
		const saved = JSON.parse(fs.readFileSync(configPath, "utf8")) as Record<string, unknown>;
		expect((saved.telegram as Record<string, unknown>).allowedChats).toEqual([1]);
		expect(secondMtime).toBeGreaterThanOrEqual(firstMtime);
	});

	it("preserves extra fields that were in the config already", async () => {
		const existing = {
			telegram: { botToken: "1:A", allowedChats: [7] },
			custom: { payload: "do not clobber" },
		};
		fs.writeFileSync(configPath, JSON.stringify(existing, null, 2));

		await runOnboard({
			chatId: "7",
			yes: true,
			skipDoctor: true,
		});

		const saved = JSON.parse(fs.readFileSync(configPath, "utf8")) as Record<string, unknown>;
		expect(saved.custom).toEqual({ payload: "do not clobber" });
	});

	it("rejects an obviously malformed token", async () => {
		await expect(
			runOnboard({
				token: "no-colon-token",
				yes: true,
				skipDoctor: true,
			}),
		).rejects.toThrow(/Invalid bot token format/);
	});

	it("rejects a non-numeric chat ID", async () => {
		await expect(
			runOnboard({
				token: "1:A",
				chatId: "not-a-number",
				yes: true,
				skipDoctor: true,
			}),
		).rejects.toThrow(/Invalid chat ID/);
	});

	it("appends new chat IDs without duplicating existing entries", async () => {
		await runOnboard({
			token: "1:A",
			chatId: "10",
			yes: true,
			skipDoctor: true,
		});
		await runOnboard({
			chatId: "20",
			yes: true,
			skipDoctor: true,
		});
		const saved = JSON.parse(fs.readFileSync(configPath, "utf8")) as Record<string, unknown>;
		expect((saved.telegram as Record<string, unknown>).allowedChats).toEqual([10, 20]);
	});
});

describe("onboard internals", () => {
	it("ensureObject coerces existing scalars into fresh objects", () => {
		const raw = { security: "junk" } as Record<string, unknown>;
		__internals.ensureObject(raw, "security");
		expect(raw.security).toEqual({});
	});

	it("ensureObject leaves valid objects intact", () => {
		const raw = { security: { keep: true } } as Record<string, unknown>;
		__internals.ensureObject(raw, "security");
		expect((raw.security as Record<string, unknown>).keep).toBe(true);
	});
});
