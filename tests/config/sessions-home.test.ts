import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

describe("home target storage", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-home-target-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		vi.resetModules();
		const { resetDatabase } = await import("../../src/storage/db.js");
		resetDatabase();
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) {
			delete process.env.TELCLAUDE_DATA_DIR;
		} else {
			process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
		}
	});

	it("stores unlinked chats under a tg: owner id", async () => {
		const { getHomeTarget, getHomeTargetForChat, setHomeTargetForChat } = await import(
			"../../src/config/sessions.js"
		);

		const stored = setHomeTargetForChat(42, undefined, 1_234);
		expect(stored.ownerId).toBe("tg:42");
		expect(getHomeTarget("tg:42")).toMatchObject({ chatId: 42, updatedAt: 1_234 });
		expect(getHomeTargetForChat(42)).toMatchObject({ chatId: 42, updatedAt: 1_234 });
	});

	it("resolves linked chats by local user id so home follows the user", async () => {
		const { consumeLinkCode, generateLinkCode } = await import("../../src/security/linking.js");
		const { getHomeTarget, getHomeTargetForChat, resolveHomeTargetOwnerId, setHomeTargetForChat } =
			await import("../../src/config/sessions.js");

		const code = generateLinkCode("alice");
		const linkResult = consumeLinkCode(code, 1001, "tester");
		expect(linkResult.success).toBe(true);

		const stored = setHomeTargetForChat(1001, 7, 2_345);
		expect(stored.ownerId).toBe("alice");
		expect(resolveHomeTargetOwnerId(1001)).toBe("alice");
		expect(getHomeTarget("alice")).toMatchObject({ chatId: 1001, threadId: 7 });
		expect(getHomeTargetForChat(1001)).toMatchObject({ chatId: 1001, threadId: 7 });
	});
});
