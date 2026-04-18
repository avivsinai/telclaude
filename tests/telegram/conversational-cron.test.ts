import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

describe("conversational cron", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-convo-cron-"));
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

	it("parses weekday schedule phrases into cron expressions", async () => {
		const { parseConversationalCronRequest } = await import(
			"../../src/telegram/conversational-cron.js"
		);
		expect(parseConversationalCronRequest("every weekday at 9am, check HN and post here")).toEqual({
			schedule: { kind: "cron", expr: "0 9 * * 1-5" },
			scheduleLabel: "weekdays at 09:00 UTC",
			prompt: "check HN and post here",
		});
	});

	it("rejects scheduling when the user tier is READ_ONLY", async () => {
		const { setHomeTargetForChat } = await import("../../src/config/sessions.js");
		const { READ_ONLY_CRON_MESSAGE, tryHandleConversationalCronRequest } = await import(
			"../../src/telegram/conversational-cron.js"
		);
		setHomeTargetForChat(50);

		const result = tryHandleConversationalCronRequest({
			body: "every weekday at 9am, check HN",
			chatId: 50,
			tier: "READ_ONLY",
		});

		expect(result).toEqual({
			handled: true,
			replyText: READ_ONLY_CRON_MESSAGE,
		});
	});

	it("creates a home-delivered agent cron job when parsing succeeds", async () => {
		const { getCronJob } = await import("../../src/cron/store.js");
		const { setHomeTargetForChat } = await import("../../src/config/sessions.js");
		const { tryHandleConversationalCronRequest } = await import(
			"../../src/telegram/conversational-cron.js"
		);
		setHomeTargetForChat(77, 3);

		const result = tryHandleConversationalCronRequest({
			body: "every weekday at 9am check HN and post here",
			chatId: 77,
			threadId: 3,
			tier: "WRITE_LOCAL",
			nowMs: Date.parse("2026-02-20T10:00:00.000Z"),
		});

		expect(result.handled).toBe(true);
		expect(result.replyText).toContain("Delivery target: chat 77 / topic 3");
		expect(result.job).toMatchObject({
			ownerId: "tg:77",
			deliveryTarget: { kind: "home" },
			action: { kind: "agent-prompt", prompt: "check HN and post here" },
			schedule: { kind: "cron", expr: "0 9 * * 1-5" },
		});
		expect(getCronJob(result.job!.id)).toMatchObject({
			ownerId: "tg:77",
			deliveryTarget: { kind: "home" },
		});
	});

	it("falls back to the normal chat path when the phrase is not parseable", async () => {
		const { tryHandleConversationalCronRequest } = await import(
			"../../src/telegram/conversational-cron.js"
		);
		expect(
			tryHandleConversationalCronRequest({
				body: "could you maybe remind me someday about HN",
				chatId: 88,
				tier: "WRITE_LOCAL",
			}),
		).toEqual({ handled: false });
	});
});
