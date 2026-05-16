import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { validateCodexModel } from "../../src/agent-runtime/codex-work-unit.js";
import { listJobs } from "../../src/background/index.js";
import type { TelclaudeConfig } from "../../src/config/config.js";
import { resetDatabase } from "../../src/storage/db.js";
import { registerAllCardRenderers } from "../../src/telegram/cards/renderers/index.js";
import {
	parseCodexWorkUnitCommand,
	queueCodexWorkUnitCommand,
} from "../../src/telegram/control-command-actions.js";

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

function cfgForTier(tier: "READ_ONLY" | "WRITE_LOCAL" | "SOCIAL" | "FULL_ACCESS") {
	return {
		security: {
			permissions: {
				users: {
					"123": { tier },
				},
			},
		},
	} as TelclaudeConfig;
}

function fakeApi() {
	return {
		sendMessage: vi.fn(async () => ({ message_id: 1 })),
	};
}

describe("/codex Telegram command", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-codex-cmd-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		resetDatabase();
		registerAllCardRenderers();
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) {
			delete process.env.TELCLAUDE_DATA_DIR;
		} else {
			process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
		}
	});

	it("rejects READ_ONLY chats before queueing", async () => {
		const api = fakeApi();

		const result = await queueCodexWorkUnitCommand(api as never, {
			chatId: 123,
			actorScope: "user:123",
			rawArgs: "inspect the repo",
			cfg: cfgForTier("READ_ONLY"),
		});

		expect(result.callbackAlert).toBe(true);
		expect(api.sendMessage.mock.calls[0]?.[1]).toContain("READ_ONLY tier cannot queue Codex");
		expect(listJobs()).toHaveLength(0);
	});

	it("rejects SOCIAL chats before queueing", async () => {
		const api = fakeApi();

		const result = await queueCodexWorkUnitCommand(api as never, {
			chatId: 123,
			actorScope: "user:123",
			rawArgs: "inspect the repo",
			cfg: cfgForTier("SOCIAL"),
		});

		expect(result.callbackAlert).toBe(true);
		expect(api.sendMessage.mock.calls[0]?.[1]).toContain("SOCIAL tier cannot queue Codex");
		expect(listJobs()).toHaveLength(0);
	});

	it("rejects --write unless the chat has FULL_ACCESS", async () => {
		const api = fakeApi();

		const result = await queueCodexWorkUnitCommand(api as never, {
			chatId: 123,
			actorScope: "user:123",
			rawArgs: "--write inspect the repo",
			cfg: cfgForTier("WRITE_LOCAL"),
		});

		expect(result.callbackAlert).toBe(true);
		expect(api.sendMessage.mock.calls[0]?.[1]).toContain("--write requires FULL_ACCESS");
		expect(listJobs()).toHaveLength(0);
	});

	it("queues --write as workspace-write for FULL_ACCESS", async () => {
		const api = fakeApi();

		const result = await queueCodexWorkUnitCommand(api as never, {
			chatId: 123,
			threadId: 7,
			actorScope: "user:123",
			actorId: 456,
			rawArgs: "--write --cwd packages/api --model gpt-5.4 fix the failing test",
			cfg: cfgForTier("FULL_ACCESS"),
		});

		const [job] = listJobs();
		expect(result.callbackText).toBe(`Queued Codex job ${job?.shortId}`);
		expect(job?.userId).toBe("tg:456");
		expect(job?.threadId).toBe(7);
		expect(job?.payload).toMatchObject({
			kind: "codex-work-unit",
			prompt: "fix the failing test",
			cwd: "packages/api",
			model: "gpt-5.4",
			sandbox: "workspace-write",
		});
		expect(api.sendMessage.mock.calls[0]?.[1]).toContain(job?.shortId);
	});

	it("keeps FULL_ACCESS /codex read-only by default", async () => {
		const api = fakeApi();

		await queueCodexWorkUnitCommand(api as never, {
			chatId: 123,
			actorScope: "user:123",
			rawArgs: "review HEAD",
			cfg: cfgForTier("FULL_ACCESS"),
		});

		const [job] = listJobs();
		expect(job?.payload).toMatchObject({
			kind: "codex-work-unit",
			prompt: "review HEAD",
			sandbox: "read-only",
		});
	});

	it("rejects absolute and parent cwd values at parse time", () => {
		expect(() => parseCodexWorkUnitCommand("--cwd /tmp inspect")).toThrow(/relative path/);
		expect(() => parseCodexWorkUnitCommand("--cwd ../foo inspect")).toThrow(
			/cannot contain '\.\.'/,
		);
		expect(() => parseCodexWorkUnitCommand("--cwd foo/../bar inspect")).toThrow(
			/cannot contain '\.\.'/,
		);
	});

	it("rejects invalid model values through the shared Codex validator", async () => {
		expect(() => validateCodexModel("../bad")).toThrow(/codex model may only contain/);
		expect(() => validateCodexModel("gpt-5")).toThrow(/not supported/);

		const api = fakeApi();
		const result = await queueCodexWorkUnitCommand(api as never, {
			chatId: 123,
			actorScope: "user:123",
			rawArgs: "--model gpt-5 inspect",
			cfg: cfgForTier("WRITE_LOCAL"),
		});

		expect(result.callbackAlert).toBe(true);
		expect(api.sendMessage.mock.calls[0]?.[1]).toContain("not supported");
		expect(listJobs()).toHaveLength(0);
	});
});
