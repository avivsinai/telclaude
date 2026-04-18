import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

let resetDatabase: typeof import("../../src/storage/db.js").resetDatabase;
let createApproval: typeof import("../../src/security/approvals.js").createApproval;
let getPendingApprovalsForChat: typeof import("../../src/security/approvals.js").getPendingApprovalsForChat;
let resolvePendingToolApproval: typeof import("../../src/security/approvals.js").resolvePendingToolApproval;
let waitForToolApproval: typeof import("../../src/security/approval-wait.js").waitForToolApproval;

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

describe("waitForToolApproval", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-approval-wait-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;

		vi.resetModules();
		const approvals = await import("../../src/security/approvals.js");
		({ createApproval, getPendingApprovalsForChat, resolvePendingToolApproval } = approvals);
		({ waitForToolApproval } = await import("../../src/security/approval-wait.js"));
		({ resetDatabase } = await import("../../src/storage/db.js"));
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

	it("resolves when a card approval arrives", async () => {
		const { nonce } = createApproval({
			requestId: "tool-1",
			chatId: 1,
			tier: "WRITE_LOCAL",
			body: "Claude wants to edit README.md",
			from: "tg:1",
			to: "tool-approval",
			messageId: "tool-1",
			observerClassification: "ALLOW",
			observerConfidence: 1,
			riskTier: "medium",
			toolKey: "Edit",
			sessionKey: "tg:1",
		});

		const waiting = waitForToolApproval({ nonce, chatId: 1, timeoutMs: 1_000 });
		expect(
			resolvePendingToolApproval(nonce, {
				status: "approved",
				scope: "session",
				source: "card",
			}),
		).toBe(true);

		await expect(waiting).resolves.toMatchObject({
			status: "approved",
			scope: "session",
			source: "card",
		});
	});

	it("times out and clears the pending approval row", async () => {
		const { nonce } = createApproval({
			requestId: "tool-2",
			chatId: 2,
			tier: "WRITE_LOCAL",
			body: "Claude wants to write notes.txt",
			from: "tg:2",
			to: "tool-approval",
			messageId: "tool-2",
			observerClassification: "ALLOW",
			observerConfidence: 1,
			riskTier: "medium",
			toolKey: "Write",
			sessionKey: "tg:2",
		});

		await expect(waitForToolApproval({ nonce, chatId: 2, timeoutMs: 10 })).resolves.toMatchObject({
			status: "denied",
			source: "timeout",
		});
		expect(getPendingApprovalsForChat(2)).toHaveLength(0);
	});

	it("aborts cleanly and removes the pending approval", async () => {
		const { nonce } = createApproval({
			requestId: "tool-3",
			chatId: 3,
			tier: "WRITE_LOCAL",
			body: "Claude wants to run Bash",
			from: "tg:3",
			to: "tool-approval",
			messageId: "tool-3",
			observerClassification: "ALLOW",
			observerConfidence: 1,
			riskTier: "high",
			toolKey: "Bash",
			sessionKey: "tg:3",
		});
		const controller = new AbortController();
		const waiting = waitForToolApproval({
			nonce,
			chatId: 3,
			timeoutMs: 1_000,
			signal: controller.signal,
		});

		controller.abort();

		await expect(waiting).resolves.toMatchObject({
			status: "denied",
			source: "abort",
		});
		expect(getPendingApprovalsForChat(3)).toHaveLength(0);
	});
});
