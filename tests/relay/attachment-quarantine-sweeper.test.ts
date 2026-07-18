import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	createAttachmentProcessorCapability,
	createAttachmentQuarantineStore,
	type QuarantineOwnerBinding,
} from "../../src/relay/attachment-quarantine-store.js";
import { startAttachmentQuarantineSweeper } from "../../src/relay/attachment-quarantine-sweeper.js";
import { closeDb, getDb } from "../../src/storage/db.js";

const OWNER: QuarantineOwnerBinding = {
	actorId: "household:whatsapp:parent-a",
	subjectUserId: "household:parent-a",
	bindingId: "parent-a",
	senderPrincipalId: "whatsapp:sender-a",
	conversationId: "whatsapp:conversation-a",
	conversationToken: "conversation-token-a",
};
const PNG = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

describe("attachment quarantine sweeper", () => {
	let tempDir: string;
	let quarantineDir: string;
	let nowMs: number;
	let originalDataDir: string | undefined;

	beforeEach(() => {
		vi.useFakeTimers();
		originalDataDir = process.env.TELCLAUDE_DATA_DIR;
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-quarantine-sweep-"));
		quarantineDir = path.join(tempDir, "attachment-quarantine");
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		nowMs = 1_000;
	});

	afterEach(() => {
		vi.useRealTimers();
		closeDb();
		if (originalDataDir === undefined) delete process.env.TELCLAUDE_DATA_DIR;
		else process.env.TELCLAUDE_DATA_DIR = originalDataDir;
		fs.rmSync(tempDir, { recursive: true, force: true });
	});

	it("cleans crash residue and expired rows on startup", () => {
		const store = createAttachmentQuarantineStore({ durable: true, now: () => nowMs });
		const ref = store.store({
			bytes: PNG,
			mediaType: "image/png",
			conversationToken: OWNER.conversationToken,
			owner: OWNER,
			accessClass: "media-processor",
			receivedAtMs: nowMs,
			ttlMs: 10,
		});
		fs.writeFileSync(path.join(quarantineDir, "crash-residue.bin"), PNG);
		fs.writeFileSync(path.join(quarantineDir, ".pending-crash-residue"), PNG);
		const mediaCrashDir = path.join(quarantineDir, ".pending-media-crash-residue");
		fs.mkdirSync(mediaCrashDir, { mode: 0o700 });
		fs.writeFileSync(path.join(mediaCrashDir, "derived.wav"), PNG, { mode: 0o600 });
		nowMs += 11;

		const handle = startAttachmentQuarantineSweeper({ store, intervalMs: 100 });
		expect(handle.startup).toEqual({ expired: 1, orphanedFilesDeleted: 3 });
		expect(fs.existsSync(mediaCrashDir)).toBe(false);
		expect(store.inspect(ref.quarantineId, OWNER)?.state).toBe("expired");
		expect(store.getDeletionReceipt(ref.quarantineId)?.reason).toBe("expired");
		handle.stop();
	});

	it("runs again on the bounded interval and stops cleanly", () => {
		const store = createAttachmentQuarantineStore({ durable: true, now: () => nowMs });
		const ref = store.store({
			bytes: PNG,
			mediaType: "image/png",
			conversationToken: OWNER.conversationToken,
			owner: OWNER,
			accessClass: "media-processor",
			receivedAtMs: nowMs,
			ttlMs: 10,
		});
		const onSweep = vi.fn();
		const handle = startAttachmentQuarantineSweeper({ store, intervalMs: 100, onSweep });
		nowMs += 11;
		vi.advanceTimersByTime(100);
		expect(store.inspect(ref.quarantineId, OWNER)?.state).toBe("expired");
		expect(onSweep).toHaveBeenCalledTimes(2);
		handle.stop();
		vi.advanceTimersByTime(100);
		expect(onSweep).toHaveBeenCalledTimes(2);
	});

	it("does not sweep an active processor workspace", () => {
		const capability = createAttachmentProcessorCapability();
		const store = createAttachmentQuarantineStore({
			durable: true,
			now: () => nowMs,
			processorCapability: capability,
		});
		const workspace = store.createProcessorTempDirectory(capability);
		if (!workspace) throw new Error("expected processor workspace");
		fs.writeFileSync(path.join(workspace.directoryPath, "derived.wav"), PNG);

		const handle = startAttachmentQuarantineSweeper({ store, intervalMs: 100 });
		expect(handle.startup.orphanedFilesDeleted).toBe(0);
		expect(fs.existsSync(workspace.directoryPath)).toBe(true);
		workspace.cleanup();
		expect(fs.existsSync(workspace.directoryPath)).toBe(false);
		handle.stop();
	});

	it("recreates an idempotent terminal receipt after a crash gap", () => {
		const first = createAttachmentQuarantineStore({ durable: true, now: () => nowMs });
		const ref = first.store({
			bytes: new Uint8Array([1, 2, 3]),
			mediaType: "image/png",
			conversationToken: OWNER.conversationToken,
			owner: OWNER,
			accessClass: "media-processor",
			receivedAtMs: nowMs,
		});
		const receipt = first.getDeletionReceipt(ref.quarantineId);
		if (!receipt) throw new Error("expected initial receipt");
		getDb()
			.prepare("DELETE FROM attachment_quarantine_deletion_receipts WHERE quarantine_id_hash = ?")
			.run(receipt.quarantineIdHash);
		closeDb();

		const restarted = createAttachmentQuarantineStore({ durable: true, now: () => nowMs });
		const handle = startAttachmentQuarantineSweeper({ store: restarted, intervalMs: 100 });
		expect(restarted.getDeletionReceipt(ref.quarantineId)).toEqual(receipt);
		handle.stop();
	});
});
