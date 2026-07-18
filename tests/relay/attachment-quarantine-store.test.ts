import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	createAttachmentProcessorCapability,
	createAttachmentQuarantineStore,
	QUARANTINE_HARD_TTL_MS,
	QUARANTINE_MAX_BYTES,
	type QuarantineOwnerBinding,
} from "../../src/relay/attachment-quarantine-store.js";
import { closeDb, getDb } from "../../src/storage/db.js";

const OWNER: QuarantineOwnerBinding = {
	actorId: "household:whatsapp:parent-a",
	subjectUserId: "household:parent-a",
	bindingId: "parent-a",
	senderPrincipalId: "whatsapp:sender-a",
	conversationId: "whatsapp:conversation-a",
	conversationToken: "conversation-token-a",
};

const OTHER_OWNER: QuarantineOwnerBinding = {
	...OWNER,
	actorId: "household:whatsapp:parent-b",
	subjectUserId: "household:parent-b",
	bindingId: "parent-b",
	senderPrincipalId: "whatsapp:sender-b",
};

const PNG = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

describe("durable attachment quarantine lifecycle", () => {
	let tempDir: string;
	let nowMs: number;
	let originalDataDir: string | undefined;

	beforeEach(() => {
		originalDataDir = process.env.TELCLAUDE_DATA_DIR;
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-quarantine-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		nowMs = 10_000;
	});

	afterEach(() => {
		closeDb();
		if (originalDataDir === undefined) delete process.env.TELCLAUDE_DATA_DIR;
		else process.env.TELCLAUDE_DATA_DIR = originalDataDir;
		fs.rmSync(tempDir, { recursive: true, force: true });
	});

	it("persists pending state and restores it after restart", () => {
		const capability = createAttachmentProcessorCapability();
		const first = createAttachmentQuarantineStore({
			durable: true,
			now: () => nowMs,
			processorCapability: capability,
		});
		const ref = first.store(mediaInput());
		expect(ref.scanState).toBe("pending");
		expect(first.inspect(ref.quarantineId, OWNER)?.state).toBe("pending");

		closeDb();
		const restarted = createAttachmentQuarantineStore({
			durable: true,
			now: () => nowMs,
			processorCapability: capability,
		});
		expect(restarted.inspect(ref.quarantineId, OWNER)?.state).toBe("pending");
		expect(restarted.inspect(ref.quarantineId, OTHER_OWNER)).toBeNull();
	});

	it("moves pending exactly once to clean or blocked", () => {
		const store = createAttachmentQuarantineStore({ durable: true, now: () => nowMs });
		const clean = store.store(mediaInput());
		expect(store.recordScanResult(clean.quarantineId, OWNER, "clean")?.state).toBe("clean");
		expect(store.recordScanResult(clean.quarantineId, OWNER, "blocked")).toBeNull();

		const blocked = store.store(mediaInput());
		expect(store.recordScanResult(blocked.quarantineId, OWNER, "blocked")?.state).toBe("blocked");
		expect(store.inspect(blocked.quarantineId, OWNER)?.hasBytes).toBe(false);
		expect(store.getDeletionReceipt(blocked.quarantineId)?.reason).toBe("scan_blocked");
	});

	it("blocks supplied MIME spoofing without exposing bytes", () => {
		const store = createAttachmentQuarantineStore({ durable: true, now: () => nowMs });
		const ref = store.store({ ...mediaInput(), mediaType: "application/pdf" });
		expect(ref.scanState).toBe("blocked");
		expect(ref.mediaType).toBe("image/png");
		expect(store.inspect(ref.quarantineId, OWNER)?.state).toBe("blocked");
		expect(store.getDeletionReceipt(ref.quarantineId)?.reason).toBe("mime_mismatch");
	});

	it("fails unreadable input closed with a content-free receipt", () => {
		const store = createAttachmentQuarantineStore({ durable: true, now: () => nowMs });
		const ref = store.store({ ...mediaInput(), bytes: new Uint8Array([1, 2, 3]) });
		expect(ref.scanState).toBe("blocked");
		const receipt = store.getDeletionReceipt(ref.quarantineId);
		expect(receipt).toMatchObject({ reason: "unsupported_type" });
		expect(JSON.stringify(receipt)).not.toContain("attachment-quarantine");
		expect(JSON.stringify(receipt)).not.toContain(ref.quarantineId);
		expect(
			getDb()
				.prepare(
					"SELECT conversation_token, byte_path FROM attachment_quarantine WHERE quarantine_id = ?",
				)
				.get(ref.quarantineId),
		).toEqual({ conversation_token: "", byte_path: null });
	});

	it("rejects oversize bytes before persistence", () => {
		const store = createAttachmentQuarantineStore({ durable: true, now: () => nowMs });
		expect(() =>
			store.store({ ...mediaInput(), bytes: new Uint8Array(QUARANTINE_MAX_BYTES + 1) }),
		).toThrow(/exceeds cap/);
		expect(
			(
				getDb().prepare("SELECT count(*) AS count FROM attachment_quarantine").get() as {
					count: number;
				}
			).count,
		).toBe(0);
	});

	it("leases clean bytes only to the configured processor capability and owner", () => {
		const capability = createAttachmentProcessorCapability();
		const wrongCapability = createAttachmentProcessorCapability();
		const store = createAttachmentQuarantineStore({
			durable: true,
			now: () => nowMs,
			processorCapability: capability,
		});
		const ref = store.store(mediaInput());
		store.recordScanResult(ref.quarantineId, OWNER, "clean");

		expect(
			store.resolve(ref.quarantineId, { conversationToken: OWNER.conversationToken }),
		).toBeNull();
		expect(store.leaseForProcessing(ref.quarantineId, OWNER, wrongCapability)).toBeNull();
		expect(store.leaseForProcessing(ref.quarantineId, OTHER_OWNER, capability)).toBeNull();
		const lease = store.leaseForProcessing(ref.quarantineId, OWNER, capability);
		expect(lease?.bytes).toEqual(PNG);
		expect(store.leaseForProcessing(ref.quarantineId, OWNER, capability)).toBeNull();
	});

	it("completes a lease once and makes deletion receipt creation idempotent", () => {
		const capability = createAttachmentProcessorCapability();
		const store = createAttachmentQuarantineStore({
			durable: true,
			now: () => nowMs,
			processorCapability: capability,
		});
		const ref = store.store(mediaInput());
		store.recordScanResult(ref.quarantineId, OWNER, "clean");
		const lease = store.leaseForProcessing(ref.quarantineId, OWNER, capability);
		if (!lease) throw new Error("expected processor lease");
		const first = store.completeProcessing(lease, OWNER, capability);
		const second = store.completeProcessing(lease, OWNER, capability);
		expect(first?.state).toBe("deleted");
		expect(second).toBeNull();
		const receipt = store.getDeletionReceipt(ref.quarantineId);
		expect(receipt).toEqual(store.getDeletionReceipt(ref.quarantineId));
		expect(receipt?.reason).toBe("processed");

		closeDb();
		const restarted = createAttachmentQuarantineStore({ durable: true, now: () => nowMs });
		expect(restarted.getDeletionReceipt(ref.quarantineId)).toEqual(receipt);
	});

	it("blocks an unreadable clean object and records deletion without leaking its path", () => {
		const capability = createAttachmentProcessorCapability();
		const store = createAttachmentQuarantineStore({
			durable: true,
			now: () => nowMs,
			processorCapability: capability,
		});
		const ref = store.store(mediaInput());
		store.recordScanResult(ref.quarantineId, OWNER, "clean");
		const quarantineDir = path.join(tempDir, "attachment-quarantine");
		const storedFile = fs.readdirSync(quarantineDir).find((name) => name.endsWith(".bin"));
		if (!storedFile) throw new Error("expected durable quarantine bytes");
		fs.unlinkSync(path.join(quarantineDir, storedFile));

		expect(store.leaseForProcessing(ref.quarantineId, OWNER, capability)).toBeNull();
		expect(store.inspect(ref.quarantineId, OWNER)?.state).toBe("blocked");
		const receipt = store.getDeletionReceipt(ref.quarantineId);
		expect(receipt?.reason).toBe("unreadable");
		expect(JSON.stringify(receipt)).not.toContain(tempDir);
	});

	it("expires pending and clean bytes at the received-at hard deadline", () => {
		const store = createAttachmentQuarantineStore({ durable: true, now: () => nowMs });
		const pending = store.store({ ...mediaInput(), ttlMs: 50 });
		const clean = store.store({ ...mediaInput(), ttlMs: 50 });
		store.recordScanResult(clean.quarantineId, OWNER, "clean");
		nowMs += 51;
		expect(store.sweepExpired()).toMatchObject({ expired: 2 });
		expect(store.inspect(pending.quarantineId, OWNER)?.state).toBe("expired");
		expect(store.inspect(clean.quarantineId, OWNER)?.state).toBe("expired");
		expect(store.getDeletionReceipt(pending.quarantineId)?.reason).toBe("expired");
	});

	it("never extends raw retention beyond 24 hours from receipt", () => {
		const store = createAttachmentQuarantineStore({ durable: true, now: () => nowMs });
		const ref = store.store({ ...mediaInput(), ttlMs: QUARANTINE_HARD_TTL_MS * 2 });
		nowMs += QUARANTINE_HARD_TTL_MS;
		expect(store.sweepExpired().expired).toBe(1);
		expect(store.inspect(ref.quarantineId, OWNER)?.state).toBe("expired");
	});

	it("exposes an owner deletion-request hook without retaining content", () => {
		const store = createAttachmentQuarantineStore({ durable: true, now: () => nowMs });
		const ref = store.store(mediaInput());
		expect(store.deleteForOwner(ref.quarantineId, OTHER_OWNER)).toBeNull();
		expect(store.deleteForOwner(ref.quarantineId, OWNER)?.state).toBe("deleted");
		expect(store.getDeletionReceipt(ref.quarantineId)?.reason).toBe("owner_request");
	});
});

function mediaInput() {
	return {
		bytes: PNG,
		mediaType: "image/png",
		conversationToken: OWNER.conversationToken,
		owner: OWNER,
		accessClass: "media-processor" as const,
		receivedAtMs: 10_000,
	};
}
