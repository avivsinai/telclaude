import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	WHATSAPP_BRIDGE_JOURNAL_RETENTION_MS,
	WhatsAppBridgeIdempotencyJournal,
} from "../../src/whatsapp-bridge/idempotency-journal.js";
import { sendWhatsAppBridgeRequest } from "../../src/whatsapp-bridge/index.js";

describe("WhatsApp bridge idempotency journal", () => {
	let tempDir: string;
	let nowMs: number;

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tc-wa-journal-"));
		nowMs = Date.parse("2026-07-18T00:00:00.000Z");
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
	});

	it("persists 0600 pending state before send and caches a sanitized terminal response", async () => {
		const journal = new WhatsAppBridgeIdempotencyJournal({ dataDir: tempDir, nowMs: () => nowMs });
		const send = vi.fn(async (messageIds: readonly string[]) => {
			const files = journalFiles(tempDir);
			expect(files).toHaveLength(1);
			expect(fs.statSync(files[0]).mode & 0o777).toBe(0o600);
			expect(JSON.parse(fs.readFileSync(files[0], "utf8"))).toMatchObject({
				state: "pending",
				idempotencyKey: "idem:one",
				requestDigest: `sha256:${"a".repeat(64)}`,
				messageIds,
			});
			return {
				ok: true as const,
				platformMessageId: messageIds[0],
				observedThreadMessageId: messageIds[0],
			};
		});

		const first = await journal.execute(
			{
				idempotencyKey: "idem:one",
				requestDigest: `sha256:${"a".repeat(64)}`,
				messageCount: 1,
			},
			send,
		);
		expect(first).toMatchObject({ ok: true, platformMessageId: expect.any(String) });
		expect(send).toHaveBeenCalledTimes(1);

		const reopened = new WhatsAppBridgeIdempotencyJournal({
			dataDir: tempDir,
			nowMs: () => nowMs,
		});
		const cached = await reopened.execute(
			{
				idempotencyKey: "idem:one",
				requestDigest: `sha256:${"a".repeat(64)}`,
				messageCount: 1,
			},
			vi.fn(),
		);
		expect(cached).toEqual(first);
		expect(fs.statSync(journalFiles(tempDir)[0]).mode & 0o777).toBe(0o600);
		expect(
			JSON.stringify(JSON.parse(fs.readFileSync(journalFiles(tempDir)[0], "utf8"))),
		).not.toMatch(/body|destination|recipient|attachment/);
	});

	it("recovers a pending retry after restart with byte-identical message ids", async () => {
		const input = {
			idempotencyKey: "idem:pending",
			requestDigest: `sha256:${"b".repeat(64)}` as const,
			messageCount: 2,
		};
		let firstIds: readonly string[] = [];
		const journal = new WhatsAppBridgeIdempotencyJournal({ dataDir: tempDir, nowMs: () => nowMs });
		await expect(
			journal.execute(input, async (messageIds) => {
				firstIds = [...messageIds];
				return {
					ok: false,
					code: "whatsapp_bridge_send_failed",
					reason: "transient transport failure",
					retryable: true,
				};
			}),
		).resolves.toMatchObject({ ok: false, retryable: true });
		expect(JSON.parse(fs.readFileSync(journalFiles(tempDir)[0], "utf8"))).toMatchObject({
			state: "pending",
		});

		const reopened = new WhatsAppBridgeIdempotencyJournal({
			dataDir: tempDir,
			nowMs: () => nowMs + 1_000,
		});
		await expect(
			reopened.execute(input, async (messageIds) => {
				expect(messageIds).toEqual(firstIds);
				return { ok: true, platformMessageId: messageIds[0] };
			}),
		).resolves.toMatchObject({ ok: true, platformMessageId: firstIds[0] });
		expect(fs.statSync(journalFiles(tempDir)[0]).mode & 0o777).toBe(0o600);
	});

	it("persists only a generic sanitized terminal failure", async () => {
		const journal = new WhatsAppBridgeIdempotencyJournal({ dataDir: tempDir, nowMs: () => nowMs });
		await expect(
			journal.execute(
				{
					idempotencyKey: "idem:terminal-failure",
					requestDigest: `sha256:${"9".repeat(64)}`,
					messageCount: 1,
				},
				async () => ({
					ok: false,
					code: "whatsapp_destination_invalid",
					reason: "sensitive destination details",
					retryable: false,
				}),
			),
		).resolves.toEqual({
			ok: false,
			code: "whatsapp_destination_invalid",
			reason: "WhatsApp bridge request failed.",
			retryable: false,
		});
		const serialized = fs.readFileSync(journalFiles(tempDir)[0], "utf8");
		expect(serialized).not.toContain("sensitive destination details");
		expect(JSON.parse(serialized)).toMatchObject({ state: "completed" });
	});

	it("rejects digest drift and serializes concurrent sends for one key", async () => {
		const journal = new WhatsAppBridgeIdempotencyJournal({ dataDir: tempDir, nowMs: () => nowMs });
		let releaseFirst: (() => void) | undefined;
		const blocked = new Promise<void>((resolve) => {
			releaseFirst = resolve;
		});
		const send = vi.fn(async (messageIds: readonly string[]) => {
			await blocked;
			return { ok: true as const, platformMessageId: messageIds[0] };
		});
		const input = {
			idempotencyKey: "idem:serialized",
			requestDigest: `sha256:${"c".repeat(64)}` as const,
			messageCount: 1,
		};
		const first = journal.execute(input, send);
		const second = journal.execute(input, send);
		await vi.waitFor(() => expect(send).toHaveBeenCalledTimes(1));
		releaseFirst?.();
		expect(await second).toEqual(await first);
		expect(send).toHaveBeenCalledTimes(1);

		await expect(
			journal.execute({ ...input, requestDigest: `sha256:${"d".repeat(64)}` }, vi.fn()),
		).resolves.toMatchObject({
			ok: false,
			code: "whatsapp_bridge_idempotency_mismatch",
			retryable: false,
		});
	});

	it("prunes completed rows only after 30 days and never removes pending rows", async () => {
		const journal = new WhatsAppBridgeIdempotencyJournal({ dataDir: tempDir, nowMs: () => nowMs });
		await journal.execute(
			{
				idempotencyKey: "idem:complete",
				requestDigest: `sha256:${"e".repeat(64)}`,
				messageCount: 1,
			},
			async (messageIds) => ({ ok: true, platformMessageId: messageIds[0] }),
		);
		await journal.execute(
			{
				idempotencyKey: "idem:pending",
				requestDigest: `sha256:${"f".repeat(64)}`,
				messageCount: 1,
			},
			async () => ({ ok: false, code: "temporary", retryable: true }),
		);
		expect(journalFiles(tempDir)).toHaveLength(2);

		nowMs += WHATSAPP_BRIDGE_JOURNAL_RETENTION_MS + 1;
		expect(journal.cleanup()).toBe(1);
		expect(journalFiles(tempDir)).toHaveLength(1);
		expect(JSON.parse(fs.readFileSync(journalFiles(tempDir)[0], "utf8"))).toMatchObject({
			state: "pending",
			idempotencyKey: "idem:pending",
		});
	});

	it("passes the journaled deterministic id through Baileys sendMessage options", async () => {
		const sendMessage = vi.fn(async () => ({}));
		const request = {
			schemaVersion: "telclaude.edge.whatsapp.send.v1",
			outboundRef: "outbound:test",
			idempotencyKey: "idem:baileys",
			destination: { kind: "address", addressRef: "whatsapp:+15551234567" },
			body: "hello",
			attachments: [],
		};
		const messageId = `TCREMINDER${"1".repeat(32)}`;

		await expect(
			sendWhatsAppBridgeRequest({ sendMessage }, "15551234567@s.whatsapp.net", request, [
				messageId,
			]),
		).resolves.toEqual({
			ok: true,
			platformMessageId: messageId,
			observedThreadMessageId: messageId,
		});
		expect(sendMessage).toHaveBeenCalledWith(
			"15551234567@s.whatsapp.net",
			{ text: "hello" },
			{ messageId },
		);
	});
});

function journalFiles(dataDir: string): string[] {
	const directory = path.join(dataDir, "idempotency-journal");
	return fs.existsSync(directory)
		? fs
				.readdirSync(directory)
				.filter((entry) => entry.endsWith(".json"))
				.map((entry) => path.join(directory, entry))
		: [];
}
