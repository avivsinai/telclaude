import { describe, expect, it, vi } from "vitest";
import {
	createContentFreeBaileysLogger,
	createRecentInboundMessageStore,
	extractContentFreeBaileysLogText,
	summarizeWhatsAppUpsert,
} from "../../src/whatsapp-bridge/inbound-observe.js";

describe("WhatsApp inbound observe", () => {
	it("summarizes upsert batches without copying identifiers or bodies", () => {
		const summary = summarizeWhatsAppUpsert({
			type: "notify",
			messages: [
				{
					key: { id: "AAAA", fromMe: false, remoteJid: "15551234567@s.whatsapp.net" },
					message: { conversation: "secret household text" },
				},
				{
					key: { id: "BBBB", fromMe: true },
					messageStubType: 1,
				},
				{
					key: { fromMe: false },
				},
			],
		});

		expect(summary).toEqual({
			type: "notify",
			count: 3,
			fromMe: 1,
			missingId: 1,
			hasContent: 1,
			ciphertextStub: 1,
		});
		expect(JSON.stringify(summary)).not.toContain("15551234567");
		expect(JSON.stringify(summary)).not.toContain("secret household text");
	});

	it("keeps only Baileys log strings so JID-bearing objects never reach the sink", () => {
		const sink = {
			info: vi.fn(),
			warn: vi.fn(),
			error: vi.fn(),
		};
		const logger = createContentFreeBaileysLogger(sink);

		logger.warn(
			{ remoteJid: "15551234567@s.whatsapp.net", key: { id: "AAAA" } },
			"failed to decrypt message",
		);
		logger.debug(
			{ remoteJid: "15551234567@s.whatsapp.net", unavailableType: "hosted_unavailable_fanout" },
			"skipping placeholder resend for excluded unavailable type",
		);
		logger.debug({ remoteJid: "15551234567@s.whatsapp.net" }, "ignored routine stanza");

		expect(
			extractContentFreeBaileysLogText({ remoteJid: "1555" }, "failed to decrypt message"),
		).toBe("failed to decrypt message");
		expect(sink.warn).toHaveBeenCalledTimes(1);
		expect(sink.warn).toHaveBeenCalledWith({ component: "baileys" }, "failed to decrypt message");
		expect(sink.info).toHaveBeenCalledTimes(1);
		expect(sink.info).toHaveBeenCalledWith(
			{ component: "baileys" },
			"skipping placeholder resend for excluded unavailable type",
		);
		expect(JSON.stringify(sink.warn.mock.calls)).not.toContain("15551234567");
		expect(JSON.stringify(sink.info.mock.calls)).not.toContain("15551234567");
	});

	it("returns recent plaintext for Baileys retries and evicts the oldest entry", async () => {
		const store = createRecentInboundMessageStore(2);
		store.remember({ remoteJid: "a@s.whatsapp.net", id: "1" }, { conversation: "one" });
		store.remember({ remoteJid: "a@s.whatsapp.net", id: "2" }, { conversation: "two" });
		store.remember({ remoteJid: "a@s.whatsapp.net", id: "3" }, { conversation: "three" });

		expect(await store.getMessage({ remoteJid: "a@s.whatsapp.net", id: "1" })).toBeUndefined();
		expect(await store.getMessage({ remoteJid: "a@s.whatsapp.net", id: "2" })).toEqual({
			conversation: "two",
		});
		expect(await store.getMessage({ remoteJid: "a@s.whatsapp.net", id: "3" })).toEqual({
			conversation: "three",
		});
	});
});
