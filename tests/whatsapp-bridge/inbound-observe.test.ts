import { describe, expect, it, vi } from "vitest";
import {
	classifyBaileysLogKind,
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

	it("maps Baileys logs to allowlisted kinds and never forwards interpolated identifiers", () => {
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
		logger.warn({}, "failed to decrypt SYNTHETIC_JID_7f4 SYNTHETIC_BODY_91c");
		logger.debug(
			{},
			"sendRetryRequest: requested placeholder resend for message SYNTHETIC_JID_7f4",
		);
		logger.debug(`Added message to retry cache: 15551234567@s.whatsapp.net/AAAA`);
		logger.debug({ remoteJid: "15551234567@s.whatsapp.net" }, "ignored routine stanza");

		expect(
			extractContentFreeBaileysLogText({ remoteJid: "1555" }, "failed to decrypt message"),
		).toBe("decrypt_failed");
		expect(
			classifyBaileysLogKind("skipping placeholder resend for excluded unavailable type"),
		).toBe("placeholder_resend");
		expect(sink.warn).toHaveBeenCalledTimes(2);
		expect(sink.warn).toHaveBeenNthCalledWith(1, { component: "baileys" }, "decrypt_failed");
		expect(sink.warn).toHaveBeenNthCalledWith(2, { component: "baileys" }, "decrypt_failed");
		expect(sink.info).toHaveBeenCalledTimes(2);
		expect(sink.info).toHaveBeenNthCalledWith(1, { component: "baileys" }, "placeholder_resend");
		expect(sink.info).toHaveBeenNthCalledWith(2, { component: "baileys" }, "retry");
		const serialized = JSON.stringify([...sink.warn.mock.calls, ...sink.info.mock.calls]);
		expect(serialized).not.toContain("15551234567");
		expect(serialized).not.toContain("SYNTHETIC_JID_7f4");
		expect(serialized).not.toContain("SYNTHETIC_BODY_91c");
		expect(serialized).not.toContain("@s.whatsapp.net");
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
