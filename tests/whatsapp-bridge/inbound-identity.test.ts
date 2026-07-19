import { isHostedLidUser, isHostedPnUser, isLidUser, isPnUser } from "@whiskeysockets/baileys";
import { describe, expect, it, vi } from "vitest";
import { resolveWhatsAppInboundDirectIdentity } from "../../src/whatsapp-bridge/index.js";

const classifyJid = {
	isPhoneJid: (jid: string) => Boolean(isPnUser(jid) || isHostedPnUser(jid)),
	isLidJid: (jid: string) => Boolean(isLidUser(jid) || isHostedLidUser(jid)),
};

describe("WhatsApp bridge inbound identity", () => {
	it("resolves a LID-addressed DM through its PN alternate for both phone references", async () => {
		const householdBinding = {
			address: "whatsapp:+15551234567",
			expectedConversationKey: "whatsapp:15551234567@s.whatsapp.net",
		};

		const resolved = await resolveWhatsAppInboundDirectIdentity(
			{
				remoteJid: "710000000000001@lid",
				remoteJidAlt: "15551234567@s.whatsapp.net",
			},
			{
				...classifyJid,
				getPhoneJidForLid: vi.fn(),
			},
		);

		expect(resolved).toEqual({
			senderAddressRef: householdBinding.address,
			conversationKey: householdBinding.expectedConversationKey,
		});
	});

	it("keeps a PN-addressed DM canonical when the alternate is a LID", async () => {
		const getPhoneJidForLid = vi.fn();

		const resolved = await resolveWhatsAppInboundDirectIdentity(
			{
				remoteJid: "15551234567@s.whatsapp.net",
				remoteJidAlt: "710000000000001@lid",
			},
			{ ...classifyJid, getPhoneJidForLid },
		);

		expect(resolved).toEqual({
			senderAddressRef: "whatsapp:+15551234567",
			conversationKey: "whatsapp:15551234567@s.whatsapp.net",
		});
		expect(getPhoneJidForLid).not.toHaveBeenCalled();
	});

	it("uses the cached PN mapping when a LID-addressed DM has no PN alternate", async () => {
		const getPhoneJidForLid = vi.fn(async () => "15551234567@s.whatsapp.net");

		const resolved = await resolveWhatsAppInboundDirectIdentity(
			{ remoteJid: "710000000000001@lid" },
			{ ...classifyJid, getPhoneJidForLid },
		);

		expect(resolved).toEqual({
			senderAddressRef: "whatsapp:+15551234567",
			conversationKey: "whatsapp:15551234567@s.whatsapp.net",
		});
		expect(getPhoneJidForLid).toHaveBeenCalledWith("710000000000001@lid");
	});

	it("fails closed when a LID-addressed DM has no resolvable PN", async () => {
		const resolved = await resolveWhatsAppInboundDirectIdentity(
			{ remoteJid: "710000000000001@lid" },
			{
				...classifyJid,
				getPhoneJidForLid: async () => null,
			},
		);

		expect(resolved).toBeNull();
	});

	it("never mints a phone address from raw LID digits", async () => {
		const resolved = await resolveWhatsAppInboundDirectIdentity(
			{
				remoteJid: "710000000000001@lid",
				remoteJidAlt: "710000000000002@lid",
			},
			{
				...classifyJid,
				getPhoneJidForLid: async () => "710000000000001@lid",
			},
		);

		expect(resolved).toBeNull();
	});
});
