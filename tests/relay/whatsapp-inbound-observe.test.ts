import { describe, expect, it, vi } from "vitest";
import { logWhatsAppInboundRelayOutcome } from "../../src/relay/whatsapp-inbound-http.js";
import { logWhatsAppInboundReplyOutcome } from "../../src/relay/whatsapp-inbound-reply.js";

describe("WhatsApp inbound relay observability", () => {
	it("logs only accepted outcome booleans or the existing failure code", () => {
		const sink = {
			info: vi.fn(),
			warn: vi.fn(),
		};

		logWhatsAppInboundRelayOutcome(sink, {
			kind: "accepted",
			duplicate: false,
			intercepted: false,
			dispatched: true,
			toolUses: 0,
			toolResults: 0,
		});
		logWhatsAppInboundRelayOutcome(sink, {
			kind: "accepted",
			duplicate: true,
			intercepted: false,
			dispatched: false,
		});
		logWhatsAppInboundRelayOutcome(sink, {
			kind: "accepted",
			duplicate: false,
			intercepted: true,
			dispatched: false,
		});
		logWhatsAppInboundRelayOutcome(sink, {
			kind: "failed",
			code: "whatsapp_inbound_sender_unlinked",
		});

		expect(sink.info).toHaveBeenNthCalledWith(
			1,
			{
				outcome: "accepted",
				duplicate: false,
				intercepted: false,
				dispatched: true,
				toolUses: 0,
				toolResults: 0,
			},
			"WhatsApp inbound POST",
		);
		expect(sink.info).toHaveBeenNthCalledWith(
			2,
			{ outcome: "accepted", duplicate: true, intercepted: false, dispatched: false },
			"WhatsApp inbound POST",
		);
		expect(sink.info).toHaveBeenNthCalledWith(
			3,
			{ outcome: "accepted", duplicate: false, intercepted: true, dispatched: false },
			"WhatsApp inbound POST",
		);
		expect(sink.warn).toHaveBeenCalledWith(
			{ outcome: "failed", code: "whatsapp_inbound_sender_unlinked" },
			"WhatsApp inbound POST",
		);
	});

	it("logs reply outcomes without reply content or identifiers", () => {
		const sink = {
			info: vi.fn(),
			warn: vi.fn(),
		};

		logWhatsAppInboundReplyOutcome(sink, { kind: "reply_sent" });
		logWhatsAppInboundReplyOutcome(sink, { kind: "reply_skipped_empty" });
		logWhatsAppInboundReplyOutcome(sink, { kind: "reply_skipped_tools" });
		logWhatsAppInboundReplyOutcome(sink, {
			kind: "reply_failed",
			code: "whatsapp_inbound_reply_delivery_failed",
		});

		expect(sink.info).toHaveBeenNthCalledWith(
			1,
			{ outcome: "reply_sent" },
			"WhatsApp inbound reply",
		);
		expect(sink.info).toHaveBeenNthCalledWith(
			2,
			{ outcome: "reply_skipped_empty" },
			"WhatsApp inbound reply",
		);
		expect(sink.info).toHaveBeenNthCalledWith(
			3,
			{ outcome: "reply_skipped_tools" },
			"WhatsApp inbound reply",
		);
		expect(sink.warn).toHaveBeenCalledWith(
			{ outcome: "reply_failed", code: "whatsapp_inbound_reply_delivery_failed" },
			"WhatsApp inbound reply",
		);
		expect(JSON.stringify(sink)).not.toContain("SYNTHETIC_BODY");
	});
});
