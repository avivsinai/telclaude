import { describe, expect, it, vi } from "vitest";
import { logWhatsAppInboundRelayOutcome } from "../../src/relay/whatsapp-inbound-http.js";

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
			{ outcome: "accepted", duplicate: false, intercepted: false, dispatched: true },
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
});
