import { describe, expect, it } from "vitest";
import {
	isStaleWhatsAppBridgeGeneration,
	WHATSAPP_BRIDGE_CONNECTION_REPLACED,
	whatsappBridgeReconnectDelayMs,
} from "../../src/whatsapp-bridge/reconnect.js";

describe("WhatsApp bridge reconnect policy", () => {
	it("does not reconnect after a logged-out disconnect", () => {
		expect(
			whatsappBridgeReconnectDelayMs({
				loggedOut: true,
				statusCode: 401,
				attempt: 0,
			}),
		).toBeNull();
	});

	it("uses a 5s base for ordinary closes", () => {
		expect(
			whatsappBridgeReconnectDelayMs({
				loggedOut: false,
				statusCode: 428,
				attempt: 0,
			}),
		).toBe(5_000);
		expect(
			whatsappBridgeReconnectDelayMs({
				loggedOut: false,
				statusCode: 428,
				attempt: 1,
			}),
		).toBe(10_000);
	});

	it("backs off replaced sessions so reconnect does not fight itself", () => {
		expect(
			whatsappBridgeReconnectDelayMs({
				loggedOut: false,
				statusCode: WHATSAPP_BRIDGE_CONNECTION_REPLACED,
				attempt: 0,
			}),
		).toBe(30_000);
		expect(
			whatsappBridgeReconnectDelayMs({
				loggedOut: false,
				statusCode: WHATSAPP_BRIDGE_CONNECTION_REPLACED,
				attempt: 1,
			}),
		).toBe(60_000);
		expect(
			whatsappBridgeReconnectDelayMs({
				loggedOut: false,
				statusCode: WHATSAPP_BRIDGE_CONNECTION_REPLACED,
				attempt: 3,
			}),
		).toBe(120_000);
	});

	it("ignores events from a replaced socket generation", () => {
		expect(isStaleWhatsAppBridgeGeneration(1, 2)).toBe(true);
		expect(isStaleWhatsAppBridgeGeneration(2, 2)).toBe(false);
	});
});
