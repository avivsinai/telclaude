import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createRelayConversationStore } from "../../src/hermes/relay-conversation-store.js";
import { householdReminderWhatsAppMessageId } from "../../src/household-reminders/render.js";
import { createAttachmentQuarantineStore } from "../../src/relay/attachment-quarantine-store.js";
import {
	createWhatsAppBridgeAuthToken,
	WHATSAPP_SIDECAR_AUTH_HEADER,
	WHATSAPP_SIDECAR_REQUEST_DIGEST_HEADER,
	WHATSAPP_SIDECAR_SESSION_EXPIRES_AT_HEADER,
	WHATSAPP_SIDECAR_SESSION_KEY_HEADER,
} from "../../src/relay/whatsapp-edge-channel-connector.js";
import {
	handleWhatsAppInboundBridgePost,
	type WhatsAppInboundDispatch,
} from "../../src/relay/whatsapp-inbound-http.js";
import { closeDb, resetDatabase } from "../../src/storage/db.js";
import {
	deterministicWhatsAppBridgeMessageId,
	digestWhatsAppBridgeSendRequest,
	parseWhatsAppDestinationJid,
	parseWhatsAppBridgeAttachments,
	signWhatsAppInboundBridgeEvent,
	validateWhatsAppBridgeSend,
	WHATSAPP_INBOUND_BRIDGE_SCHEMA_VERSION,
	whatsappInboundBridgeBody,
	whatsappBridgeContentForAttachment,
} from "../../src/whatsapp-bridge/contract.js";

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;
const WHATSAPP_BRIDGE_SECRET = "test-whatsapp-bridge-secret";

describe("WhatsApp bridge contract", () => {
	let tempDir = "";

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tc-wa-bridge-contract-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		resetDatabase();
	});

	afterEach(() => {
		closeDb();
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) {
			delete process.env.TELCLAUDE_DATA_DIR;
		} else {
			process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
		}
	});

	it("accepts only relay-bound send requests with a matching digest and live session", () => {
		const request = sendRequest();
		const requestDigest = digestWhatsAppBridgeSendRequest(request);
		const expiresAt = new Date(2_000).toISOString();
		const headers = {
			[WHATSAPP_SIDECAR_SESSION_KEY_HEADER]: "wa-session:test",
			[WHATSAPP_SIDECAR_REQUEST_DIGEST_HEADER]: requestDigest,
			[WHATSAPP_SIDECAR_SESSION_EXPIRES_AT_HEADER]: expiresAt,
			[WHATSAPP_SIDECAR_AUTH_HEADER]: createWhatsAppBridgeAuthToken({
				secret: WHATSAPP_BRIDGE_SECRET,
				sessionKey: "wa-session:test",
				requestDigest,
				expiresAt,
			}),
		};

		expect(validateWhatsAppBridgeSend(request, headers, WHATSAPP_BRIDGE_SECRET, 1_000)).toEqual({
			ok: true,
			sessionKey: "wa-session:test",
		});

		expect(
			validateWhatsAppBridgeSend(
				{ ...request, body: "tampered" },
				headers,
				WHATSAPP_BRIDGE_SECRET,
				1_000,
			),
		).toMatchObject({
			ok: false,
			status: 401,
			code: "whatsapp_bridge_digest_mismatch",
		});

		expect(
			validateWhatsAppBridgeSend(request, headers, WHATSAPP_BRIDGE_SECRET, 3_000),
		).toMatchObject({
			ok: false,
			status: 401,
			code: "whatsapp_bridge_session_expired",
		});

		expect(
			validateWhatsAppBridgeSend(
				request,
				{ ...headers, [WHATSAPP_SIDECAR_AUTH_HEADER]: "" },
				WHATSAPP_BRIDGE_SECRET,
				1_000,
			),
		).toMatchObject({
			ok: false,
			status: 401,
			code: "whatsapp_bridge_auth_missing",
		});

		expect(
			validateWhatsAppBridgeSend(
				request,
				{ ...headers, [WHATSAPP_SIDECAR_AUTH_HEADER]: `sha256:${"b".repeat(64)}` },
				WHATSAPP_BRIDGE_SECRET,
				1_000,
			),
		).toMatchObject({
			ok: false,
			status: 401,
			code: "whatsapp_bridge_auth_mismatch",
		});

		expect(validateWhatsAppBridgeSend(request, headers, "", 1_000)).toMatchObject({
			ok: false,
			status: 503,
			code: "whatsapp_bridge_secret_unconfigured",
		});
	});

	it("maps allowed E.164 destinations into WhatsApp JIDs", () => {
		expect(parseWhatsAppDestinationJid(sendRequest()).ok).toBe(true);
		expect(parseWhatsAppDestinationJid(sendRequest()).jid).toBe("15551234567@s.whatsapp.net");

		expect(
			parseWhatsAppDestinationJid({
				...sendRequest(),
				destination: { kind: "address", addressRef: "not-a-phone" },
			}),
		).toMatchObject({ ok: false, code: "whatsapp_destination_invalid" });
	});

	it("derives stable Baileys-safe message ids per idempotent send part", () => {
		const first = deterministicWhatsAppBridgeMessageId("idem:test", 0);
		expect(first).toMatch(/^TCREMINDER[a-f0-9]{32}$/);
		expect(first).toBe(householdReminderWhatsAppMessageId("idem:test"));
		expect(deterministicWhatsAppBridgeMessageId("idem:test", 0)).toBe(first);
		expect(deterministicWhatsAppBridgeMessageId("idem:test", 1)).not.toBe(first);
		expect(() => deterministicWhatsAppBridgeMessageId("idem:test", -1)).toThrow(/part index/);
	});

	it("binds and renders only the safe document filename at the bridge boundary", () => {
		const parsed = parseWhatsAppBridgeAttachments([
			{
				mediaType: "application/pdf",
				bytesBase64: Buffer.from("pdf").toString("base64"),
				sizeBytes: 3,
				redactedFilename: "Provider_Statement.pdf",
				quarantineId: "tc-quarantine:internal",
				filepath: "/private/provider/raw.pdf",
			},
		]);

		expect(parsed).toEqual([
			{
				mediaType: "application/pdf",
				bytesBase64: Buffer.from("pdf").toString("base64"),
				sizeBytes: 3,
				redactedFilename: "Provider_Statement.pdf",
			},
		]);
		const attachment = parsed[0];
		if (!attachment) throw new Error("expected parsed bridge attachment");
		expect(whatsappBridgeContentForAttachment(attachment, "caption")).toMatchObject({
			mimetype: "application/pdf",
			fileName: "Provider_Statement.pdf",
			caption: "caption",
		});
		expect(JSON.stringify(parsed)).not.toContain("tc-quarantine");
		expect(JSON.stringify(parsed)).not.toContain("/private/provider");

		const request = { ...sendRequest(), attachments: parsed };
		expect(digestWhatsAppBridgeSendRequest(request)).not.toBe(
			digestWhatsAppBridgeSendRequest({
				...request,
				attachments: [{ ...parsed[0], redactedFilename: "mutated.pdf" }],
			}),
		);
	});

	it("signs inbound events compatibly with the relay CL-1 endpoint", async () => {
		const event = {
			schemaVersion: WHATSAPP_INBOUND_BRIDGE_SCHEMA_VERSION,
			eventId: "wa:event:1",
			messageId: "wamid.1",
			cursorSequence: 1,
			chatKind: "direct" as const,
			senderAddressRef: "whatsapp:+15551234567",
			conversationKey: "whatsapp:15551234567@s.whatsapp.net",
			text: "hello",
			attachments: [],
			receivedAtMs: 1_000,
		};
		const dispatch: WhatsAppInboundDispatch = async () => ({ ok: true });

		const result = await handleWhatsAppInboundBridgePost({
			body: whatsappInboundBridgeBody(event),
			signatureHeader: signWhatsAppInboundBridgeEvent(event, "secret"),
			options: {
				signatureSecret: "secret",
				operatorAddressRefs: ["whatsapp:+15551234567"],
				config: {
					hermes: {
						privateRuntime: {
							providerScopes: [],
							capabilityScopes: [],
							outboundChannels: ["whatsapp"],
						},
					},
				},
				profile: {
					id: "default",
					label: "Default",
					providerScopes: [],
					capabilityScopes: [],
					outboundChannels: ["whatsapp"],
				},
				conversationStore: createRelayConversationStore({ nowMs: () => 1_000 }),
				quarantineStore: createAttachmentQuarantineStore({ now: () => 1_000 }),
				dispatch,
				nowMs: () => 1_000,
			},
		});

		expect(result.status).toBe(202);
		expect(result.payload.ok).toBe(true);
	});
});

function sendRequest() {
	return {
		schemaVersion: "telclaude.edge.whatsapp.send.v1",
		outboundRef: "outbound:test",
		idempotencyKey: "idem:test",
		destination: { kind: "address", addressRef: "whatsapp:+15551234567" },
		body: "hello",
		threadMessageIds: [],
		attachments: [],
	};
}
