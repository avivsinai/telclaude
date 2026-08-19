import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	DeliveryReceiptSchema,
	EdgeAdapterSchemaVersions,
} from "../../src/hermes/edge-adapter-contract.js";
import { TelclaudeEdgeRuntime } from "../../src/hermes/edge-adapter-runtime.js";
import {
	createRelayConversationStore,
	type RelayConversationStore,
} from "../../src/hermes/relay-conversation-store.js";
import {
	createWhatsAppInboundReplyPolicyStore,
	createWhatsAppInboundReplySender,
} from "../../src/relay/whatsapp-inbound-reply.js";
import { closeDb, resetDatabase } from "../../src/storage/db.js";

const NOW = Date.parse("2026-08-19T16:00:00.000Z");
const ADDRESS = "whatsapp:+15551234567";
const TURN_REF = `turn_${"a".repeat(32)}`;
const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

describe("WhatsApp inbound reply sender", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-wa-inbound-reply-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		resetDatabase();
	});

	afterEach(() => {
		closeDb();
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) delete process.env.TELCLAUDE_DATA_DIR;
		else process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
	});

	it("delivers no-tool text through prepareOutbound and a single-use policy", async () => {
		const conversationStore = createRelayConversationStore({ nowMs: () => NOW });
		const conversation = mintPrivateConversation(conversationStore);
		const policyStore = createWhatsAppInboundReplyPolicyStore({
			conversationStore,
			nowMs: () => NOW,
		});
		let authorizedOutbound: Parameters<typeof policyStore.claim>[0] | null = null;
		const dispatch = vi.fn(async (prepared) => {
			authorizedOutbound = prepared;
			expect(await policyStore.resolveConversation(prepared)).toMatchObject({
				conversationToken: conversation.token,
			});
			return sentReceipt(prepared.outboundRef, prepared.idempotencyKey);
		});
		const sender = createWhatsAppInboundReplySender({
			edgeRuntime: new TelclaudeEdgeRuntime({ now: () => new Date(NOW).toISOString() }),
			dispatch,
			policyStore,
		});

		await sender({
			conversation,
			recipientAddressRef: ADDRESS,
			body: "  Dinner is at 7  ",
			turnRef: TURN_REF,
		});

		expect(dispatch).toHaveBeenCalledTimes(1);
		expect(policyStore.list()).toEqual([
			expect.objectContaining({
				origin: "relay_system_whatsapp_inbound_reply",
				turnRef: TURN_REF,
				status: "sent",
			}),
		]);
		expect(policyStore.list()[0]).not.toHaveProperty("body");
		expect(authorizedOutbound).not.toBeNull();
		if (!authorizedOutbound) throw new Error("authorized outbound was not dispatched");
		expect(authorizedOutbound.finalRenderedBody).toBe("Dinner is at 7");
		expect(policyStore.claim(authorizedOutbound)).toBe(false);
	});

	it("refuses household copy that is not auto-grant safe", async () => {
		const conversationStore = createRelayConversationStore({ nowMs: () => NOW });
		const conversation = mintHouseholdConversation(conversationStore);
		const policyStore = createWhatsAppInboundReplyPolicyStore({ conversationStore });
		const dispatch = vi.fn();
		const sender = createWhatsAppInboundReplySender({
			edgeRuntime: new TelclaudeEdgeRuntime(),
			dispatch,
			policyStore,
		});

		await expect(
			sender({
				conversation,
				recipientAddressRef: ADDRESS,
				body: "Send the credit card number now",
				turnRef: TURN_REF,
			}),
		).rejects.toMatchObject({
			name: "WhatsAppInboundReplyError",
			code: "whatsapp_inbound_reply_not_auto_grant_safe",
		});
		expect(dispatch).not.toHaveBeenCalled();
	});
});

function mintPrivateConversation(store: RelayConversationStore) {
	return store.mint({
		channel: "whatsapp",
		conversationId: ADDRESS,
		threadId: ADDRESS,
		profileId: "operator-private",
		domain: "private",
		authorizationState: "authorized",
		humanPairingProvenance: true,
		authorizationScopes: ["message:read", "message:reply"],
		members: [
			{
				actorId: "operator:aviv",
				principalId: ADDRESS,
				role: "sender",
				identityAssurance: "strong_link",
				scopes: ["message:read", "message:reply"],
			},
		],
		nowMs: NOW,
	}).conversation;
}

function mintHouseholdConversation(store: RelayConversationStore) {
	return store.mint({
		channel: "whatsapp",
		conversationId: "whatsapp:household:parent-a",
		threadId: "whatsapp:15551234567@s.whatsapp.net",
		profileId: "parent-a",
		domain: "household",
		authorizationState: "authorized",
		humanPairingProvenance: true,
		authorizationScopes: ["message:read", "message:reply"],
		members: [
			{
				actorId: "household:whatsapp:parent-a",
				principalId: ADDRESS,
				role: "sender",
				identityAssurance: "strong_link",
				scopes: ["message:read", "message:reply"],
			},
		],
		nowMs: NOW,
	}).conversation;
}

function sentReceipt(outboundRef: string, idempotencyKey: string) {
	return DeliveryReceiptSchema.parse({
		schemaVersion: EdgeAdapterSchemaVersions.deliveryReceipt,
		outboundRef,
		platformMessageId: "wa-inbound-reply-1",
		deliveryStatus: "sent",
		timestamps: {
			observedAt: new Date(NOW).toISOString(),
			sentAt: new Date(NOW).toISOString(),
		},
		retry: { attempt: 1, maxAttempts: 3, idempotencyKey },
	});
}
