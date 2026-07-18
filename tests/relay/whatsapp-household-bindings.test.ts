import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { TelclaudeConfig } from "../../src/config/config.js";

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;
const NOW = Date.parse("2026-07-17T09:00:00.000Z");
const SECRET = "test-household-inbound-secret";

describe("WhatsApp household bindings", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-wa-household-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		vi.resetModules();
		const { resetDatabase } = await import("../../src/storage/db.js");
		resetDatabase();
	});

	afterEach(async () => {
		const { closeDb } = await import("../../src/storage/db.js");
		closeDb();
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) delete process.env.TELCLAUDE_DATA_DIR;
		else process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
	});

	it("mints disjoint household actor, subject, profile, memory, and conversation authority", async () => {
		const { createRelayConversationStore } = await import(
			"../../src/hermes/relay-conversation-store.js"
		);
		const { createAttachmentQuarantineStore } = await import(
			"../../src/relay/attachment-quarantine-store.js"
		);
		const { createWhatsAppHouseholdIdentityResolver } = await import(
			"../../src/relay/whatsapp-household-bindings.js"
		);
		const { createWhatsAppInboundCl1Pipeline, signWhatsAppInboundBridgeEvent } = await import(
			"../../src/relay/whatsapp-inbound-cl1.js"
		);
		const conversationStore = createRelayConversationStore({ nowMs: () => NOW });
		const pipeline = createWhatsAppInboundCl1Pipeline({
			signatureSecret: SECRET,
			conversationStore,
			quarantineStore: createAttachmentQuarantineStore({ now: () => NOW }),
			resolveIdentity: createWhatsAppHouseholdIdentityResolver(config),
			nowMs: () => NOW,
		});
		const eventA = householdEvent("a");
		const eventB = householdEvent("b");
		const resultA = await pipeline.ingest({
			event: eventA,
			signature: signWhatsAppInboundBridgeEvent(eventA, SECRET),
		});
		const resultB = await pipeline.ingest({
			event: eventB,
			signature: signWhatsAppInboundBridgeEvent(eventB, SECRET),
		});

		expect(resultA).toMatchObject({
			ok: true,
			duplicate: false,
			identity: {
				bindingId: "parent-a",
				addresseeGender: "f",
				actorId: "household:whatsapp:parent-a",
				subjectUserId: "household:parent-a",
				profileId: "parent-a",
				domain: "household",
				memorySource: "household:parent-a",
				writableNamespace: "household:parent-a",
			},
			conversation: {
				conversationId: "whatsapp:household:parent-a",
				profileId: "parent-a",
				domain: "household",
			},
		});
		expect(resultB).toMatchObject({
			ok: true,
			duplicate: false,
			identity: {
				bindingId: "parent-b",
				addresseeGender: "m",
				actorId: "household:whatsapp:parent-b",
				subjectUserId: "household:parent-b",
				profileId: "parent-b",
				memorySource: "household:parent-b",
			},
			conversation: {
				conversationId: "whatsapp:household:parent-b",
				profileId: "parent-b",
				domain: "household",
			},
		});
		expect(JSON.stringify(resultA)).not.toContain("parent-b");
		expect(JSON.stringify(resultB)).not.toContain("parent-a");
	});

	it("denies a sender whose bridge conversation key is not its bound reply address", async () => {
		const { createRelayConversationStore } = await import(
			"../../src/hermes/relay-conversation-store.js"
		);
		const { createAttachmentQuarantineStore } = await import(
			"../../src/relay/attachment-quarantine-store.js"
		);
		const { createWhatsAppHouseholdIdentityResolver } = await import(
			"../../src/relay/whatsapp-household-bindings.js"
		);
		const { createWhatsAppInboundCl1Pipeline, signWhatsAppInboundBridgeEvent } = await import(
			"../../src/relay/whatsapp-inbound-cl1.js"
		);
		const pipeline = createWhatsAppInboundCl1Pipeline({
			signatureSecret: SECRET,
			conversationStore: createRelayConversationStore({ nowMs: () => NOW }),
			quarantineStore: createAttachmentQuarantineStore({ now: () => NOW }),
			resolveIdentity: createWhatsAppHouseholdIdentityResolver(config),
			nowMs: () => NOW,
		});
		const event = {
			...householdEvent("a"),
			conversationKey: "whatsapp:15557654321@s.whatsapp.net",
		};

		await expect(
			pipeline.ingest({ event, signature: signWhatsAppInboundBridgeEvent(event, SECRET) }),
		).resolves.toMatchObject({
			ok: false,
			code: "whatsapp_inbound_conversation_mismatch",
		});
	});

	it("re-resolves reply evidence only for the exact actor, subject, and profile tuple", async () => {
		const { createWhatsAppHouseholdReplyBindingResolver } = await import(
			"../../src/relay/whatsapp-household-bindings.js"
		);
		const resolve = createWhatsAppHouseholdReplyBindingResolver(config);

		expect(
			await resolve({
				actorId: "household:whatsapp:parent-a",
				subjectUserId: "household:parent-a",
				profileId: "parent-a",
			}),
		).toEqual({
			bindingId: "parent-a",
			actorId: "household:whatsapp:parent-a",
			subjectUserId: "household:parent-a",
			profileId: "parent-a",
			principalId: "whatsapp:+15551234567",
			replyPrincipalId: "whatsapp:+15551234567",
			identityAssurance: "strong_link",
			pairingAttested: true,
			revoked: false,
		});
		expect(
			await resolve({
				actorId: "household:whatsapp:parent-b",
				subjectUserId: "household:parent-a",
				profileId: "parent-a",
			}),
		).toBeNull();
	});
});

function householdEvent(parent: "a" | "b") {
	const phone = parent === "a" ? "+15551234567" : "+15557654321";
	const bare = phone.slice(1);
	return {
		schemaVersion: "telclaude.edge.whatsapp.inbound.v1" as const,
		eventId: `wa-event-${parent}`,
		messageId: `wa-message-${parent}`,
		cursorSequence: 1,
		chatKind: "direct" as const,
		senderAddressRef: `whatsapp:${phone}`,
		conversationKey: `whatsapp:${bare}@s.whatsapp.net`,
		text: `hello from parent ${parent}`,
		attachments: [],
		receivedAtMs: NOW,
	};
}

const config = {
	profiles: [
		{
			id: "parent-a",
			label: "Parent A",
			allowedSkills: [],
			providerScopes: ["clalit"],
			capabilityScopes: ["schedule.read", "schedule.write"],
			outboundChannels: ["whatsapp"],
			whatsappHouseholdBindings: [
				{
					bindingId: "parent-a",
					addresseeGender: "f",
					address: "whatsapp:+15551234567",
					replyAddress: "whatsapp:+15551234567",
					displayName: "Parent A",
					subjectUserId: "household:parent-a",
				},
			],
		},
		{
			id: "parent-b",
			label: "Parent B",
			allowedSkills: [],
			providerScopes: ["clalit"],
			capabilityScopes: ["schedule.read", "schedule.write"],
			outboundChannels: ["whatsapp"],
			whatsappHouseholdBindings: [
				{
					bindingId: "parent-b",
					addresseeGender: "m",
					address: "whatsapp:+15557654321",
					replyAddress: "whatsapp:+15557654321",
					displayName: "Parent B",
					subjectUserId: "household:parent-b",
				},
			],
		},
	],
} as TelclaudeConfig;
