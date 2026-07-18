import { describe, expect, it, vi } from "vitest";
import type { TelclaudeConfig } from "../../src/config/config.js";
import {
	DeliveryReceiptSchema,
	EdgeAdapterSchemaVersions,
} from "../../src/hermes/edge-adapter-contract.js";
import { TelclaudeEdgeRuntime } from "../../src/hermes/edge-adapter-runtime.js";
import { createRelayConversationStore } from "../../src/hermes/relay-conversation-store.js";
import { createHouseholdEmergencyControlPolicyStore } from "../../src/relay/household-emergency-control-policy.js";
import { createHouseholdEmergencyControlSender } from "../../src/relay/household-emergency-control-sender.js";
import { householdEmergencyCopy } from "../../src/relay/household-emergency-copy.js";

const NOW = Date.parse("2026-07-18T12:00:00.000Z");
const ADDRESS = "whatsapp:+15551234567";

describe("household emergency control sender", () => {
	it("delivers only fixed copy to the binding-owned destination under its own policy record", async () => {
		const conversationStore = createRelayConversationStore({ nowMs: () => NOW });
		mintConversation(conversationStore);
		const policyStore = createHouseholdEmergencyControlPolicyStore({
			conversationStore,
			nowMs: () => NOW,
		});
		const dispatch = vi.fn(async (prepared) =>
			DeliveryReceiptSchema.parse({
				schemaVersion: EdgeAdapterSchemaVersions.deliveryReceipt,
				outboundRef: prepared.outboundRef,
				platformMessageId: "wa-emergency-1",
				deliveryStatus: "sent",
				timestamps: {
					observedAt: new Date(NOW).toISOString(),
					sentAt: new Date(NOW).toISOString(),
				},
				retry: { attempt: 1, maxAttempts: 3, idempotencyKey: prepared.idempotencyKey },
			}),
		);
		const sender = createHouseholdEmergencyControlSender({
			config,
			conversationStore,
			edgeRuntime: new TelclaudeEdgeRuntime({ now: () => new Date(NOW).toISOString() }),
			dispatch,
			policyStore,
		});

		await expect(
			sender({
				bindingId: "parent-a",
				replyAddressRef: ADDRESS,
				body: householdEmergencyCopy("f"),
				eventMessageId: "wa-msg-1",
			}),
		).resolves.toBe(true);
		expect(dispatch).toHaveBeenCalledTimes(1);
		expect(policyStore.list()).toEqual([
			expect.objectContaining({
				origin: "relay_system_household_emergency_control",
				bindingId: "parent-a",
				status: "sent",
			}),
		]);
		expect(JSON.stringify(policyStore.list())).not.toContain(ADDRESS);
		expect(JSON.stringify(policyStore.list())).not.toContain(householdEmergencyCopy("f"));
		await expect(
			sender({
				bindingId: "parent-a",
				replyAddressRef: ADDRESS,
				body: householdEmergencyCopy("f"),
				eventMessageId: "wa-msg-1",
			}),
		).resolves.toBe(false);
		expect(dispatch).toHaveBeenCalledTimes(1);
	});

	it("rejects free-form copy and event replay before delivery", async () => {
		const conversationStore = createRelayConversationStore({ nowMs: () => NOW });
		mintConversation(conversationStore);
		const policyStore = createHouseholdEmergencyControlPolicyStore({
			conversationStore,
			nowMs: () => NOW,
		});
		const dispatch = vi.fn();
		const sender = createHouseholdEmergencyControlSender({
			config,
			conversationStore,
			edgeRuntime: new TelclaudeEdgeRuntime(),
			dispatch,
			policyStore,
		});
		await expect(
			sender({
				bindingId: "parent-a",
				replyAddressRef: ADDRESS,
				body: "free form",
				eventMessageId: "wa-msg-1",
			}),
		).rejects.toThrow(/fixed emergency copy/);
		expect(dispatch).not.toHaveBeenCalled();
	});
});

function mintConversation(store: ReturnType<typeof createRelayConversationStore>) {
	store.resumeOrMint({
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
	});
}

const config = {
	householdEmergency: { enabled: true },
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
					address: ADDRESS,
					replyAddress: ADDRESS,
					displayName: "Parent A",
					subjectUserId: "household:parent-a",
					emergencyEnabled: true,
				},
			],
		},
	],
} as TelclaudeConfig;
