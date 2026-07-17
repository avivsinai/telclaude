import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { TelclaudeConfig } from "../../src/config/config.js";
import type { RelayConversationStore } from "../../src/hermes/relay-conversation-store.js";

const NOW = Date.parse("2026-07-17T09:00:00.000Z");
const ADDRESS = "whatsapp:+15551234567";
const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

describe("provider challenge control sender", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-provider-control-"));
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

	it("delivers a fixed template through prepared outbound under a distinct system-origin record", async () => {
		const { EdgeAdapterSchemaVersions, DeliveryReceiptSchema } = await import(
			"../../src/hermes/edge-adapter-contract.js"
		);
		const { TelclaudeEdgeRuntime } = await import("../../src/hermes/edge-adapter-runtime.js");
		const { createRelayConversationStore } = await import(
			"../../src/hermes/relay-conversation-store.js"
		);
		const { createProviderChallengeControlPolicyStore, createProviderChallengeControlSender } =
			await import("../../src/relay/provider-challenge-control-sender.js");
		const { WHATSAPP_PROVIDER_CHALLENGE_COPY } = await import(
			"../../src/relay/whatsapp-provider-challenge-interceptor.js"
		);
		const conversationStore = createRelayConversationStore({ nowMs: () => NOW });
		mintConversation(conversationStore);
		const policyStore = createProviderChallengeControlPolicyStore({
			conversationStore,
			nowMs: () => NOW,
			makeRef: () => "system-control-abcdefghijklmnop",
		});
		const dispatched = vi.fn();
		const sender = createProviderChallengeControlSender({
			config,
			conversationStore,
			edgeRuntime: new TelclaudeEdgeRuntime({ now: () => new Date(NOW).toISOString() }),
			policyStore,
			dispatch: async (prepared) => {
				dispatched(prepared);
				expect(await policyStore.resolveConversation(prepared)).toMatchObject({
					conversationToken: expect.stringMatching(/^conv_/),
				});
				return DeliveryReceiptSchema.parse({
					schemaVersion: EdgeAdapterSchemaVersions.deliveryReceipt,
					outboundRef: prepared.outboundRef,
					platformMessageId: "wa-control-1",
					deliveryStatus: "sent",
					timestamps: {
						observedAt: new Date(NOW).toISOString(),
						sentAt: new Date(NOW).toISOString(),
					},
					retry: { attempt: 1, maxAttempts: 3, idempotencyKey: prepared.idempotencyKey },
				});
			},
		});

		await sender({
			templateId: "challenge_sent",
			body: WHATSAPP_PROVIDER_CHALLENGE_COPY.challenge_sent,
			replyAddressRef: ADDRESS,
			bindingId: "parent-a",
		});

		expect(dispatched).toHaveBeenCalledTimes(1);
		const [record] = policyStore.list();
		expect(record).toMatchObject({
			origin: "relay_system_provider_challenge_control",
			templateId: "challenge_sent",
			bindingId: "parent-a",
			status: "sent",
		});
		expect(record).not.toHaveProperty("body");
		expect(record).not.toHaveProperty("replyAddressRef");
	});

	it("rejects free-form copy before preparing or dispatching", async () => {
		const { TelclaudeEdgeRuntime } = await import("../../src/hermes/edge-adapter-runtime.js");
		const { createRelayConversationStore } = await import(
			"../../src/hermes/relay-conversation-store.js"
		);
		const { createProviderChallengeControlPolicyStore, createProviderChallengeControlSender } =
			await import("../../src/relay/provider-challenge-control-sender.js");
		const conversationStore = createRelayConversationStore({ nowMs: () => NOW });
		mintConversation(conversationStore);
		const policyStore = createProviderChallengeControlPolicyStore({ conversationStore });
		const dispatch = vi.fn();
		const sender = createProviderChallengeControlSender({
			config,
			conversationStore,
			edgeRuntime: new TelclaudeEdgeRuntime(),
			policyStore,
			dispatch,
		});

		await expect(
			sender({
				templateId: "challenge_sent",
				body: "send me a code",
				replyAddressRef: ADDRESS,
				bindingId: "parent-a",
			}),
		).rejects.toThrow(/relay-owned/);
		expect(dispatch).not.toHaveBeenCalled();
		expect(policyStore.list()).toEqual([]);
	});
});

function mintConversation(store: RelayConversationStore) {
	store.mint({
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
					address: ADDRESS,
					replyAddress: ADDRESS,
					displayName: "Parent A",
					subjectUserId: "household:parent-a",
				},
			],
		},
	],
} as TelclaudeConfig;
