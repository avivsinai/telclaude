import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { TelclaudeConfig } from "../../src/config/config.js";
import {
	DeliveryReceiptSchema,
	EdgeAdapterSchemaVersions,
} from "../../src/hermes/edge-adapter-contract.js";
import { TelclaudeEdgeRuntime } from "../../src/hermes/edge-adapter-runtime.js";
import {
	createRelayConversationStore,
	type RelayConversationStore,
} from "../../src/hermes/relay-conversation-store.js";
import { createMediaActionConfirmationControlPolicyStore } from "../../src/relay/media-action-confirmation-control-policy.js";
import { createMediaActionConfirmationControlSender } from "../../src/relay/media-action-confirmation-control-sender.js";
import { mediaActionConfirmationCopy } from "../../src/relay/media-action-confirmation-copy.js";
import { closeDb, resetDatabase } from "../../src/storage/db.js";

const NOW = Date.parse("2026-07-18T09:00:00.000Z");
const ADDRESS = "whatsapp:+15551234567";
const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

describe("media action confirmation control sender", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-media-control-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		resetDatabase();
	});

	afterEach(() => {
		closeDb();
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) delete process.env.TELCLAUDE_DATA_DIR;
		else process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
	});

	it("delivers only fixed copy through a distinct one-shot policy", async () => {
		const conversationStore = createRelayConversationStore({ nowMs: () => NOW });
		mintConversation(conversationStore);
		const policyStore = createMediaActionConfirmationControlPolicyStore({
			conversationStore,
			nowMs: () => NOW,
		});
		let authorizedOutbound: Parameters<typeof policyStore.claim>[0] | null = null;
		const dispatch = vi.fn(async (prepared) => {
			authorizedOutbound = prepared;
			expect(await policyStore.resolveConversation(prepared)).toMatchObject({
				threadMessageIds: [],
			});
			return DeliveryReceiptSchema.parse({
				schemaVersion: EdgeAdapterSchemaVersions.deliveryReceipt,
				outboundRef: prepared.outboundRef,
				platformMessageId: "wa-media-control-1",
				deliveryStatus: "sent",
				timestamps: {
					observedAt: new Date(NOW).toISOString(),
					sentAt: new Date(NOW).toISOString(),
				},
				retry: { attempt: 1, maxAttempts: 3, idempotencyKey: prepared.idempotencyKey },
			});
		});
		const sender = createMediaActionConfirmationControlSender({
			config,
			conversationStore,
			edgeRuntime: new TelclaudeEdgeRuntime({ now: () => new Date(NOW).toISOString() }),
			dispatch,
			policyStore,
		});

		await sender({
			templateId: "choice_required",
			body: mediaActionConfirmationCopy("choice_required", "f"),
			bindingId: "parent-a",
			deliveryRef: "media-confirmation-a:choice_required",
		});

		expect(policyStore.list()).toEqual([
			expect.objectContaining({
				origin: "relay_system_media_action_confirmation_control",
				templateId: "choice_required",
				status: "sent",
			}),
		]);
		expect(policyStore.list()[0]).not.toHaveProperty("body");
		if (!authorizedOutbound) throw new Error("media control outbound missing");
		expect(policyStore.claim(authorizedOutbound)).toBe(false);
	});

	it("rejects free-form copy before dispatch", async () => {
		const conversationStore = createRelayConversationStore({ nowMs: () => NOW });
		mintConversation(conversationStore);
		const policyStore = createMediaActionConfirmationControlPolicyStore({ conversationStore });
		const dispatch = vi.fn();
		const sender = createMediaActionConfirmationControlSender({
			config,
			conversationStore,
			edgeRuntime: new TelclaudeEdgeRuntime(),
			dispatch,
			policyStore,
		});

		await expect(
			sender({
				templateId: "confirmed",
				body: "אושר",
				bindingId: "parent-a",
				deliveryRef: "media-confirmation-a:confirmed",
			}),
		).rejects.toThrow(/relay-owned/u);
		expect(dispatch).not.toHaveBeenCalled();
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
					addresseeGender: "f",
					address: ADDRESS,
					replyAddress: ADDRESS,
					displayName: "Parent A",
					subjectUserId: "household:parent-a",
				},
			],
		},
	],
} as TelclaudeConfig;
