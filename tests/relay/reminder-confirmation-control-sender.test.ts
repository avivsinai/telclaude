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
import { householdReminderConfirmationCopy } from "../../src/household-reminders/copy.js";
import { createReminderConfirmationControlPolicyStore } from "../../src/relay/reminder-confirmation-control-policy.js";
import { createReminderConfirmationControlSender } from "../../src/relay/reminder-confirmation-control-sender.js";
import { closeDb, resetDatabase } from "../../src/storage/db.js";

const NOW = Date.parse("2026-07-17T09:00:00.000Z");
const ADDRESS = "whatsapp:+15551234567";
const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

describe("reminder confirmation control sender", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-reminder-control-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		resetDatabase();
	});

	afterEach(() => {
		closeDb();
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) delete process.env.TELCLAUDE_DATA_DIR;
		else process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
	});

	it("delivers fixed copy under a distinct single-use system-origin policy", async () => {
		const conversationStore = createRelayConversationStore({ nowMs: () => NOW });
		mintConversation(conversationStore);
		const policyStore = createReminderConfirmationControlPolicyStore({
			conversationStore,
			nowMs: () => NOW,
			makeRef: () => "confirmation-abcdefghijklmnop",
		});
		let authorizedOutbound: Parameters<typeof policyStore.claim>[0] | null = null;
		const dispatch = vi.fn(async (prepared) => {
			authorizedOutbound = prepared;
			expect(await policyStore.resolveConversation(prepared)).toMatchObject({
				conversationToken: expect.stringMatching(/^conv_/),
			});
			return DeliveryReceiptSchema.parse({
				schemaVersion: EdgeAdapterSchemaVersions.deliveryReceipt,
				outboundRef: prepared.outboundRef,
				platformMessageId: "wa-reminder-control-1",
				deliveryStatus: "sent",
				timestamps: {
					observedAt: new Date(NOW).toISOString(),
					sentAt: new Date(NOW).toISOString(),
				},
				retry: { attempt: 1, maxAttempts: 3, idempotencyKey: prepared.idempotencyKey },
			});
		});
		const sender = createReminderConfirmationControlSender({
			config,
			conversationStore,
			edgeRuntime: new TelclaudeEdgeRuntime({ now: () => new Date(NOW).toISOString() }),
			dispatch,
			policyStore,
		});

		await sender({
			templateId: "confirmed",
			body: householdReminderConfirmationCopy("confirmed", "f"),
			replyAddressRef: ADDRESS,
			bindingId: "parent-a",
		});

		expect(dispatch).toHaveBeenCalledTimes(1);
		expect(policyStore.list()).toEqual([
			expect.objectContaining({
				origin: "relay_system_reminder_confirmation_control",
				templateId: "confirmed",
				addresseeGender: "f",
				status: "sent",
			}),
		]);
		expect(policyStore.list()[0]).not.toHaveProperty("body");
		expect(authorizedOutbound).not.toBeNull();
		if (!authorizedOutbound) throw new Error("authorized outbound was not dispatched");
		expect(policyStore.claim(authorizedOutbound)).toBe(false);
	});

	it("rejects free-form copy and a mismatched destination before dispatch", async () => {
		const conversationStore = createRelayConversationStore({ nowMs: () => NOW });
		mintConversation(conversationStore);
		const policyStore = createReminderConfirmationControlPolicyStore({ conversationStore });
		const dispatch = vi.fn();
		const sender = createReminderConfirmationControlSender({
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
				replyAddressRef: ADDRESS,
				bindingId: "parent-a",
			}),
		).rejects.toThrow(/relay-owned/);
		await expect(
			sender({
				templateId: "confirmed",
				body: householdReminderConfirmationCopy("confirmed", "f"),
				replyAddressRef: "whatsapp:+15550000999",
				bindingId: "parent-a",
			}),
		).rejects.toThrow(/binding is unavailable/);
		expect(dispatch).not.toHaveBeenCalled();
		expect(policyStore.list()).toEqual([]);
	});

	it("reconstructs the same byte-stable outbound for a pending receipt retry", async () => {
		const conversationStore = createRelayConversationStore({ nowMs: () => NOW });
		mintConversation(conversationStore);
		const policyStore = createReminderConfirmationControlPolicyStore({
			conversationStore,
			nowMs: () => NOW,
		});
		const preparedAttempts: Parameters<typeof policyStore.claim>[0][] = [];
		const dispatch = vi.fn(async (prepared) => {
			preparedAttempts.push(prepared);
			expect(await policyStore.resolveConversation(prepared)).toMatchObject({
				threadMessageIds: [],
			});
			return DeliveryReceiptSchema.parse({
				schemaVersion: EdgeAdapterSchemaVersions.deliveryReceipt,
				outboundRef: prepared.outboundRef,
				platformMessageId: "wa-reminder-control-stable",
				deliveryStatus: "sent",
				timestamps: {
					observedAt: new Date(NOW).toISOString(),
					sentAt: new Date(NOW).toISOString(),
				},
				retry: { attempt: 1, maxAttempts: 3, idempotencyKey: prepared.idempotencyKey },
			});
		});
		let edgeNow = NOW;
		const sender = createReminderConfirmationControlSender({
			config,
			conversationStore,
			edgeRuntime: new TelclaudeEdgeRuntime({ now: () => new Date(edgeNow).toISOString() }),
			dispatch,
			policyStore,
		});
		const input = {
			templateId: "confirmed" as const,
			body: householdReminderConfirmationCopy("confirmed", "f"),
			replyAddressRef: ADDRESS,
			bindingId: "parent-a",
			deliveryRef: `reminder-interception:${"a".repeat(64)}`,
		};

		await sender(input);
		edgeNow += 1_000;
		conversationStore.recordThreadMessageId(
			conversationStore.list({ channel: "whatsapp" })[0].token,
			"wa-reminder-control-stable",
		);
		await sender(input);

		expect(dispatch).toHaveBeenCalledTimes(2);
		const stableRequestFields = ({
			outboundRef,
			idempotencyKey,
			sideEffectLedgerRef,
			edgePreparedHash,
			resolvedDestination,
			finalRenderedBody,
			mediaRefs,
		}: Parameters<typeof policyStore.claim>[0]) => ({
			outboundRef,
			idempotencyKey,
			sideEffectLedgerRef,
			edgePreparedHash,
			resolvedDestination,
			finalRenderedBody,
			mediaRefs,
		});
		expect(stableRequestFields(preparedAttempts[1])).toEqual(
			stableRequestFields(preparedAttempts[0]),
		);
		expect(preparedAttempts[1].createdAt).not.toBe(preparedAttempts[0].createdAt);
		expect(preparedAttempts[0]).toMatchObject({
			outboundRef: expect.stringContaining(input.deliveryRef),
			idempotencyKey: expect.stringContaining(input.deliveryRef),
		});
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
