import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { TelclaudeConfig } from "../../src/config/config.js";

const NOW = Date.parse("2026-07-17T09:00:00.000Z");
const SECRET = "test-provider-login-coordinator-secret";
const ADDRESS = "whatsapp:+15551234567";
const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

describe("provider login coordinator", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-provider-login-"));
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

	it("arms only the exact authorized turn with current content-free consent", async () => {
		const fixture = await conversationFixture(configWithConsent());
		const { createPendingProviderChallengeRegistry } = await import(
			"../../src/relay/pending-provider-challenge.js"
		);
		const { createProviderLoginCoordinator } = await import(
			"../../src/relay/provider-login-coordinator.js"
		);
		const registry = createPendingProviderChallengeRegistry({
			nowMs: () => NOW,
			makeRef: () => "provider_challenge_ref",
		});
		const sendControl = vi.fn(async () => undefined);
		const initiate = vi.fn(async () => ({
			status: "challenge" as const,
			challengeId: "raw-sidecar-challenge",
			challengeType: "sms_otp" as const,
		}));
		const coordinator = createProviderLoginCoordinator({
			config: configWithConsent(),
			conversationStore: fixture.conversationStore,
			sidecar: { initiate, respond: vi.fn() },
			sendControl,
			registry,
			nowMs: () => NOW,
			makeInitiationRef: () => "provider_login_abcdefghijklmnop",
		});

		const result = await coordinator.start({
			origin: "relay_login_coordinator",
			bindingId: "parent-a",
			initiatingTurnRef: fixture.turn.ref,
		});

		expect(result).toEqual({
			status: "provider_challenge_armed",
			initiationRef: "provider_login_abcdefghijklmnop",
			expiresAtMs: NOW + 180_000,
		});
		expect(JSON.stringify(result)).not.toContain("raw-sidecar-challenge");
		expect(initiate).toHaveBeenCalledWith({
			actorUserId: "household:whatsapp:parent-a",
			subjectUserId: "household:parent-a",
		});
		expect(sendControl).toHaveBeenCalledWith({
			templateId: "challenge_sent",
			body: expect.any(String),
			replyAddressRef: ADDRESS,
			bindingId: "parent-a",
		});
		expect(
			registry.peekForInbound({
				bindingId: "parent-a",
				actorId: "household:whatsapp:parent-a",
				subjectUserId: "household:parent-a",
				profileId: "parent-a",
				conversationToken: fixture.conversation.token,
				conversationId: fixture.conversation.conversationId,
				senderPrincipalHash: digest(ADDRESS),
			}),
		).toEqual({ status: "armed", expiresAtMs: NOW + 180_000 });
	});

	it("fails closed when consent is absent or revoked before calling the sidecar", async () => {
		for (const [index, config] of [
			configWithoutConsent(),
			configWithConsent("revoked"),
		].entries()) {
			const fixture = await conversationFixture(config, "parent-a", String(index));
			const { createProviderLoginCoordinator } = await import(
				"../../src/relay/provider-login-coordinator.js"
			);
			const initiate = vi.fn();
			const coordinator = createProviderLoginCoordinator({
				config,
				conversationStore: fixture.conversationStore,
				sidecar: { initiate, respond: vi.fn() },
				sendControl: vi.fn(),
				nowMs: () => NOW,
			});

			await expect(
				coordinator.start({
					origin: "relay_login_coordinator",
					bindingId: "parent-a",
					initiatingTurnRef: fixture.turn.ref,
				}),
			).resolves.toEqual({ status: "denied" });
			expect(initiate).not.toHaveBeenCalled();
		}
	});

	it("denies a turn from another binding even when the requested binding has consent", async () => {
		const fixture = await conversationFixture(configWithConsent(), "parent-b");
		const { createProviderLoginCoordinator } = await import(
			"../../src/relay/provider-login-coordinator.js"
		);
		const initiate = vi.fn();
		const coordinator = createProviderLoginCoordinator({
			config: configWithConsent(),
			conversationStore: fixture.conversationStore,
			sidecar: { initiate, respond: vi.fn() },
			sendControl: vi.fn(),
			nowMs: () => NOW,
		});

		await expect(
			coordinator.start({
				origin: "relay_login_coordinator",
				bindingId: "parent-a",
				initiatingTurnRef: fixture.turn.ref,
			}),
		).resolves.toEqual({ status: "denied" });
		expect(initiate).not.toHaveBeenCalled();
	});
});

async function conversationFixture(
	config: TelclaudeConfig,
	bindingId = "parent-a",
	eventSuffix = "default",
) {
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
	const isA = bindingId === "parent-a";
	const address = isA ? ADDRESS : "whatsapp:+15557654321";
	const event = {
		schemaVersion: "telclaude.edge.whatsapp.inbound.v1" as const,
		eventId: `event-${bindingId}-${eventSuffix}`,
		messageId: `message-${bindingId}-${eventSuffix}`,
		cursorSequence: /^\d+$/.test(eventSuffix) ? Number(eventSuffix) + 1 : 1,
		chatKind: "direct" as const,
		senderAddressRef: address,
		conversationKey: isA
			? "whatsapp:15551234567@s.whatsapp.net"
			: "whatsapp:15557654321@s.whatsapp.net",
		text: "appointments",
		attachments: [],
		receivedAtMs: NOW,
	};
	const result = await pipeline.ingest({
		event,
		signature: signWhatsAppInboundBridgeEvent(event, SECRET),
	});
	if (!result.ok || result.duplicate || result.intercepted)
		throw new Error("fixture ingest failed");
	return { conversationStore, conversation: result.conversation, turn: result.turn };
}

function configWithConsent(state: "granted" | "revoked" = "granted"): TelclaudeConfig {
	return configFor({
		service: "clalit",
		state,
		ceremonyVersion: "phase0.v1",
		ceremonyHash: `sha256:${"a".repeat(64)}`,
		verifiedChannelHash: digest(ADDRESS),
		categories: {
			otpRelay: true,
			subjectOwnership: true,
			retentionDisclosure: true,
			emergencyUnderstanding: true,
		},
		recordedAt: "2026-07-17T08:00:00.000Z",
		operatorId: "operator:phase0-admin",
		...(state === "revoked" ? { revokedAt: "2026-07-17T08:30:00.000Z" } : {}),
	});
}

function configWithoutConsent(): TelclaudeConfig {
	return configFor();
}

function configFor(providerConsent?: Record<string, unknown>): TelclaudeConfig {
	const binding = (id: "parent-a" | "parent-b", address: string) => ({
		id,
		label: id,
		allowedSkills: [],
		providerScopes: ["clalit"],
		capabilityScopes: ["schedule.read", "schedule.write"],
		outboundChannels: ["whatsapp"],
		whatsappHouseholdBindings: [
			{
				bindingId: id,
				address,
				replyAddress: address,
				displayName: id,
				subjectUserId: `household:${id}`,
				...(id === "parent-a" && providerConsent ? { providerConsent } : {}),
			},
		],
	});
	return {
		profiles: [binding("parent-a", ADDRESS), binding("parent-b", "whatsapp:+15557654321")],
	} as TelclaudeConfig;
}

function digest(value: string): `sha256:${string}` {
	return `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
}
