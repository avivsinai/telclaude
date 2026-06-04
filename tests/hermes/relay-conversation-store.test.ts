import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;
const NOW = Date.parse("2026-06-04T08:00:00.000Z");

describe("Hermes relay conversation store", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-relay-conv-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		vi.resetModules();
		const { resetDatabase } = await import("../../src/storage/db.js");
		resetDatabase();
	});

	afterEach(async () => {
		const { closeDb } = await import("../../src/storage/db.js");
		closeDb();
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) {
			delete process.env.TELCLAUDE_DATA_DIR;
		} else {
			process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
		}
	});

	it("mints resolvable opaque tokens and rejects unminted well-formed tokens", async () => {
		const { createRelayConversationStore } = await loadStore();
		const store = createRelayConversationStore({ nowMs: () => NOW });

		const { token, conversation } = store.mint(baseInput("one"));

		expect(token).toMatch(/^conv_[0-9a-f]{32}$/);
		expect(conversation.token).toBe(token);
		expect(store.resolve(token)?.conversationId).toBe("conversation-one");
		expect(store.resolve(`conv_${"a".repeat(32)}`)).toBeNull();
	});

	it("retries bounded CSPRNG token collisions", async () => {
		const { createRelayConversationStore } = await loadStore();
		const firstToken = `conv_${"1".repeat(32)}`;
		const secondToken = `conv_${"2".repeat(32)}`;
		const tokens = [firstToken, firstToken, secondToken];
		const store = createRelayConversationStore({
			nowMs: () => NOW,
			tokenGenerator: () => tokens.shift() ?? `conv_${"3".repeat(32)}`,
		});

		expect(store.mint(baseInput("first")).token).toBe(firstToken);
		expect(store.mint(baseInput("second")).token).toBe(secondToken);
	});

	it("fails closed for expired, revoked, and denied rows while surfacing approval-required state", async () => {
		const { createRelayConversationStore } = await loadStore();
		const store = createRelayConversationStore({ nowMs: () => NOW });

		const expired = store.mint(baseInput("expired", { expiresAtMs: NOW + 1_000 }));
		expect(store.resolve(expired.token, NOW + 999)).not.toBeNull();
		expect(store.resolve(expired.token, NOW + 1_000)).toBeNull();
		expect(store.inspect(expired.token)?.conversationId).toBe("conversation-expired");

		const revoked = store.mint(baseInput("revoked"));
		store.revoke(revoked.token, "test revoke");
		expect(store.resolve(revoked.token)).toBeNull();
		expect(store.inspect(revoked.token)?.authorizationState).toBe("revoked");

		const denied = store.mint(baseInput("denied", { authorizationState: "denied" }));
		expect(store.resolve(denied.token)).toBeNull();

		const approvalRequired = store.mint(
			baseInput("approval", { authorizationState: "approval_required" }),
		);
		expect(store.resolve(approvalRequired.token)?.authorizationState).toBe("approval_required");
		expect(store.resolveAuthorized(approvalRequired.token)).toBeNull();
	});

	it("rejects member changes on revoked conversations", async () => {
		const { createRelayConversationStore } = await loadStore();
		const store = createRelayConversationStore({ nowMs: () => NOW });
		const { token } = store.mint(baseInput("revoked-add"));
		store.revoke(token, "no more members");

		expect(
			store.addMember(token, {
				actorId: "actor:new",
				principalId: "new@example.com",
				role: "recipient",
			}),
		).toEqual({ ok: false, reason: "conversation unavailable" });
	});

	it("survives restart with members, authority, message ids, cursor, audit ids, and permissions", async () => {
		const { createRelayConversationStore, RELAY_PAIRING_AUTHORITY_ACTOR_ID } = await loadStore();
		const store = createRelayConversationStore({ nowMs: () => NOW });
		const { token } = store.mint(baseInput("restart"));
		store.recordThreadMessageId(token, "message-1");
		store.updateInboundCursor(token, "uidvalidity:uid");
		store.linkAuditId(token, "audit-1");

		const { closeDb } = await import("../../src/storage/db.js");
		closeDb();
		vi.resetModules();

		const reloaded = await loadStore();
		const storeAfterRestart = reloaded.createRelayConversationStore({ nowMs: () => NOW });
		const conversation = storeAfterRestart.resolve(token);

		expect(
			conversation?.members.some((member) => member.actorId === RELAY_PAIRING_AUTHORITY_ACTOR_ID),
		).toBe(true);
		expect(conversation?.threadMessageIds).toEqual(["message-1"]);
		expect(conversation?.inboundCursor).toBe("uidvalidity:uid");
		expect(conversation?.auditIds).toEqual(["audit-1"]);
		expect(fs.statSync(tempDir).mode & 0o777).toBe(0o700);
		expect(fs.statSync(path.join(tempDir, "telclaude.db")).mode & 0o777).toBe(0o600);
	});

	it("normalizes canonical domains and fails closed for non-edge-projectable specialist domains", async () => {
		const {
			createRelayConversationStore,
			normalizeRelayConversationDomain,
			relayConversationToConversationRef,
		} = await loadStore();
		const store = createRelayConversationStore({ nowMs: () => NOW });

		const social = store.mint(baseInput("social", { domain: "social" })).conversation;
		expect(social.domain).toBe("public-social");
		expect(social.mcpDomain).toBe("social");
		expect(social.edgeDomain).toBe("public-social");

		const privateConversation = store.mint(
			baseInput("private", { domain: "private" }),
		).conversation;
		const household = store.mint(baseInput("household", { domain: "household" })).conversation;
		expect(privateConversation.domain).toBe("private");
		expect(household.domain).toBe("household");
		expect(normalizeRelayConversationDomain("social")).toBe("public-social");

		const specialist = store.mint(baseInput("specialist", { domain: "specialist" }));
		expect(store.resolveAuthorized(specialist.token)).toBeNull();
		expect(() => relayConversationToConversationRef(specialist.conversation)).toThrow(
			"not edge-projectable",
		);
	});

	it("projects schema-valid edge ConversationRef and relay authority ActorRef", async () => {
		const {
			RELAY_PAIRING_AUTHORITY_ACTOR_ID,
			createRelayConversationStore,
			relayAuthorityActorRefFor,
			relayConversationToConversationRef,
		} = await loadStore();
		const { ActorRefSchema, ConversationRefSchema } = await import(
			"../../src/hermes/edge-adapter-contract.js"
		);
		const store = createRelayConversationStore({ nowMs: () => NOW });
		const conversation = store.mint(baseInput("project")).conversation;

		const ref = relayConversationToConversationRef(conversation);
		expect(ConversationRefSchema.parse(ref)).toEqual(ref);
		expect(ref.recipients).toContainEqual(
			expect.objectContaining({
				actorId: RELAY_PAIRING_AUTHORITY_ACTOR_ID,
				role: "owner",
			}),
		);

		const actor = relayAuthorityActorRefFor(conversation);
		expect(ActorRefSchema.parse(actor)).toEqual(actor);
		expect(actor.actorId).toBe(RELAY_PAIRING_AUTHORITY_ACTOR_ID);
		expect(actor.identityAssurance).toBe("strong_link");
		expect(actor.scopes.flatMap((scope) => scope.actions)).toEqual(["send", "reply"]);
	});

	it("recomputes principal hashes and rejects mismatches", async () => {
		const { createRelayConversationStore } = await loadStore();
		const store = createRelayConversationStore({ nowMs: () => NOW });
		const conversation = store.mint(baseInput("hash")).conversation;
		const recipient = conversation.members.find(
			(member) => member.actorId === "actor:hash:recipient",
		);

		expect(recipient?.principalHash).toBe(sha256Digest("recipient-hash@example.com"));
		expect(() =>
			store.mint(
				baseInput("bad-hash", {
					members: [
						{
							actorId: "actor:bad-hash:sender",
							principalId: "sender@example.com",
							principalHash: sha256Digest("other@example.com"),
							role: "sender",
						},
					],
				}),
			),
		).toThrow("principalHash does not match principalId");
	});

	it("only sender and recipient members are targetable by reply intent", async () => {
		const {
			RELAY_PAIRING_AUTHORITY_ACTOR_ID,
			assertTargetableReplyIntent,
			createRelayConversationStore,
			targetableRelayConversationMembers,
		} = await loadStore();
		const store = createRelayConversationStore({ nowMs: () => NOW });
		const conversation = store.mint(
			baseInput("target", {
				members: [
					member("target", "sender", "sender", "sender-target@example.com"),
					member("target", "recipient", "recipient", "recipient-target@example.com"),
					member("target", "owner", "owner", "owner-target@example.com"),
					member("target", "observer", "observer", "observer-target@example.com"),
					{
						...member("target", "revoked", "recipient", "revoked-target@example.com"),
						revoked: true,
					},
				],
			}),
		).conversation;

		expect(targetableRelayConversationMembers(conversation).map((entry) => entry.actorId)).toEqual([
			"actor:target:sender",
			"actor:target:recipient",
		]);
		expect(() =>
			assertTargetableReplyIntent(conversation, { kind: "thread", threadId: "thread-target" }),
		).not.toThrow();
		expect(() =>
			assertTargetableReplyIntent(conversation, {
				kind: "actor",
				actorId: "actor:target:recipient",
			}),
		).not.toThrow();
		expect(() =>
			assertTargetableReplyIntent(conversation, {
				kind: "address",
				addressRef: "recipient-target@example.com",
			}),
		).not.toThrow();
		expect(() =>
			assertTargetableReplyIntent(conversation, { kind: "thread", threadId: "wrong-thread" }),
		).toThrow("thread is not bound");
		expect(() =>
			assertTargetableReplyIntent(conversation, { kind: "actor", actorId: "actor:target:owner" }),
		).toThrow("actor is not targetable");
		expect(() =>
			assertTargetableReplyIntent(conversation, {
				kind: "actor",
				actorId: RELAY_PAIRING_AUTHORITY_ACTOR_ID,
			}),
		).toThrow("actor is not targetable");
		expect(() =>
			assertTargetableReplyIntent(conversation, {
				kind: "address",
				addressRef: "owner-target@example.com",
			}),
		).toThrow("address is not targetable");
	});
});

async function loadStore(): Promise<typeof import("../../src/hermes/relay-conversation-store.js")> {
	return import("../../src/hermes/relay-conversation-store.js");
}

function baseInput(
	suffix: string,
	overrides: Record<string, unknown> = {},
): Record<string, unknown> {
	return {
		channel: "email",
		conversationId: `conversation-${suffix}`,
		threadId: `thread-${suffix}`,
		profileId: `profile-${suffix}`,
		domain: "public",
		routingSession: {
			sessionId: `session-${suffix}`,
			routeKey: `route-${suffix}`,
		},
		members: [
			member(suffix, "sender", "sender", `sender-${suffix}@example.com`),
			member(suffix, "recipient", "recipient", `recipient-${suffix}@example.com`),
		],
		nowMs: NOW,
		...overrides,
	};
}

function member(
	suffix: string,
	label: string,
	role: string,
	principalId: string,
): Record<string, unknown> {
	return {
		actorId: `actor:${suffix}:${label}`,
		principalId,
		role,
	};
}

function sha256Digest(value: string): string {
	return `sha256:${crypto.createHash("sha256").update(value, "utf8").digest("hex")}`;
}
