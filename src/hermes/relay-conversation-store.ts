import crypto from "node:crypto";
import { z } from "zod";
import { getDb } from "../storage/db.js";
import {
	type ActorRef,
	ActorRefSchema,
	type ConversationRef,
	ConversationRefSchema,
	EdgeAdapterSchemaVersions,
} from "./edge-adapter-contract.js";
import type { TelclaudeMcpDomain } from "./mcp/bridge.js";

export const RELAY_PAIRING_AUTHORITY_ACTOR_ID = "relay:pairing-authority";
export const RELAY_PAIRING_AUTHORITY_PRINCIPAL_ID = "relay:pairing-authority";

const RELAY_CONVERSATION_TOKEN_RE = /^conv_[0-9a-f]{32}$/;
const RELAY_CONVERSATION_TURN_REF_RE = /^turn_[0-9a-f]{32}$/;
const MAX_TOKEN_MINT_ATTEMPTS = 8;

export class ConversationIdentityExistsError extends Error {
	constructor(channel: string, conversationId: string) {
		super(`relay conversation already exists for ${channel}:${conversationId} — use resumeOrMint`);
		this.name = "ConversationIdentityExistsError";
	}
}

type EdgeChannel = ConversationRef["channel"];
type EdgeTrustDomain = ConversationRef["domain"];
type AuthorizationState = ConversationRef["authorization"]["state"];
type IdentityAssurance = ActorRef["identityAssurance"];

export type RelayConversationDomain =
	| "private"
	| "household"
	| "public"
	| "public-social"
	| "specialist";

export type RelayConversationDomainInput = RelayConversationDomain | TelclaudeMcpDomain;

export type RelayConversationMemberRole =
	| "sender"
	| "recipient"
	| "observer"
	| "owner"
	| "relay-authority";

export type RelayConversationReplyIntent =
	| {
			readonly kind: "thread";
			readonly threadId: string;
	  }
	| {
			readonly kind: "actor";
			readonly actorId: string;
	  }
	| {
			readonly kind: "address";
			readonly addressRef: string;
	  };

export type RelayConversationMemberInput = {
	readonly actorId: string;
	readonly channel?: EdgeChannel;
	readonly principalId: string;
	readonly principalHash?: string;
	readonly displayName?: string;
	readonly role: RelayConversationMemberRole;
	readonly identityAssurance?: IdentityAssurance;
	readonly scopes?: readonly string[];
	readonly revoked?: boolean;
};

export type RelayConversationMember = {
	readonly actorId: string;
	readonly channel: EdgeChannel;
	readonly principalId: string;
	readonly principalHash: string;
	readonly displayName?: string;
	readonly role: RelayConversationMemberRole;
	readonly identityAssurance: IdentityAssurance;
	readonly scopes: readonly string[];
	readonly revoked: boolean;
};

export type RelayConversation = {
	readonly token: string;
	readonly channel: EdgeChannel;
	readonly conversationId: string;
	readonly threadId: string;
	readonly profileId: string;
	readonly domain: RelayConversationDomain;
	readonly mcpDomain: TelclaudeMcpDomain;
	readonly edgeDomain: EdgeTrustDomain | null;
	readonly routingSession: {
		readonly sessionId: string;
		readonly routeKey: string;
	};
	readonly authorizationState: AuthorizationState;
	readonly humanPairingProvenance: boolean;
	readonly authorizationScopes: readonly string[];
	readonly members: readonly RelayConversationMember[];
	readonly threadMessageIds: readonly string[];
	readonly inboundCursor: string | null;
	readonly auditIds: readonly string[];
	readonly createdAtMs: number;
	readonly expiresAtMs: number | null;
	readonly revokedAtMs: number | null;
	readonly revokeReason: string | null;
	readonly updatedAtMs: number;
};

export type RelayConversationMintInput = {
	readonly channel: EdgeChannel;
	readonly conversationId: string;
	readonly threadId: string;
	readonly profileId: string;
	readonly domain: RelayConversationDomainInput;
	readonly routingSession?: {
		readonly sessionId: string;
		readonly routeKey: string;
	};
	readonly authorizationState?: AuthorizationState;
	readonly humanPairingProvenance?: boolean;
	readonly authorizationScopes?: readonly string[];
	readonly members: readonly RelayConversationMemberInput[];
	readonly threadMessageIds?: readonly string[];
	readonly inboundCursor?: string | null;
	readonly auditIds?: readonly string[];
	readonly expiresAtMs?: number | null;
	readonly nowMs?: number;
};

export type RelayConversationInboundTurnMintInput = {
	readonly conversationToken: string;
	readonly inboundMessageId: string;
	readonly senderActorId: string;
	readonly expiresAtMs?: number | null;
	readonly nowMs?: number;
};

export type RelayConversationInboundTurn = {
	readonly ref: string;
	readonly conversationToken: string;
	readonly channel: EdgeChannel;
	readonly conversationId: string;
	readonly threadId: string;
	readonly profileId: string;
	readonly domain: RelayConversationDomain;
	readonly mcpDomain: TelclaudeMcpDomain;
	readonly inboundMessageId: string;
	readonly senderActorId: string;
	readonly senderPrincipalId: string;
	readonly createdAtMs: number;
	readonly expiresAtMs: number | null;
	readonly revokedAtMs: number | null;
	readonly revokeReason: string | null;
};

export type RelayConversationStore = {
	mint(input: RelayConversationMintInput): { token: string; conversation: RelayConversation };
	resumeOrMint(input: RelayConversationMintInput): {
		token: string;
		conversation: RelayConversation;
		resumed: boolean;
	};
	resolve(token: string, nowMs?: number): RelayConversation | null;
	resolveAuthorized(token: string, nowMs?: number): RelayConversation | null;
	inspect(token: string): RelayConversation | null;
	mintInboundTurn(input: RelayConversationInboundTurnMintInput): {
		turnRef: string;
		turn: RelayConversationInboundTurn;
	};
	resolveInboundTurn(ref: string, nowMs?: number): RelayConversationInboundTurn | null;
	resolveAuthorizedInboundTurn(
		ref: string,
		conversationToken: string,
		nowMs?: number,
	): RelayConversationInboundTurn | null;
	inspectInboundTurn(ref: string): RelayConversationInboundTurn | null;
	revokeInboundTurn(
		ref: string,
		reason: string,
		nowMs?: number,
	): RelayConversationInboundTurn | null;
	addMember(
		token: string,
		member: RelayConversationMemberInput,
	): { ok: true; conversation: RelayConversation } | { ok: false; reason: string };
	recordThreadMessageId(token: string, messageId: string): RelayConversation | null;
	updateInboundCursor(token: string, cursor: string): RelayConversation | null;
	linkAuditId(token: string, auditId: string): RelayConversation | null;
	revoke(token: string, reason: string): RelayConversation | null;
	list(filters?: {
		readonly channel?: EdgeChannel;
		readonly domain?: RelayConversationDomainInput;
		readonly authorizationState?: AuthorizationState;
	}): readonly RelayConversation[];
	cleanupExpired(nowMs: number): number;
};

export type RelayConversationStoreOptions = {
	readonly nowMs?: () => number;
	readonly tokenGenerator?: () => string;
};

const NonEmptyStringSchema = z.string().trim().min(1);
const PrincipalHashSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const EdgeChannelSchema = z.enum(["whatsapp", "email", "agentmail", "social"]);
const EdgeDomainSchema = z.enum(["private", "household", "public", "public-social"]);
const McpDomainSchema = z.enum(["private", "social", "household", "public", "specialist"]);
const RelayDomainSchema = z.enum(["private", "household", "public", "public-social", "specialist"]);
const AuthorizationStateSchema = z.enum(["authorized", "approval_required", "denied", "revoked"]);
const MemberRoleSchema = z.enum(["sender", "recipient", "observer", "owner", "relay-authority"]);
const IdentityAssuranceSchema = z.enum(["channel_bound", "paired", "verified", "strong_link"]);

const RelayConversationMemberSchema = z
	.object({
		actorId: NonEmptyStringSchema,
		channel: EdgeChannelSchema,
		principalId: NonEmptyStringSchema,
		principalHash: PrincipalHashSchema,
		displayName: NonEmptyStringSchema.optional(),
		role: MemberRoleSchema,
		identityAssurance: IdentityAssuranceSchema,
		scopes: z.array(NonEmptyStringSchema),
		revoked: z.boolean(),
	})
	.strict();

const StringListSchema = z.array(NonEmptyStringSchema);

type RelayConversationRow = {
	token: string;
	channel: EdgeChannel;
	conversation_id: string;
	thread_id: string;
	profile_id: string;
	domain: RelayConversationDomain;
	mcp_domain: TelclaudeMcpDomain;
	edge_domain: EdgeTrustDomain | null;
	routing_session_id: string;
	route_key: string;
	authorization_state: AuthorizationState;
	human_pairing_provenance: number;
	authorization_scopes_json: string;
	members_json: string;
	thread_message_ids_json: string;
	inbound_cursor: string | null;
	audit_ids_json: string;
	created_at_ms: number;
	expires_at_ms: number | null;
	revoked_at_ms: number | null;
	revoke_reason: string | null;
	updated_at_ms: number;
};

type RelayConversationInboundTurnRow = {
	ref: string;
	conversation_token: string;
	channel: EdgeChannel;
	conversation_id: string;
	thread_id: string;
	profile_id: string;
	domain: RelayConversationDomain;
	mcp_domain: TelclaudeMcpDomain;
	inbound_message_id: string;
	sender_actor_id: string;
	sender_principal_id: string;
	created_at_ms: number;
	expires_at_ms: number | null;
	revoked_at_ms: number | null;
	revoke_reason: string | null;
};

export function createRelayConversationStore(
	options: RelayConversationStoreOptions = {},
): RelayConversationStore {
	const nowMs = () => normalizeTimestamp(options.nowMs?.() ?? Date.now(), "nowMs");
	const tokenGenerator = options.tokenGenerator ?? createRelayConversationToken;

	const mintFresh = (normalized: RelayConversation) => {
		for (let attempt = 0; attempt < MAX_TOKEN_MINT_ATTEMPTS; attempt += 1) {
			const token = tokenGenerator();
			if (!isRelayConversationToken(token)) {
				throw new Error("conversation token generator produced invalid token");
			}
			try {
				insertConversation({ ...normalized, token });
				const conversation = selectConversation(token);
				if (!conversation) throw new Error("minted conversation missing after insert");
				return { token, conversation };
			} catch (error) {
				if (isSqliteIdentityConstraint(error)) {
					throw new ConversationIdentityExistsError(normalized.channel, normalized.conversationId);
				}
				if (isSqliteConstraint(error)) continue;
				throw error;
			}
		}
		throw new Error("could not mint unique relay conversation token");
	};

	return {
		mint(input) {
			const now = normalizeTimestamp(input.nowMs ?? nowMs(), "nowMs");
			return mintFresh(normalizeMintInput(input, now));
		},

		resumeOrMint(input) {
			const now = normalizeTimestamp(input.nowMs ?? nowMs(), "nowMs");
			const normalized = normalizeMintInput(input, now);
			for (let attempt = 0; attempt < MAX_TOKEN_MINT_ATTEMPTS; attempt += 1) {
				const existing = selectConversationByIdentity(
					normalized.channel,
					normalized.conversationId,
				);
				if (existing) {
					if (
						!conversationUnavailable(existing, now) &&
						conversationAuthorityMatches(existing, normalized)
					) {
						resumeConversation(existing, normalized, now);
						const conversation = selectConversation(existing.token);
						if (!conversation) throw new Error("resumed conversation missing after update");
						return { token: existing.token, conversation, resumed: true };
					}
					// Expired, revoked, denied, or authority shape changed: never resume — replace.
					deleteConversation(existing.token);
				}
				try {
					return { ...mintFresh(normalized), resumed: false };
				} catch (error) {
					// Lost a mint race for this identity; re-resolve and try to resume instead.
					if (error instanceof ConversationIdentityExistsError) continue;
					throw error;
				}
			}
			throw new Error("could not resume or mint relay conversation");
		},

		resolve(token, atMs = nowMs()) {
			if (!isRelayConversationToken(token)) return null;
			const conversation = selectConversation(token);
			if (!conversation || conversationUnavailable(conversation, atMs)) return null;
			return conversation;
		},

		resolveAuthorized(token, atMs = nowMs()) {
			const conversation = this.resolve(token, atMs);
			if (!conversation) return null;
			if (conversation.authorizationState !== "authorized") return null;
			if (conversation.edgeDomain === null) return null;
			return conversation;
		},

		inspect(token) {
			if (!isRelayConversationToken(token)) return null;
			return selectConversation(token);
		},

		mintInboundTurn(input) {
			const now = normalizeTimestamp(input.nowMs ?? nowMs(), "nowMs");
			const conversation = this.resolveAuthorized(input.conversationToken, now);
			if (!conversation) {
				throw new Error("conversation unavailable");
			}
			const senderActorId = requiredTrimmed(input.senderActorId, "senderActorId");
			const sender = conversation.members.find(
				(member) => member.actorId === senderActorId && !member.revoked,
			);
			if (!sender) {
				throw new Error("turn sender is not a conversation member");
			}
			if (sender.role !== "sender" && sender.role !== "recipient") {
				throw new Error("turn sender is not a targetable conversation member");
			}
			const turn = normalizeInboundTurnInput({
				ref: "",
				conversation,
				inboundMessageId: input.inboundMessageId,
				sender,
				nowMs: now,
				expiresAtMs: input.expiresAtMs,
			});
			for (let attempt = 0; attempt < MAX_TOKEN_MINT_ATTEMPTS; attempt += 1) {
				const ref = createRelayConversationTurnRef();
				try {
					insertInboundTurn({ ...turn, ref });
					const persisted = selectInboundTurn(ref);
					if (!persisted) throw new Error("minted inbound turn missing after insert");
					return { turnRef: ref, turn: persisted };
				} catch (error) {
					if (isSqliteConstraint(error)) continue;
					throw error;
				}
			}
			throw new Error("could not mint unique relay conversation turn ref");
		},

		resolveInboundTurn(ref, atMs = nowMs()) {
			if (!isRelayConversationTurnRef(ref)) return null;
			const turn = selectInboundTurn(ref);
			if (!turn || inboundTurnUnavailable(turn, atMs)) return null;
			const conversation = this.resolve(turn.conversationToken, atMs);
			if (!conversation) return null;
			return turn;
		},

		resolveAuthorizedInboundTurn(ref, conversationToken, atMs = nowMs()) {
			if (!isRelayConversationToken(conversationToken)) return null;
			const turn = this.resolveInboundTurn(ref, atMs);
			if (!turn || turn.conversationToken !== conversationToken) return null;
			if (!this.resolveAuthorized(conversationToken, atMs)) return null;
			return turn;
		},

		inspectInboundTurn(ref) {
			if (!isRelayConversationTurnRef(ref)) return null;
			return selectInboundTurn(ref);
		},

		revokeInboundTurn(ref, reason, atMs = nowMs()) {
			if (!isRelayConversationTurnRef(ref)) return null;
			const turn = this.inspectInboundTurn(ref);
			if (!turn) return null;
			const now = normalizeTimestamp(atMs, "nowMs");
			getDb()
				.prepare(
					`UPDATE hermes_relay_conversation_turns
					 SET revoked_at_ms = ?,
					     revoke_reason = ?
					 WHERE ref = ?`,
				)
				.run(now, requiredTrimmed(reason, "reason"), ref);
			return this.inspectInboundTurn(ref);
		},

		addMember(token, member) {
			const conversation = this.resolve(token);
			if (!conversation) return { ok: false, reason: "conversation unavailable" };
			if (conversation.revokedAtMs !== null || conversation.authorizationState === "revoked") {
				return { ok: false, reason: "conversation revoked" };
			}
			const normalizedMember = normalizeMember(member, conversation.channel);
			if (normalizedMember.actorId === RELAY_PAIRING_AUTHORITY_ACTOR_ID) {
				return { ok: false, reason: "relay authority member is managed by the store" };
			}
			const members = replaceMember(conversation.members, normalizedMember);
			updateJsonFields(token, {
				members_json: JSON.stringify(members),
				updated_at_ms: nowMs(),
			});
			const updated = this.resolve(token);
			if (!updated) return { ok: false, reason: "conversation unavailable after update" };
			return { ok: true, conversation: updated };
		},

		recordThreadMessageId(token, messageId) {
			const conversation = this.resolve(token);
			if (!conversation) return null;
			const ids = uniqueStrings([
				...conversation.threadMessageIds,
				requiredTrimmed(messageId, "messageId"),
			]);
			updateJsonFields(token, {
				thread_message_ids_json: JSON.stringify(ids),
				updated_at_ms: nowMs(),
			});
			return this.resolve(token);
		},

		updateInboundCursor(token, cursor) {
			const conversation = this.resolve(token);
			if (!conversation) return null;
			updateJsonFields(token, {
				inbound_cursor: requiredTrimmed(cursor, "cursor"),
				updated_at_ms: nowMs(),
			});
			return this.resolve(token);
		},

		linkAuditId(token, auditId) {
			const conversation = this.resolve(token);
			if (!conversation) return null;
			const auditIds = uniqueStrings([
				...conversation.auditIds,
				requiredTrimmed(auditId, "auditId"),
			]);
			updateJsonFields(token, {
				audit_ids_json: JSON.stringify(auditIds),
				updated_at_ms: nowMs(),
			});
			return this.resolve(token);
		},

		revoke(token, reason) {
			const conversation = this.inspect(token);
			if (!conversation) return null;
			const now = nowMs();
			getDb()
				.prepare(
					`UPDATE hermes_relay_conversations
					 SET authorization_state = 'revoked',
					     revoked_at_ms = ?,
					     revoke_reason = ?,
					     updated_at_ms = ?
					 WHERE token = ?`,
				)
				.run(now, requiredTrimmed(reason, "reason"), now, token);
			return this.inspect(token);
		},

		list(filters = {}) {
			const rows = getDb()
				.prepare("SELECT * FROM hermes_relay_conversations ORDER BY created_at_ms ASC")
				.all() as RelayConversationRow[];
			const domain = filters.domain ? normalizeRelayConversationDomain(filters.domain) : undefined;
			return rows
				.map(deserializeConversation)
				.filter((conversation): conversation is RelayConversation => conversation !== null)
				.filter((conversation) => {
					if (filters.channel && conversation.channel !== filters.channel) return false;
					if (domain && conversation.domain !== domain) return false;
					if (
						filters.authorizationState &&
						conversation.authorizationState !== filters.authorizationState
					) {
						return false;
					}
					return true;
				});
		},

		cleanupExpired(atMs) {
			const result = getDb()
				.prepare(
					"DELETE FROM hermes_relay_conversations WHERE expires_at_ms IS NOT NULL AND expires_at_ms <= ?",
				)
				.run(normalizeTimestamp(atMs, "nowMs"));
			return result.changes;
		},
	};
}

export function createRelayConversationToken(): string {
	return `conv_${crypto.randomBytes(16).toString("hex")}`;
}

export function isRelayConversationToken(value: string): boolean {
	return RELAY_CONVERSATION_TOKEN_RE.test(value);
}

export function createRelayConversationTurnRef(): string {
	return `turn_${crypto.randomBytes(16).toString("hex")}`;
}

export function isRelayConversationTurnRef(value: string): boolean {
	return RELAY_CONVERSATION_TURN_REF_RE.test(value);
}

export function normalizeRelayConversationDomain(
	domain: RelayConversationDomainInput,
): RelayConversationDomain {
	switch (domain) {
		case "private":
		case "household":
		case "public":
		case "public-social":
		case "specialist":
			return domain;
		case "social":
			return "public-social";
		default:
			throw new Error(`unsupported relay conversation domain: ${String(domain)}`);
	}
}

export function relayDomainToMcpDomain(domain: RelayConversationDomain): TelclaudeMcpDomain {
	if (domain === "public-social") return "social";
	return domain;
}

export function relayDomainToEdgeDomain(domain: RelayConversationDomain): EdgeTrustDomain | null {
	if (domain === "specialist") return null;
	return domain;
}

export function relayConversationToConversationRef(
	conversation: RelayConversation,
): ConversationRef {
	if (conversation.edgeDomain === null) {
		throw new Error("relay conversation domain is not edge-projectable");
	}
	return ConversationRefSchema.parse({
		schemaVersion: EdgeAdapterSchemaVersions.conversationRef,
		channel: conversation.channel,
		conversationId: conversation.conversationId,
		threadId: conversation.threadId,
		profileId: conversation.profileId,
		domain: conversation.edgeDomain,
		recipients: conversation.members.map((member) => ({
			actorId: member.actorId,
			channelIdentity: {
				channel: member.channel,
				principalId: member.principalId,
				...(member.displayName ? { displayName: member.displayName } : {}),
			},
			role: member.role === "relay-authority" ? "owner" : member.role,
		})),
		routingSession: conversation.routingSession,
		authorization: {
			state: conversation.authorizationState,
			scopes: [...conversation.authorizationScopes],
			revoked: conversation.revokedAtMs !== null || conversation.authorizationState === "revoked",
		},
	});
}

export function relayAuthorityActorRefFor(conversation: RelayConversation): ActorRef {
	const authority = conversation.members.find(
		(member) => member.actorId === RELAY_PAIRING_AUTHORITY_ACTOR_ID,
	);
	if (!authority || authority.revoked) {
		throw new Error("relay authority member missing or revoked");
	}
	return ActorRefSchema.parse({
		schemaVersion: EdgeAdapterSchemaVersions.actorRef,
		actorId: RELAY_PAIRING_AUTHORITY_ACTOR_ID,
		channelIdentity: {
			channel: conversation.channel,
			principalId: RELAY_PAIRING_AUTHORITY_PRINCIPAL_ID,
			...(authority.displayName ? { displayName: authority.displayName } : {}),
		},
		identityAssurance: "strong_link",
		scopes: [
			{
				scope: "relay:pairing-authority",
				actions: ["send", "reply"],
				grantedAt: new Date(conversation.createdAtMs).toISOString(),
				...(conversation.expiresAtMs !== null
					? { expiresAt: new Date(conversation.expiresAtMs).toISOString() }
					: {}),
			},
		],
		revocation: {
			revoked: false,
		},
	});
}

export function targetableRelayConversationMembers(
	conversation: RelayConversation,
): readonly RelayConversationMember[] {
	return conversation.members.filter((member) => {
		if (member.revoked) return false;
		return member.role === "sender" || member.role === "recipient";
	});
}

export function assertTargetableReplyIntent(
	conversation: RelayConversation,
	replyIntent: RelayConversationReplyIntent,
): void {
	const members = targetableRelayConversationMembers(conversation);
	if (members.length === 0) {
		throw new Error("reply intent conversation has no targetable members");
	}
	if (replyIntent.kind === "thread") {
		if (replyIntent.threadId !== conversation.threadId) {
			throw new Error("reply intent thread is not bound to conversation");
		}
		return;
	}

	if (replyIntent.kind === "actor") {
		if (!members.some((member) => member.actorId === replyIntent.actorId)) {
			throw new Error("reply intent actor is not targetable");
		}
		return;
	}

	if (!members.some((member) => member.principalId === replyIntent.addressRef)) {
		throw new Error("reply intent address is not targetable");
	}
}

function normalizeMintInput(input: RelayConversationMintInput, nowMs: number): RelayConversation {
	const domain = normalizeRelayConversationDomain(input.domain);
	const channel = EdgeChannelSchema.parse(input.channel);
	const conversationId = requiredTrimmed(input.conversationId, "conversationId");
	const threadId = requiredTrimmed(input.threadId, "threadId");
	const profileId = requiredTrimmed(input.profileId, "profileId");
	const edgeDomain = relayDomainToEdgeDomain(domain);
	const routingSession = {
		sessionId:
			input.routingSession?.sessionId ??
			`${channel}:${domain}:${hashShort(`${conversationId}:${threadId}`)}:session`,
		routeKey:
			input.routingSession?.routeKey ?? `${channel}:${domain}:${conversationId}:${threadId}`,
	};
	const members = withRelayAuthorityMember(
		input.members.map((member) => normalizeMember(member, channel)),
		channel,
	);

	return {
		token: "",
		channel,
		conversationId,
		threadId,
		profileId,
		domain,
		mcpDomain: relayDomainToMcpDomain(domain),
		edgeDomain,
		routingSession: {
			sessionId: requiredTrimmed(routingSession.sessionId, "routingSession.sessionId"),
			routeKey: requiredTrimmed(routingSession.routeKey, "routingSession.routeKey"),
		},
		authorizationState: AuthorizationStateSchema.parse(input.authorizationState ?? "authorized"),
		humanPairingProvenance: input.humanPairingProvenance === true,
		authorizationScopes: uniqueStrings(
			input.authorizationScopes ?? ["message:read", "message:reply"],
		),
		members,
		threadMessageIds: uniqueStrings(input.threadMessageIds ?? []),
		inboundCursor: input.inboundCursor
			? requiredTrimmed(input.inboundCursor, "inboundCursor")
			: null,
		auditIds: uniqueStrings(input.auditIds ?? []),
		createdAtMs: nowMs,
		expiresAtMs:
			input.expiresAtMs === undefined || input.expiresAtMs === null
				? null
				: normalizeTimestamp(input.expiresAtMs, "expiresAtMs"),
		revokedAtMs: null,
		revokeReason: null,
		updatedAtMs: nowMs,
	};
}

function normalizeMember(
	input: RelayConversationMemberInput,
	defaultChannel: EdgeChannel,
): RelayConversationMember {
	const principalId = requiredTrimmed(input.principalId, "principalId");
	const principalHash = sha256Digest(principalId);
	if (input.principalHash !== undefined && input.principalHash !== principalHash) {
		throw new Error("principalHash does not match principalId");
	}
	const member: RelayConversationMember = {
		actorId: requiredTrimmed(input.actorId, "actorId"),
		channel: EdgeChannelSchema.parse(input.channel ?? defaultChannel),
		principalId,
		principalHash,
		...(input.displayName
			? { displayName: requiredTrimmed(input.displayName, "displayName") }
			: {}),
		role: MemberRoleSchema.parse(input.role),
		identityAssurance: IdentityAssuranceSchema.parse(input.identityAssurance ?? "channel_bound"),
		scopes: uniqueStrings(input.scopes ?? []),
		revoked: input.revoked ?? false,
	};
	return RelayConversationMemberSchema.parse(member);
}

function withRelayAuthorityMember(
	members: readonly RelayConversationMember[],
	channel: EdgeChannel,
): readonly RelayConversationMember[] {
	const authorityMembers = members.filter(
		(member) => member.actorId === RELAY_PAIRING_AUTHORITY_ACTOR_ID,
	);
	if (authorityMembers.length > 1) {
		throw new Error("relay authority member must be unique");
	}
	if (authorityMembers.length === 1) {
		const authority = authorityMembers[0];
		if (
			authority.role !== "relay-authority" ||
			authority.principalId !== RELAY_PAIRING_AUTHORITY_PRINCIPAL_ID ||
			authority.principalHash !== sha256Digest(RELAY_PAIRING_AUTHORITY_PRINCIPAL_ID) ||
			authority.identityAssurance !== "strong_link" ||
			authority.revoked ||
			!authority.scopes.includes("send") ||
			!authority.scopes.includes("reply")
		) {
			throw new Error("relay authority member is malformed");
		}
		return members;
	}
	return [
		...members,
		RelayConversationMemberSchema.parse({
			actorId: RELAY_PAIRING_AUTHORITY_ACTOR_ID,
			channel,
			principalId: RELAY_PAIRING_AUTHORITY_PRINCIPAL_ID,
			principalHash: sha256Digest(RELAY_PAIRING_AUTHORITY_PRINCIPAL_ID),
			role: "relay-authority",
			identityAssurance: "strong_link",
			scopes: ["send", "reply"],
			revoked: false,
		}),
	];
}

function replaceMember(
	members: readonly RelayConversationMember[],
	member: RelayConversationMember,
): readonly RelayConversationMember[] {
	return [...members.filter((existing) => existing.actorId !== member.actorId), member];
}

function normalizeInboundTurnInput(input: {
	readonly ref: string;
	readonly conversation: RelayConversation;
	readonly inboundMessageId: string;
	readonly sender: RelayConversationMember;
	readonly nowMs: number;
	readonly expiresAtMs?: number | null;
}): RelayConversationInboundTurn {
	return {
		ref: input.ref,
		conversationToken: input.conversation.token,
		channel: input.conversation.channel,
		conversationId: input.conversation.conversationId,
		threadId: input.conversation.threadId,
		profileId: input.conversation.profileId,
		domain: input.conversation.domain,
		mcpDomain: input.conversation.mcpDomain,
		inboundMessageId: requiredTrimmed(input.inboundMessageId, "inboundMessageId"),
		senderActorId: input.sender.actorId,
		senderPrincipalId: input.sender.principalId,
		createdAtMs: input.nowMs,
		expiresAtMs:
			input.expiresAtMs === undefined || input.expiresAtMs === null
				? null
				: normalizeTimestamp(input.expiresAtMs, "expiresAtMs"),
		revokedAtMs: null,
		revokeReason: null,
	};
}

function insertConversation(conversation: RelayConversation): void {
	getDb()
		.prepare(
			`INSERT INTO hermes_relay_conversations (
				token,
				channel,
				conversation_id,
				thread_id,
				profile_id,
				domain,
				mcp_domain,
				edge_domain,
				routing_session_id,
				route_key,
				authorization_state,
				human_pairing_provenance,
				authorization_scopes_json,
				members_json,
				thread_message_ids_json,
				inbound_cursor,
				audit_ids_json,
				created_at_ms,
				expires_at_ms,
				revoked_at_ms,
				revoke_reason,
				updated_at_ms
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		)
		.run(
			conversation.token,
			conversation.channel,
			conversation.conversationId,
			conversation.threadId,
			conversation.profileId,
			conversation.domain,
			conversation.mcpDomain,
			conversation.edgeDomain,
			conversation.routingSession.sessionId,
			conversation.routingSession.routeKey,
			conversation.authorizationState,
			conversation.humanPairingProvenance ? 1 : 0,
			JSON.stringify(conversation.authorizationScopes),
			JSON.stringify(conversation.members),
			JSON.stringify(conversation.threadMessageIds),
			conversation.inboundCursor,
			JSON.stringify(conversation.auditIds),
			conversation.createdAtMs,
			conversation.expiresAtMs,
			conversation.revokedAtMs,
			conversation.revokeReason,
			conversation.updatedAtMs,
		);
}

function insertInboundTurn(turn: RelayConversationInboundTurn): void {
	getDb()
		.prepare(
			`INSERT INTO hermes_relay_conversation_turns (
				ref,
				conversation_token,
				channel,
				conversation_id,
				thread_id,
				profile_id,
				domain,
				mcp_domain,
				inbound_message_id,
				sender_actor_id,
				sender_principal_id,
				created_at_ms,
				expires_at_ms,
				revoked_at_ms,
				revoke_reason
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		)
		.run(
			turn.ref,
			turn.conversationToken,
			turn.channel,
			turn.conversationId,
			turn.threadId,
			turn.profileId,
			turn.domain,
			turn.mcpDomain,
			turn.inboundMessageId,
			turn.senderActorId,
			turn.senderPrincipalId,
			turn.createdAtMs,
			turn.expiresAtMs,
			turn.revokedAtMs,
			turn.revokeReason,
		);
}

function selectConversation(token: string): RelayConversation | null {
	const row = getDb()
		.prepare("SELECT * FROM hermes_relay_conversations WHERE token = ?")
		.get(token) as RelayConversationRow | undefined;
	if (!row) return null;
	return deserializeConversation(row);
}

function selectConversationByIdentity(
	channel: EdgeChannel,
	conversationId: string,
): RelayConversation | null {
	const row = getDb()
		.prepare("SELECT * FROM hermes_relay_conversations WHERE channel = ? AND conversation_id = ?")
		.get(channel, conversationId) as RelayConversationRow | undefined;
	if (!row) return null;
	return deserializeConversation(row);
}

function deleteConversation(token: string): void {
	getDb().prepare("DELETE FROM hermes_relay_conversations WHERE token = ?").run(token);
}

/**
 * A conversation may only be resumed when every authority-relevant field matches
 * the new turn's normalized mint input. Any change in authority shape (profile,
 * domain, thread, scopes, pairing provenance) replaces the conversation instead.
 */
function conversationAuthorityMatches(
	existing: RelayConversation,
	normalized: RelayConversation,
): boolean {
	return (
		existing.threadId === normalized.threadId &&
		existing.profileId === normalized.profileId &&
		existing.domain === normalized.domain &&
		existing.mcpDomain === normalized.mcpDomain &&
		existing.edgeDomain === normalized.edgeDomain &&
		existing.authorizationState === normalized.authorizationState &&
		existing.humanPairingProvenance === normalized.humanPairingProvenance &&
		existing.authorizationScopes.length === normalized.authorizationScopes.length &&
		existing.authorizationScopes.every((scope) => normalized.authorizationScopes.includes(scope))
	);
}

function resumeConversation(
	existing: RelayConversation,
	normalized: RelayConversation,
	nowMs: number,
): void {
	let members = existing.members;
	for (const member of normalized.members) {
		members = replaceMember(members, member);
	}
	getDb()
		.prepare(
			`UPDATE hermes_relay_conversations SET
				routing_session_id = ?,
				route_key = ?,
				members_json = ?,
				thread_message_ids_json = ?,
				inbound_cursor = ?,
				audit_ids_json = ?,
				expires_at_ms = ?,
				updated_at_ms = ?
			WHERE token = ?`,
		)
		.run(
			normalized.routingSession.sessionId,
			normalized.routingSession.routeKey,
			JSON.stringify(members),
			JSON.stringify(uniqueStrings([...existing.threadMessageIds, ...normalized.threadMessageIds])),
			normalized.inboundCursor ?? existing.inboundCursor,
			JSON.stringify(uniqueStrings([...existing.auditIds, ...normalized.auditIds])),
			normalized.expiresAtMs,
			nowMs,
			existing.token,
		);
}

function selectInboundTurn(ref: string): RelayConversationInboundTurn | null {
	const row = getDb()
		.prepare("SELECT * FROM hermes_relay_conversation_turns WHERE ref = ?")
		.get(ref) as RelayConversationInboundTurnRow | undefined;
	if (!row) return null;
	return deserializeInboundTurn(row);
}

function deserializeConversation(row: RelayConversationRow): RelayConversation | null {
	try {
		const members = z.array(RelayConversationMemberSchema).parse(JSON.parse(row.members_json));
		const authorizationScopes = StringListSchema.parse(JSON.parse(row.authorization_scopes_json));
		const threadMessageIds = StringListSchema.parse(JSON.parse(row.thread_message_ids_json));
		const auditIds = StringListSchema.parse(JSON.parse(row.audit_ids_json));
		const domain = RelayDomainSchema.parse(row.domain);
		const edgeDomain = row.edge_domain === null ? null : EdgeDomainSchema.parse(row.edge_domain);
		return {
			token: row.token,
			channel: EdgeChannelSchema.parse(row.channel),
			conversationId: row.conversation_id,
			threadId: row.thread_id,
			profileId: row.profile_id,
			domain,
			mcpDomain: McpDomainSchema.parse(row.mcp_domain),
			edgeDomain,
			routingSession: {
				sessionId: row.routing_session_id,
				routeKey: row.route_key,
			},
			authorizationState: AuthorizationStateSchema.parse(row.authorization_state),
			humanPairingProvenance: row.human_pairing_provenance === 1,
			authorizationScopes,
			members,
			threadMessageIds,
			inboundCursor: row.inbound_cursor,
			auditIds,
			createdAtMs: row.created_at_ms,
			expiresAtMs: row.expires_at_ms,
			revokedAtMs: row.revoked_at_ms,
			revokeReason: row.revoke_reason,
			updatedAtMs: row.updated_at_ms,
		};
	} catch {
		return null;
	}
}

function deserializeInboundTurn(
	row: RelayConversationInboundTurnRow,
): RelayConversationInboundTurn | null {
	try {
		return {
			ref: row.ref,
			conversationToken: row.conversation_token,
			channel: EdgeChannelSchema.parse(row.channel),
			conversationId: row.conversation_id,
			threadId: row.thread_id,
			profileId: row.profile_id,
			domain: RelayDomainSchema.parse(row.domain),
			mcpDomain: McpDomainSchema.parse(row.mcp_domain),
			inboundMessageId: row.inbound_message_id,
			senderActorId: row.sender_actor_id,
			senderPrincipalId: row.sender_principal_id,
			createdAtMs: normalizeTimestamp(row.created_at_ms, "createdAtMs"),
			expiresAtMs:
				row.expires_at_ms === null ? null : normalizeTimestamp(row.expires_at_ms, "expiresAtMs"),
			revokedAtMs:
				row.revoked_at_ms === null ? null : normalizeTimestamp(row.revoked_at_ms, "revokedAtMs"),
			revokeReason: row.revoke_reason,
		};
	} catch {
		return null;
	}
}

function updateJsonFields(
	token: string,
	fields: {
		readonly members_json?: string;
		readonly thread_message_ids_json?: string;
		readonly inbound_cursor?: string;
		readonly audit_ids_json?: string;
		readonly updated_at_ms: number;
	},
): void {
	const assignments = Object.keys(fields)
		.filter((key) => key !== "updated_at_ms")
		.map((key) => `${key} = ?`);
	assignments.push("updated_at_ms = ?");
	const values = Object.entries(fields)
		.filter(([key]) => key !== "updated_at_ms")
		.map(([, value]) => value);
	values.push(fields.updated_at_ms, token);
	getDb()
		.prepare(`UPDATE hermes_relay_conversations SET ${assignments.join(", ")} WHERE token = ?`)
		.run(...values);
}

function conversationUnavailable(conversation: RelayConversation, nowMs: number): boolean {
	if (conversation.expiresAtMs !== null && conversation.expiresAtMs <= nowMs) return true;
	if (conversation.revokedAtMs !== null) return true;
	if (
		conversation.authorizationState === "revoked" ||
		conversation.authorizationState === "denied"
	) {
		return true;
	}
	return false;
}

function inboundTurnUnavailable(turn: RelayConversationInboundTurn, nowMs: number): boolean {
	if (turn.expiresAtMs !== null && turn.expiresAtMs <= nowMs) return true;
	if (turn.revokedAtMs !== null) return true;
	return false;
}

function sha256Digest(value: string): string {
	return `sha256:${crypto.createHash("sha256").update(value, "utf8").digest("hex")}`;
}

function hashShort(value: string): string {
	return crypto.createHash("sha256").update(value, "utf8").digest("hex").slice(0, 12);
}

function uniqueStrings(values: readonly string[]): readonly string[] {
	return [...new Set(values.map((value) => requiredTrimmed(value, "value")))];
}

function requiredTrimmed(value: string, label: string): string {
	const trimmed = value.trim();
	if (!trimmed) throw new Error(`${label} is required`);
	return trimmed;
}

function normalizeTimestamp(value: number, label: string): number {
	if (!Number.isSafeInteger(value) || value < 0) {
		throw new Error(`${label} must be a non-negative safe integer`);
	}
	return value;
}

function isSqliteConstraint(error: unknown): boolean {
	return (
		typeof error === "object" &&
		error !== null &&
		"code" in error &&
		(error as { code?: unknown }).code === "SQLITE_CONSTRAINT_PRIMARYKEY"
	);
}

/** UNIQUE(channel, conversation_id) violation — a new token can never resolve this. */
function isSqliteIdentityConstraint(error: unknown): boolean {
	return (
		error instanceof Error &&
		"code" in error &&
		(error as { code?: unknown }).code === "SQLITE_CONSTRAINT_UNIQUE" &&
		error.message.includes("hermes_relay_conversations.channel")
	);
}
