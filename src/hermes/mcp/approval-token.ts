import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import Database from "better-sqlite3";
import { z } from "zod";
import { sortKeysDeep } from "../../crypto/canonical-hash.js";
import {
	TELCLAUDE_MCP_BROWSER_WRITE_APPROVAL_DOMAIN,
	TELCLAUDE_MCP_OUTBOUND_APPROVAL_DOMAIN,
	TELCLAUDE_MCP_PROVIDER_APPROVAL_DOMAIN,
	TELCLAUDE_MCP_SCHEDULED_OUTBOUND_APPROVAL_DOMAIN,
} from "../../security/approval-domains.js";
import {
	getTelclaudeMcpSideEffectApprovalBinding,
	type TelclaudeMcpBrowserWriteApprovalBinding,
	type TelclaudeMcpOutboundApprovalBinding,
	type TelclaudeMcpProviderApprovalBinding,
	type TelclaudeMcpScheduledOutboundApprovalBinding,
	type TelclaudeMcpSideEffectApprovalBinding,
	type TelclaudeMcpSideEffectApprovalVerifier,
} from "./side-effect-ledger.js";

const DEFAULT_TOKEN_TTL_SECONDS = 60;
const MAX_MINT_TOKEN_TTL_SECONDS = 60;
const MAX_VERIFY_TOKEN_TTL_SECONDS = MAX_MINT_TOKEN_TTL_SECONDS;
const APPROVAL_AUDIENCE = "telclaude-hermes-mcp-side-effect";
const JTI_DATABASE_NAME = "hermes_mcp_side_effect_approval_jti.sqlite";

const NonEmptyString = z.string().trim().min(1);
const HashSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const Sha256RefSchema = HashSchema.transform((value) => value as `sha256:${string}`);
const PrincipalHashSchema = HashSchema.transform((value) => value as `sha256:${string}`);
const HmacRevisionSchema = z.string().regex(/^hmac-sha256:[a-f0-9]{64}$/);
const EdgePreparedHashSchema = z.string().regex(/^[a-f0-9]{64}$/);
const TurnConversationRefSchema = z.string().regex(/^turn_[0-9a-f]{32}$/);
const DomainSchema = z.enum(["private", "social", "household", "public", "specialist"]);
const BrowserAuthorityDomainSchema = z.enum(["private", "public-social", "household", "public"]);
const ResolvedDestinationSchema = z
	.object({
		kind: z.enum(["thread", "actor", "address"]),
		threadId: NonEmptyString.optional(),
		actorId: NonEmptyString.optional(),
		addressRef: NonEmptyString.optional(),
		conversationId: NonEmptyString.optional(),
	})
	.strict();
const PreparedMediaRefSchema = z
	.object({
		quarantineId: NonEmptyString,
		contentHash: HashSchema,
		mediaType: NonEmptyString.regex(/^[^\s/]+\/[^\s/]+$/u).optional(),
		redactedFilename: z
			.string()
			.trim()
			.min(1)
			.max(180)
			.regex(/^[A-Za-z0-9][A-Za-z0-9._ -]*$/u)
			.refine((value) => value !== "." && value !== "..")
			.optional(),
		sizeBytes: z.number().int().nonnegative().optional(),
	})
	.strict()
	.refine((value) => {
		const count = [value.mediaType, value.redactedFilename, value.sizeBytes].filter(
			(item) => item !== undefined,
		).length;
		return count === 0 || count === 3;
	}, "prepared media metadata must be complete");
const AuthorizationStateSchema = z.enum(["authorized", "approval_required", "denied", "revoked"]);
const HouseholdReplyBindingSchema = z
	.object({
		bindingId: NonEmptyString,
		subjectUserId: NonEmptyString,
		senderPrincipalHash: PrincipalHashSchema,
		recipientPrincipalHash: PrincipalHashSchema,
		identityAssurance: z.literal("strong_link"),
	})
	.strict();
const HouseholdReminderPolicyBaseSchema = z.object({
	reminderId: NonEmptyString,
	fireId: NonEmptyString,
	revision: z.number().int().min(1),
	scheduleHash: Sha256RefSchema,
	contentHash: Sha256RefSchema,
	bindingFingerprint: Sha256RefSchema,
	actorId: NonEmptyString,
	subjectUserId: NonEmptyString,
	profileId: NonEmptyString,
	recipientPrincipalHash: PrincipalHashSchema,
	systemPolicyPrincipal: z.literal("telclaude:household-reminder-system"),
	systemPolicyVersion: z.literal("phase0.v1"),
});
const HouseholdReminderPolicySchema = z.discriminatedUnion("authorizationKind", [
	HouseholdReminderPolicyBaseSchema.extend({
		authorizationKind: z.literal("parent-confirmed"),
		confirmedProposalHash: Sha256RefSchema,
	}).strict(),
	HouseholdReminderPolicyBaseSchema.extend({
		authorizationKind: z.literal("appointment-derived"),
		sourceObservationHash: Sha256RefSchema,
	}).strict(),
]);

const ProviderBindingSchema = z
	.object({
		domainSeparator: z.literal(TELCLAUDE_MCP_PROVIDER_APPROVAL_DOMAIN),
		ref: NonEmptyString,
		kind: z.literal("provider"),
		actorId: NonEmptyString,
		approverActorId: NonEmptyString,
		profileId: NonEmptyString,
		domain: DomainSchema,
		providerId: NonEmptyString,
		service: NonEmptyString,
		action: NonEmptyString,
		subjectUserId: NonEmptyString.optional(),
		providerAccountRef: NonEmptyString,
		approvalRequestId: NonEmptyString,
		approvalRevision: z.number().int().min(1),
		turnConversationRef: TurnConversationRefSchema.optional(),
		idempotencyKey: NonEmptyString.optional(),
		paramsHash: HashSchema,
		bodyHash: HashSchema,
		contentHash: HashSchema,
	})
	.strict();

const OutboundBindingSchema = z
	.object({
		domainSeparator: z.literal(TELCLAUDE_MCP_OUTBOUND_APPROVAL_DOMAIN),
		ref: NonEmptyString,
		kind: z.literal("outbound"),
		actorId: NonEmptyString,
		approverActorId: NonEmptyString,
		profileId: NonEmptyString,
		domain: DomainSchema,
		subjectUserId: NonEmptyString.optional(),
		householdReplyBinding: HouseholdReplyBindingSchema.optional(),
		channel: NonEmptyString,
		destination: NonEmptyString,
		resolvedDestination: ResolvedDestinationSchema,
		requestedBody: z.string(),
		preparedMediaRefs: z.array(PreparedMediaRefSchema).readonly(),
		conversationRef: NonEmptyString,
		authorizationState: AuthorizationStateSchema,
		edgePreparedRef: NonEmptyString,
		edgePreparedHash: EdgePreparedHashSchema,
		approvalRequestId: NonEmptyString,
		approvalRevision: z.number().int().min(1),
		turnConversationRef: TurnConversationRefSchema.optional(),
		idempotencyKey: NonEmptyString.optional(),
		paramsHash: HashSchema,
		bodyHash: HashSchema,
		contentHash: HashSchema,
	})
	.strict();

const ScheduledOutboundBindingSchema = z
	.object({
		domainSeparator: z.literal(TELCLAUDE_MCP_SCHEDULED_OUTBOUND_APPROVAL_DOMAIN),
		ref: NonEmptyString,
		kind: z.literal("scheduled-outbound"),
		source: z.literal("household-reminder-system.v1"),
		actorId: NonEmptyString,
		profileId: NonEmptyString,
		domain: z.literal("household"),
		subjectUserId: NonEmptyString,
		channel: z.literal("whatsapp"),
		destination: NonEmptyString,
		resolvedDestination: ResolvedDestinationSchema,
		requestedBody: z.string(),
		preparedMediaRefs: z.array(PreparedMediaRefSchema).max(0).readonly(),
		conversationRef: NonEmptyString,
		edgePreparedRef: NonEmptyString,
		edgePreparedHash: EdgePreparedHashSchema,
		idempotencyKey: NonEmptyString,
		householdReminderPolicy: HouseholdReminderPolicySchema,
		paramsHash: HashSchema,
		bodyHash: HashSchema,
		contentHash: HashSchema,
	})
	.strict();

const BrowserWriteBindingSchema = z
	.object({
		domainSeparator: z.literal(TELCLAUDE_MCP_BROWSER_WRITE_APPROVAL_DOMAIN),
		ref: NonEmptyString,
		kind: z.literal("browser-write"),
		actorId: NonEmptyString,
		approverActorId: NonEmptyString,
		profileId: NonEmptyString,
		domain: DomainSchema,
		sessionRef: NonEmptyString,
		host: NonEmptyString,
		originScope: z.array(NonEmptyString).readonly(),
		browserCredentialRef: NonEmptyString.nullable(),
		browserCredentialCreatedAt: z.number().int().nonnegative().nullable(),
		authorityDomain: BrowserAuthorityDomainSchema,
		actionVerb: NonEmptyString,
		actionTarget: NonEmptyString.nullable(),
		evidenceRevision: HmacRevisionSchema,
		evidenceScreenshotHash: HashSchema,
		evidenceScreenshotRef: NonEmptyString,
		approvalRequestId: NonEmptyString,
		approvalRevision: z.number().int().min(1),
		turnConversationRef: TurnConversationRefSchema.optional(),
		idempotencyKey: NonEmptyString.optional(),
		bindingHash: HashSchema,
		contentHash: HashSchema,
	})
	.strict();

const BindingSchema = z.discriminatedUnion("kind", [
	ProviderBindingSchema,
	OutboundBindingSchema,
	ScheduledOutboundBindingSchema,
	BrowserWriteBindingSchema,
]);

const ClaimsSchema = z
	.object({
		ver: z.literal(1),
		iss: z.literal("telclaude-vault"),
		aud: z.literal(APPROVAL_AUDIENCE),
		iat: z.number().int().min(0),
		exp: z.number().int().min(1),
		jti: NonEmptyString.max(256),
		binding: BindingSchema,
	})
	.strict();

export type TelclaudeMcpSideEffectApprovalClaims = z.infer<typeof ClaimsSchema>;
type ApprovalFailure = { ok: false; code: string; reason: string };
type ClaimsDecodeResult =
	| { ok: true; claims: TelclaudeMcpSideEffectApprovalClaims }
	| ApprovalFailure;

export type TelclaudeMcpSideEffectApprovalSigner = {
	signPayload(payload: string, prefix: string): Promise<{ type: string; signature?: string }>;
};

export type TelclaudeMcpSideEffectApprovalSignatureVerifier = {
	verifyPayload(
		payload: string,
		signature: string,
		prefix: string,
	): Promise<{ type: string; valid?: boolean }>;
};

export type GenerateTelclaudeMcpSideEffectApprovalTokenOptions = {
	readonly nowSeconds?: () => number;
	readonly ttlSeconds?: number;
	readonly jti?: string;
};

export async function generateTelclaudeMcpSideEffectApprovalToken(
	binding: TelclaudeMcpSideEffectApprovalBinding,
	vaultClient: TelclaudeMcpSideEffectApprovalSigner,
	options: GenerateTelclaudeMcpSideEffectApprovalTokenOptions = {},
): Promise<string> {
	const normalizedBinding = parseBinding(binding);
	const nowSeconds = normalizeNowSeconds(options.nowSeconds?.() ?? Math.floor(Date.now() / 1000));
	const ttlSeconds = normalizeTtlSeconds(options.ttlSeconds ?? DEFAULT_TOKEN_TTL_SECONDS);
	const claims: TelclaudeMcpSideEffectApprovalClaims = {
		ver: 1,
		iss: "telclaude-vault",
		aud: APPROVAL_AUDIENCE,
		iat: nowSeconds,
		exp: nowSeconds + ttlSeconds,
		jti: options.jti ? normalizeJti(options.jti) : `jti-${crypto.randomUUID()}`,
		binding: normalizedBinding,
	};
	const claimsB64 = Buffer.from(canonicalJson(claims), "utf8").toString("base64url");
	const signResult = await vaultClient.signPayload(claimsB64, normalizedBinding.domainSeparator);
	if (signResult.type !== "sign-payload" || !signResult.signature) {
		throw new Error("Vault signing failed");
	}
	return `v1.${claimsB64}.${signResult.signature}`;
}

export class TelclaudeMcpSideEffectJtiStore {
	private readonly db: Database.Database;
	private readonly insertStmt: Database.Statement;
	private readonly cleanupStmt: Database.Statement;

	constructor(dataDir: string) {
		fs.mkdirSync(dataDir, { recursive: true });
		this.db = new Database(path.join(dataDir, JTI_DATABASE_NAME));
		this.db.pragma("journal_mode = WAL");
		this.db.exec(`
			CREATE TABLE IF NOT EXISTS used_hermes_mcp_side_effect_approval_tokens (
				jti TEXT PRIMARY KEY,
				exp INTEGER NOT NULL,
				used_at INTEGER NOT NULL
			)
		`);
		this.insertStmt = this.db.prepare(
			"INSERT INTO used_hermes_mcp_side_effect_approval_tokens (jti, exp, used_at) VALUES (?, ?, ?)",
		);
		this.cleanupStmt = this.db.prepare(
			"DELETE FROM used_hermes_mcp_side_effect_approval_tokens WHERE exp < ?",
		);
	}

	recordJti(jti: string, exp: number, nowSeconds = Math.floor(Date.now() / 1000)): boolean {
		this.cleanup(nowSeconds);
		try {
			this.insertStmt.run(normalizeJti(jti), exp, nowSeconds);
			return true;
		} catch (error) {
			if (isSqliteConstraint(error)) return false;
			throw error;
		}
	}

	cleanup(nowSeconds = Math.floor(Date.now() / 1000)): void {
		this.cleanupStmt.run(nowSeconds);
	}

	close(): void {
		this.db.close();
	}
}

export type CreateTelclaudeMcpSideEffectApprovalVerifierOptions = {
	readonly vaultClient: TelclaudeMcpSideEffectApprovalSignatureVerifier;
	readonly jtiStore: TelclaudeMcpSideEffectJtiStore;
	readonly nowSeconds?: () => number;
};

export function createTelclaudeMcpSideEffectApprovalVerifier(
	options: CreateTelclaudeMcpSideEffectApprovalVerifierOptions,
): TelclaudeMcpSideEffectApprovalVerifier {
	return async (request) => {
		let nowSeconds: number;
		try {
			nowSeconds = normalizeNowSeconds(options.nowSeconds?.() ?? Math.floor(request.nowMs / 1_000));
		} catch {
			return failure("approval_required", "Invalid verifier clock");
		}

		let recordBinding: TelclaudeMcpSideEffectApprovalBinding;
		try {
			recordBinding = getTelclaudeMcpSideEffectApprovalBinding(request.record);
		} catch {
			return failure("approval_mismatch", "Approval record binding mismatch");
		}
		if (!sameBinding(request.binding, recordBinding)) {
			return failure("approval_mismatch", "Approval request binding mismatch");
		}

		const parts = request.approvalToken.split(".");
		if (parts.length !== 3 || parts[0] !== "v1") {
			return failure("approval_required", "Invalid token format");
		}
		const [, claimsB64, sigB64] = parts;
		if (!claimsB64 || !sigB64) {
			return failure("approval_required", "Invalid token format");
		}

		let signatureValid = false;
		try {
			const verifyResult = await options.vaultClient.verifyPayload(
				claimsB64,
				sigB64,
				recordBinding.domainSeparator,
			);
			signatureValid = verifyResult.type === "verify-payload" && verifyResult.valid === true;
		} catch {
			return failure("approval_required", "Vault verification failed");
		}
		if (!signatureValid) {
			return failure("approval_required", "Invalid token signature");
		}

		const claimsResult = decodeClaims(claimsB64);
		if (!claimsResult.ok) return claimsResult;
		const claims = claimsResult.claims;

		if (claims.exp <= nowSeconds) {
			return failure("approval_expired", "Token expired");
		}
		if (claims.iat > nowSeconds) {
			return failure("approval_required", "Token issued in the future");
		}
		if (claims.exp - claims.iat > MAX_VERIFY_TOKEN_TTL_SECONDS) {
			return failure("approval_required", "Token TTL exceeds maximum (60s)");
		}
		if (!sameBinding(claims.binding, recordBinding)) {
			return failure("approval_mismatch", "Approval token binding mismatch");
		}

		const recorded = options.jtiStore.recordJti(claims.jti, claims.exp, nowSeconds);
		if (!recorded) {
			return failure("approval_replayed", "Approval token already used");
		}
		return { ok: true, approvalId: claims.jti };
	};
}

function decodeClaims(claimsB64: string): ClaimsDecodeResult {
	let decoded: string;
	try {
		decoded = Buffer.from(claimsB64, "base64url").toString("utf8");
	} catch {
		return failure("approval_required", "Invalid token encoding");
	}

	let rawClaims: unknown;
	try {
		rawClaims = JSON.parse(decoded);
	} catch {
		return failure("approval_required", "Invalid claims JSON");
	}

	const claimsResult = ClaimsSchema.safeParse(rawClaims);
	if (!claimsResult.success) {
		return failure("approval_required", "Invalid claims structure");
	}
	return { ok: true, claims: claimsResult.data };
}

function parseBinding(
	binding: TelclaudeMcpSideEffectApprovalBinding,
):
	| TelclaudeMcpProviderApprovalBinding
	| TelclaudeMcpOutboundApprovalBinding
	| TelclaudeMcpScheduledOutboundApprovalBinding
	| TelclaudeMcpBrowserWriteApprovalBinding {
	const result = BindingSchema.safeParse(binding);
	if (!result.success) {
		throw new Error("Invalid side-effect approval binding");
	}
	return result.data;
}

function sameBinding(
	claimed: TelclaudeMcpSideEffectApprovalBinding,
	expected: TelclaudeMcpSideEffectApprovalBinding,
): boolean {
	const expectedResult = BindingSchema.safeParse(expected);
	if (!expectedResult.success) return false;
	return canonicalJson(claimed) === canonicalJson(expectedResult.data);
}

function canonicalJson(value: unknown): string {
	return JSON.stringify(sortKeysDeep(value));
}

function normalizeNowSeconds(value: number): number {
	if (!Number.isInteger(value) || value < 0) {
		throw new Error("nowSeconds must be a non-negative integer");
	}
	return value;
}

function normalizeTtlSeconds(value: number): number {
	if (!Number.isInteger(value) || value <= 0 || value > MAX_MINT_TOKEN_TTL_SECONDS) {
		throw new Error("ttlSeconds must be an integer between 1 and 60");
	}
	return value;
}

function normalizeJti(value: string): string {
	const trimmed = requiredTrimmed(value, "jti");
	if (trimmed.length > 256) {
		throw new Error("jti must be 256 characters or less");
	}
	return trimmed;
}

function requiredTrimmed(value: string, field: string): string {
	const trimmed = value.trim();
	if (!trimmed) {
		throw new Error(`${field} is required`);
	}
	return trimmed;
}

function failure(code: string, reason: string): ApprovalFailure {
	return { ok: false, code, reason };
}

function isSqliteConstraint(error: unknown): boolean {
	return (
		typeof error === "object" &&
		error !== null &&
		"code" in error &&
		typeof error.code === "string" &&
		error.code.startsWith("SQLITE_CONSTRAINT")
	);
}
