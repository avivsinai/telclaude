import crypto from "node:crypto";
import {
	generateTelclaudeMcpSideEffectApprovalToken,
	type TelclaudeMcpSideEffectApprovalSigner,
} from "../hermes/mcp/approval-token.js";
import {
	getTelclaudeMcpSideEffectApprovalBinding,
	type TelclaudeMcpScheduledOutboundSideEffectRecord,
} from "../hermes/mcp/side-effect-ledger.js";
import type {
	HouseholdReminderSystemOriginPolicyResult,
	HouseholdReminderSystemOriginPolicyRevalidator,
} from "./system-origin-policy.js";

const DEFAULT_SYSTEM_ORIGIN_TOKEN_TTL_SECONDS = 30;
const MAX_SYSTEM_ORIGIN_TOKEN_TTL_SECONDS = 60;

export type HouseholdReminderSystemOriginAuthorization =
	| {
			readonly ok: true;
			readonly approvalToken: string;
			readonly approvalId: string;
	  }
	| {
			readonly ok: false;
			readonly code: string;
			readonly reason: string;
			readonly retryable: boolean;
	  };

export type HouseholdReminderSystemOriginAuthorizer = ((
	record: TelclaudeMcpScheduledOutboundSideEffectRecord,
) => Promise<HouseholdReminderSystemOriginAuthorization>) & {
	readonly revalidate: HouseholdReminderSystemOriginPolicyRevalidator;
};

export function createHouseholdReminderSystemOriginAuthorizer(options: {
	readonly revalidate: HouseholdReminderSystemOriginPolicyRevalidator;
	readonly vaultClient: TelclaudeMcpSideEffectApprovalSigner;
	readonly nowSeconds?: () => number;
	readonly ttlSeconds?: number;
	readonly makeJti?: () => string;
}): HouseholdReminderSystemOriginAuthorizer {
	const ttlSeconds = normalizeTtlSeconds(
		options.ttlSeconds ?? DEFAULT_SYSTEM_ORIGIN_TOKEN_TTL_SECONDS,
	);
	const makeJti = options.makeJti ?? (() => `reminder-system-${crypto.randomUUID()}`);
	const authorize = async (
		record: TelclaudeMcpScheduledOutboundSideEffectRecord,
	): Promise<HouseholdReminderSystemOriginAuthorization> => {
		let policy: HouseholdReminderSystemOriginPolicyResult;
		try {
			policy = await options.revalidate(record);
		} catch {
			return {
				ok: false,
				code: "reminder_policy_unavailable",
				reason: "household reminder policy revalidation is unavailable",
				retryable: true,
			};
		}
		if (!policy.ok) return policy;
		const approvalId = normalizeJti(makeJti());
		try {
			const approvalToken = await generateTelclaudeMcpSideEffectApprovalToken(
				getTelclaudeMcpSideEffectApprovalBinding(record),
				options.vaultClient,
				{
					nowSeconds: options.nowSeconds,
					ttlSeconds,
					jti: approvalId,
				},
			);
			return { ok: true, approvalToken, approvalId };
		} catch {
			return {
				ok: false,
				code: "reminder_system_token_mint_failed",
				reason: "household reminder system approval token could not be minted",
				retryable: true,
			};
		}
	};
	return Object.assign(authorize, { revalidate: options.revalidate });
}

function normalizeTtlSeconds(value: number): number {
	if (!Number.isInteger(value) || value < 1 || value > MAX_SYSTEM_ORIGIN_TOKEN_TTL_SECONDS) {
		throw new Error("household reminder system token TTL must be between 1 and 60 seconds");
	}
	return value;
}

function normalizeJti(value: string): string {
	const normalized = value.trim();
	if (!normalized || normalized.length > 256) {
		throw new Error("household reminder system JTI must be between 1 and 256 characters");
	}
	return normalized;
}
