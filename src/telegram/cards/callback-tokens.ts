const CALLBACK_PREFIX = "c";
const SHORT_ID_PATTERN = /^[a-f0-9]{8}$/;
const ACTION_PATTERN = /^[a-z0-9][a-z0-9_-]{0,31}$/;
const REVISION_PATTERN = /^[1-9]\d*$/;
const MAX_CALLBACK_TOKEN_LENGTH = 64;

export type CardCallbackToken = {
	shortId: string;
	action: string;
	revision: number;
};

/**
 * W1 — Approval scopes encoded as callback actions. The token format itself
 * stays `c:<shortId>:<action>:<revision>`; the scope rides inside the action
 * name so existing parsing and revision-pinning apply unchanged.
 */
export const APPROVAL_SCOPE_ACTION_PREFIX = "approve-";
export const APPROVAL_SCOPE_ACTIONS = [
	"approve-once",
	"approve-session",
	"approve-always",
] as const;
export type ApprovalScopeAction = (typeof APPROVAL_SCOPE_ACTIONS)[number];

export function scopeActionToScope(action: string): "once" | "session" | "always" | null {
	if (!action.startsWith(APPROVAL_SCOPE_ACTION_PREFIX)) return null;
	const raw = action.slice(APPROVAL_SCOPE_ACTION_PREFIX.length);
	if (raw === "once" || raw === "session" || raw === "always") return raw;
	return null;
}

export function scopeToScopeAction(scope: "once" | "session" | "always"): ApprovalScopeAction {
	return `approve-${scope}` as ApprovalScopeAction;
}

export function buildCallbackToken(params: CardCallbackToken): string {
	const shortId = params.shortId.toLowerCase();
	if (!SHORT_ID_PATTERN.test(shortId)) {
		throw new Error(`Invalid card short ID: ${params.shortId}`);
	}
	if (!ACTION_PATTERN.test(params.action)) {
		throw new Error(`Invalid callback action: ${params.action}`);
	}
	if (!Number.isInteger(params.revision) || params.revision < 1) {
		throw new Error(`Invalid callback revision: ${params.revision}`);
	}

	const token = `${CALLBACK_PREFIX}:${shortId}:${params.action}:${params.revision}`;
	if (token.length > MAX_CALLBACK_TOKEN_LENGTH) {
		throw new Error(`Callback token exceeds Telegram limit: ${token.length}`);
	}
	return token;
}

export function parseCallbackToken(raw: string): CardCallbackToken | null {
	if (!raw || raw.length > MAX_CALLBACK_TOKEN_LENGTH) {
		return null;
	}

	const parts = raw.split(":");
	if (parts.length !== 4 || parts[0] !== CALLBACK_PREFIX) {
		return null;
	}

	const [, shortId, action, revisionRaw] = parts;
	const normalizedShortId = shortId.toLowerCase();

	if (!SHORT_ID_PATTERN.test(normalizedShortId)) {
		return null;
	}
	if (!ACTION_PATTERN.test(action)) {
		return null;
	}
	if (!REVISION_PATTERN.test(revisionRaw)) {
		return null;
	}

	return {
		shortId: normalizedShortId,
		action,
		revision: Number.parseInt(revisionRaw, 10),
	};
}

export function isValidCallbackToken(raw: string): boolean {
	return parseCallbackToken(raw) !== null;
}
