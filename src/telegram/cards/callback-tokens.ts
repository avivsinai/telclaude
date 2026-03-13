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
