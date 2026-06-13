import { createHmac } from "node:crypto";
import { sortKeysDeep } from "../crypto/canonical-hash.js";

export const WHATSAPP_SIDECAR_SESSION_KEY_HEADER = "x-telclaude-whatsapp-session-key";
export const WHATSAPP_SIDECAR_REQUEST_DIGEST_HEADER = "x-telclaude-whatsapp-request-digest";
export const WHATSAPP_SIDECAR_SESSION_EXPIRES_AT_HEADER = "x-telclaude-whatsapp-session-expires-at";
export const WHATSAPP_SIDECAR_AUTH_HEADER = "x-telclaude-whatsapp-bridge-auth";

export function createWhatsAppBridgeAuthToken(input: {
	readonly secret: string;
	readonly sessionKey: string;
	readonly requestDigest: string;
	readonly expiresAt: string;
}): `sha256:${string}` {
	const secret = input.secret.trim();
	const payload = JSON.stringify(
		sortKeysDeep({
			sessionKey: input.sessionKey,
			requestDigest: input.requestDigest,
			expiresAt: input.expiresAt,
		}),
	);
	const digest = createHmac("sha256", secret).update(payload).digest("hex");
	return `sha256:${digest}`;
}
