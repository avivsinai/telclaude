/** Baileys `DisconnectReason.connectionReplaced`. */
export const WHATSAPP_BRIDGE_CONNECTION_REPLACED = 440;

const GENERIC_RECONNECT_BASE_MS = 5_000;
const GENERIC_RECONNECT_CAP_MS = 60_000;
const REPLACED_RECONNECT_BASE_MS = 30_000;
const REPLACED_RECONNECT_CAP_MS = 120_000;
const MAX_BACKOFF_SHIFT = 8;

export function isStaleWhatsAppBridgeGeneration(
	eventGeneration: number,
	currentGeneration: number,
): boolean {
	return eventGeneration !== currentGeneration;
}

export function shouldCreateWhatsAppBridgeSocket(input: {
	readonly connected: boolean;
	readonly hasSocket: boolean;
}): boolean {
	return !(input.connected && input.hasSocket);
}

export function whatsappBridgeReconnectDelayMs(input: {
	readonly loggedOut: boolean;
	readonly statusCode: number | null;
	readonly attempt: number;
}): number | null {
	if (input.loggedOut) return null;
	const attempt = Math.max(0, Math.min(input.attempt, MAX_BACKOFF_SHIFT));
	const replaced = input.statusCode === WHATSAPP_BRIDGE_CONNECTION_REPLACED;
	const baseMs = replaced ? REPLACED_RECONNECT_BASE_MS : GENERIC_RECONNECT_BASE_MS;
	const capMs = replaced ? REPLACED_RECONNECT_CAP_MS : GENERIC_RECONNECT_CAP_MS;
	return Math.min(capMs, baseMs * 2 ** attempt);
}
