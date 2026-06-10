/**
 * Relay routing helpers — centralises the repeated environment-variable
 * checks that every dual-mode service needs.
 */

/**
 * True when running inside contained runtime compute (TELCLAUDE_CAPABILITIES_URL set).
 */
export function isAgentSide(): boolean {
	return Boolean(process.env.TELCLAUDE_CAPABILITIES_URL);
}

/**
 * True when the relay is reachable (capabilities URL set AND auth credential
 * available). Used by availability checks in image-gen, TTS, summarize, etc.
 */
export function isRelayReachable(): boolean {
	if (!process.env.TELCLAUDE_CAPABILITIES_URL) return false;
	return Boolean(process.env.TELCLAUDE_SESSION_TOKEN ?? process.env.TELEGRAM_RPC_AGENT_PRIVATE_KEY);
}
