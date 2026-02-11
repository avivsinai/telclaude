import type { Command } from "commander";

import { generateKeyPair } from "../internal-auth.js";

/**
 * Derive env var names for a scope string.
 * E.g., "moltbook" → MOLTBOOK_RPC_AGENT_PRIVATE_KEY, etc.
 */
function scopeEnvVars(scope: string): {
	agentPrivateKey: string;
	agentPublicKey: string;
	relayPrivateKey: string;
	relayPublicKey: string;
} {
	const prefix = scope.toUpperCase().replace(/[^A-Z0-9]/g, "_");
	return {
		agentPrivateKey: `${prefix}_RPC_AGENT_PRIVATE_KEY`,
		agentPublicKey: `${prefix}_RPC_AGENT_PUBLIC_KEY`,
		relayPrivateKey: `${prefix}_RPC_RELAY_PRIVATE_KEY`,
		relayPublicKey: `${prefix}_RPC_RELAY_PUBLIC_KEY`,
	};
}

/**
 * Generate two Ed25519 key pairs for bidirectional asymmetric RPC auth.
 *
 * Outputs 4 keys for easy copy-paste into .env:
 * - Agent keypair: agent signs → relay verifies
 * - Relay keypair: relay signs → agent verifies
 */
export function runKeygen(scope: string): void {
	const agentKeys = generateKeyPair();
	const relayKeys = generateKeyPair();
	const vars = scopeEnvVars(scope);

	console.log(`# ${scope} RPC Ed25519 Key Pairs (bidirectional auth)`);
	console.log("#");
	console.log("# Two keypairs: each side owns its own private key.");
	console.log("# Agent compromise cannot forge relay→agent requests (and vice versa).");
	console.log("#");
	console.log("# Add ALL 4 lines to your docker/.env file:");
	console.log("");
	console.log("# ── Agent keypair (agent signs → relay verifies) ──");
	console.log(`# Agent container gets the private key:`);
	console.log(`${vars.agentPrivateKey}=${agentKeys.privateKey}`);
	console.log(`# Relay container gets the public key:`);
	console.log(`${vars.agentPublicKey}=${agentKeys.publicKey}`);
	console.log("");
	console.log("# ── Relay keypair (relay signs → agent verifies) ──");
	console.log(`# Relay container gets the private key:`);
	console.log(`${vars.relayPrivateKey}=${relayKeys.privateKey}`);
	console.log(`# Agent container gets the public key:`);
	console.log(`${vars.relayPublicKey}=${relayKeys.publicKey}`);
}

export function registerKeygenCommand(program: Command): void {
	program
		.command("keygen <scope>")
		.description(
			"Generate Ed25519 key pair for asymmetric RPC auth (e.g., telegram, moltbook, or any social service scope)",
		)
		.action((scope: string) => {
			const trimmed = scope.trim();
			if (!trimmed || !/^[a-z][a-z0-9_-]*$/i.test(trimmed)) {
				console.error(
					`Invalid scope: "${scope}". Use a lowercase identifier (e.g., "telegram", "moltbook", "xtwitter").`,
				);
				process.exitCode = 1;
				return;
			}
			runKeygen(trimmed);
		});
}
