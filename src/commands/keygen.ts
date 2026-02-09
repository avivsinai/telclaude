import type { Command } from "commander";

import { generateKeyPair } from "../internal-auth.js";

type KeygenScope = "telegram" | "moltbook";

const ENV_VARS: Record<
	KeygenScope,
	{
		agentPrivateKey: string;
		agentPublicKey: string;
		relayPrivateKey: string;
		relayPublicKey: string;
	}
> = {
	telegram: {
		agentPrivateKey: "TELEGRAM_RPC_AGENT_PRIVATE_KEY",
		agentPublicKey: "TELEGRAM_RPC_AGENT_PUBLIC_KEY",
		relayPrivateKey: "TELEGRAM_RPC_RELAY_PRIVATE_KEY",
		relayPublicKey: "TELEGRAM_RPC_RELAY_PUBLIC_KEY",
	},
	moltbook: {
		agentPrivateKey: "MOLTBOOK_RPC_AGENT_PRIVATE_KEY",
		agentPublicKey: "MOLTBOOK_RPC_AGENT_PUBLIC_KEY",
		relayPrivateKey: "MOLTBOOK_RPC_RELAY_PRIVATE_KEY",
		relayPublicKey: "MOLTBOOK_RPC_RELAY_PUBLIC_KEY",
	},
};

/**
 * Generate two Ed25519 key pairs for bidirectional asymmetric RPC auth.
 *
 * Outputs 4 keys for easy copy-paste into .env:
 * - Agent keypair: agent signs → relay verifies
 * - Relay keypair: relay signs → agent verifies
 */
export function runKeygen(scope: KeygenScope): void {
	const agentKeys = generateKeyPair();
	const relayKeys = generateKeyPair();
	const vars = ENV_VARS[scope];

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
		.description("Generate Ed25519 key pair for asymmetric RPC auth (scope: telegram or moltbook)")
		.action((scope: string) => {
			if (scope !== "telegram" && scope !== "moltbook") {
				console.error(`Invalid scope: ${scope}. Use "telegram" or "moltbook".`);
				process.exitCode = 1;
				return;
			}
			runKeygen(scope);
		});
}
