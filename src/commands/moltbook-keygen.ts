import type { Command } from "commander";

import { generateMoltbookKeyPair } from "../internal-auth.js";

/**
 * Generate Ed25519 key pair for Moltbook asymmetric RPC auth.
 *
 * Outputs both keys for easy copy-paste into .env:
 * - MOLTBOOK_RPC_PRIVATE_KEY goes to relay (can sign)
 * - MOLTBOOK_RPC_PUBLIC_KEY goes to agent (can only verify)
 */
export function runMoltbookKeygen(): void {
	const { privateKey, publicKey } = generateMoltbookKeyPair();

	console.log("# Moltbook RPC Ed25519 Key Pair");
	console.log("# Generated for asymmetric authentication");
	console.log("#");
	console.log("# SECURITY: Agent only has public key - can verify but CANNOT forge signatures");
	console.log("#");
	console.log("# Add to your docker/.env file:");
	console.log("");
	console.log(`MOLTBOOK_RPC_PRIVATE_KEY=${privateKey}`);
	console.log(`MOLTBOOK_RPC_PUBLIC_KEY=${publicKey}`);
}

export function registerMoltbookKeygenCommand(program: Command): void {
	program
		.command("moltbook-keygen")
		.description("Generate Ed25519 key pair for Moltbook asymmetric RPC auth")
		.action(() => {
			runMoltbookKeygen();
		});
}
