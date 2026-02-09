import type { Command } from "commander";

import { generateKeyPair } from "../internal-auth.js";

type KeygenScope = "telegram" | "moltbook";

const ENV_VARS: Record<KeygenScope, { privateKey: string; publicKey: string }> = {
	telegram: {
		privateKey: "TELEGRAM_RPC_PRIVATE_KEY",
		publicKey: "TELEGRAM_RPC_PUBLIC_KEY",
	},
	moltbook: {
		privateKey: "MOLTBOOK_RPC_PRIVATE_KEY",
		publicKey: "MOLTBOOK_RPC_PUBLIC_KEY",
	},
};

/**
 * Generate Ed25519 key pair for asymmetric RPC auth.
 *
 * Outputs both keys for easy copy-paste into .env:
 * - Private key goes to relay (can sign)
 * - Public key goes to agent (can only verify)
 */
export function runKeygen(scope: KeygenScope): void {
	const { privateKey, publicKey } = generateKeyPair();
	const vars = ENV_VARS[scope];

	console.log(`# ${scope} RPC Ed25519 Key Pair`);
	console.log("# Generated for asymmetric authentication");
	console.log("#");
	console.log("# SECURITY: Agent only has public key - can verify but CANNOT forge signatures");
	console.log("#");
	console.log("# Add to your docker/.env file:");
	console.log("");
	console.log(`${vars.privateKey}=${privateKey}`);
	console.log(`${vars.publicKey}=${publicKey}`);
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
