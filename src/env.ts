import { z } from "zod";
import { loadConfig } from "./config/config.js";
import { getChildLogger } from "./logging.js";
import { defaultRuntime, type RuntimeEnv } from "./runtime.js";
import { CONFIG_DIR } from "./utils.js";
import { getVaultClient, isVaultAvailable } from "./vault-daemon/client.js";

const logger = getChildLogger({ module: "env" });

const TelclaudeEnvSchema = z.object({
	telegramBotToken: z.string().min(1),
});

export type TelclaudeEnv = z.infer<typeof TelclaudeEnvSchema>;

let cachedEnv: TelclaudeEnv | null = null;

/**
 * Read and validate required environment variables.
 *
 * SECURITY: Token loading priority:
 * 1. Vault (secret:telegram-bot-token) - highest priority, secrets never in env/disk
 * 2. Config file (CONFIG_DIR/telclaude.json) - preferred for native deployments
 *    because this directory is blocked from Claude's sandbox
 * 3. TELEGRAM_BOT_TOKEN env var - allowed for Docker deployments where
 *    container isolation provides equivalent security
 *
 * CONFIG_DIR defaults to ~/.telclaude but can be overridden via TELCLAUDE_DATA_DIR.
 * In Docker, the container itself provides isolation, so env vars are acceptable.
 * For native deployments, prefer the config file approach.
 */
export async function readEnv(runtime: RuntimeEnv = defaultRuntime): Promise<TelclaudeEnv> {
	if (cachedEnv) return cachedEnv;

	let token: string | undefined;
	let tokenSource: string | undefined;

	// 1. Try vault first (highest priority)
	try {
		if (await isVaultAvailable({ timeout: 2000 })) {
			const client = getVaultClient();
			const resp = await client.getSecret("telegram-bot-token", { timeout: 2000 });
			if (resp.ok && resp.type === "get-secret" && resp.value) {
				token = resp.value;
				tokenSource = "vault";
			}
		}
	} catch (err) {
		logger.debug({ error: String(err) }, "vault bot token lookup failed");
	}

	// 2. Try config file (preferred for native deployments)
	let configError: string | undefined;
	if (!token) {
		try {
			const config = loadConfig();
			token = config.telegram?.botToken;
			if (token) tokenSource = "config";
		} catch (err) {
			configError = err instanceof Error ? err.message : String(err);
		}
	}

	// 3. Fall back to environment variable (for Docker deployments)
	if (!token) {
		token = process.env.TELEGRAM_BOT_TOKEN;
		if (token) tokenSource = "env";
	}

	// If we got token from env var but config had an error, log a warning
	if (token && tokenSource === "env" && configError) {
		runtime.error(`Warning: Config file failed to load (${configError}), using TELEGRAM_BOT_TOKEN`);
	}

	if (!token) {
		runtime.error("Telegram bot token not found.");
		if (configError) {
			runtime.error(`  (config file error: ${configError})`);
		}
		runtime.error("");
		runtime.error("Option 1 - Vault (recommended for Docker):");
		runtime.error("  telclaude vault add secret telegram-bot-token --token <your-token>");
		runtime.error("");
		runtime.error("Option 2 - Config file (recommended for native deployments):");
		runtime.error(`  Add to ${CONFIG_DIR}/telclaude.json:`);
		runtime.error('  { "telegram": { "botToken": "your-token-here" } }');
		runtime.error("");
		runtime.error("Option 3 - Environment variable:");
		runtime.error("  export TELEGRAM_BOT_TOKEN=your-token-here");
		runtime.error("");
		runtime.error("Get a token from @BotFather on Telegram");
		runtime.exit(1);
	}

	logger.debug({ source: tokenSource }, "bot token loaded");

	const env: TelclaudeEnv = {
		telegramBotToken: token,
	};

	// Validate
	const result = TelclaudeEnvSchema.safeParse(env);
	if (!result.success) {
		runtime.error("Invalid token configuration:");
		for (const issue of result.error.issues) {
			runtime.error(`  ${issue.path.join(".")}: ${issue.message}`);
		}
		runtime.exit(1);
	}

	cachedEnv = result.data;
	return cachedEnv;
}

/**
 * Check if environment is properly configured.
 * Checks vault, config file, and TELEGRAM_BOT_TOKEN env var.
 */
export async function hasValidEnv(): Promise<boolean> {
	// Check vault
	try {
		if (await isVaultAvailable({ timeout: 1000 })) {
			const client = getVaultClient();
			const resp = await client.getSecret("telegram-bot-token", { timeout: 1000 });
			if (resp.ok && resp.type === "get-secret" && resp.value) return true;
		}
	} catch {
		// Vault not available, check other sources
	}
	// Check config file
	try {
		const config = loadConfig();
		if (config.telegram?.botToken) return true;
	} catch {
		// Config loading failed, check env var
	}
	return !!process.env.TELEGRAM_BOT_TOKEN;
}

/**
 * Reset cached environment (for testing).
 */
export function resetEnvCache() {
	cachedEnv = null;
}
