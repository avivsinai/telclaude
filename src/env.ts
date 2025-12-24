import { z } from "zod";
import { loadConfig } from "./config/config.js";
import { defaultRuntime, type RuntimeEnv } from "./runtime.js";
import { CONFIG_DIR } from "./utils.js";

const TelclaudeEnvSchema = z.object({
	telegramBotToken: z.string().min(1),
});

export type TelclaudeEnv = z.infer<typeof TelclaudeEnvSchema>;

let cachedEnv: TelclaudeEnv | null = null;

/**
 * Read and validate required environment variables.
 *
 * SECURITY: Token loading priority:
 * 1. Config file (CONFIG_DIR/telclaude.json) - preferred for native deployments
 *    because this directory is blocked from Claude's sandbox
 * 2. TELEGRAM_BOT_TOKEN env var - allowed for Docker deployments where
 *    container isolation provides equivalent security
 *
 * CONFIG_DIR defaults to ~/.telclaude but can be overridden via TELCLAUDE_DATA_DIR.
 * In Docker, the container itself provides isolation, so env vars are acceptable.
 * For native deployments, prefer the config file approach.
 */
export function readEnv(runtime: RuntimeEnv = defaultRuntime): TelclaudeEnv {
	if (cachedEnv) return cachedEnv;

	// Try config file first (preferred for native deployments)
	let token: string | undefined;
	let configError: string | undefined;
	try {
		const config = loadConfig();
		token = config.telegram?.botToken;
	} catch (err) {
		// Config loading failed - save error for later, but allow env var fallback
		configError = err instanceof Error ? err.message : String(err);
	}

	// Fall back to environment variable (for Docker deployments)
	if (!token) {
		token = process.env.TELEGRAM_BOT_TOKEN;
	}

	// If we got token from env var but config had an error, log a warning
	if (token && configError) {
		runtime.error(`Warning: Config file failed to load (${configError}), using TELEGRAM_BOT_TOKEN`);
	}

	if (!token) {
		runtime.error("Telegram bot token not found.");
		if (configError) {
			runtime.error(`  (config file error: ${configError})`);
		}
		runtime.error("");
		runtime.error("Option 1 - Config file (recommended for native deployments):");
		runtime.error(`  Add to ${CONFIG_DIR}/telclaude.json:`);
		runtime.error('  { "telegram": { "botToken": "your-token-here" } }');
		runtime.error("");
		runtime.error("Option 2 - Environment variable (for Docker):");
		runtime.error("  export TELEGRAM_BOT_TOKEN=your-token-here");
		runtime.error("");
		runtime.error("Get a token from @BotFather on Telegram");
		runtime.exit(1);
	}

	const env: TelclaudeEnv = {
		telegramBotToken: token,
	};

	// Validate
	const result = TelclaudeEnvSchema.safeParse(env);
	if (!result.success) {
		runtime.error("Invalid token configuration:");
		for (const error of result.error.errors) {
			runtime.error(`  ${error.path.join(".")}: ${error.message}`);
		}
		runtime.exit(1);
	}

	cachedEnv = result.data;
	return cachedEnv;
}

/**
 * Check if environment is properly configured.
 * Checks both config file and TELEGRAM_BOT_TOKEN env var.
 */
export function hasValidEnv(): boolean {
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
