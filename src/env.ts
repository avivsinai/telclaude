import { z } from "zod";
import { loadConfig } from "./config/config.js";
import { type RuntimeEnv, defaultRuntime } from "./runtime.js";

const TelclaudeEnvSchema = z.object({
	telegramBotToken: z.string().min(1),
});

export type TelclaudeEnv = z.infer<typeof TelclaudeEnvSchema>;

let cachedEnv: TelclaudeEnv | null = null;

/**
 * Read and validate required environment variables.
 *
 * SECURITY: Token is ONLY loaded from ~/.telclaude/telclaude.json
 * This directory is blocked from Claude's sandbox, preventing token
 * exposure via prompt injection attacks.
 *
 * We intentionally DO NOT support .env files or environment variables
 * for the bot token, as these are readable by Claude.
 */
export function readEnv(runtime: RuntimeEnv = defaultRuntime): TelclaudeEnv {
	if (cachedEnv) return cachedEnv;

	// ONLY load from secure config file
	let token: string | undefined;
	try {
		const config = loadConfig();
		token = config.telegram?.botToken;
	} catch (err) {
		runtime.error("Failed to load config file:");
		runtime.error(`  ${err instanceof Error ? err.message : String(err)}`);
		runtime.exit(1);
	}

	if (!token) {
		runtime.error("Telegram bot token not found in config file.");
		runtime.error("");
		runtime.error("Add to ~/.telclaude/telclaude.json:");
		runtime.error('  { "telegram": { "botToken": "your-token-here" } }');
		runtime.error("");
		runtime.error("This is the ONLY supported location for security reasons.");
		runtime.error("The ~/.telclaude/ directory is blocked from Claude's sandbox.");
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
 * ONLY checks the secure config file location.
 */
export function hasValidEnv(): boolean {
	try {
		const config = loadConfig();
		return !!config.telegram?.botToken;
	} catch {
		return false;
	}
}

/**
 * Reset cached environment (for testing).
 */
export function resetEnvCache() {
	cachedEnv = null;
}
