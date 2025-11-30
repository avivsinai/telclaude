import { z } from "zod";
import { defaultRuntime, type RuntimeEnv } from "./runtime.js";

const TelclaudeEnvSchema = z.object({
	telegramBotToken: z.string().min(1),
	anthropicApiKey: z.string().optional(),
});

export type TelclaudeEnv = z.infer<typeof TelclaudeEnvSchema>;

let cachedEnv: TelclaudeEnv | null = null;

/**
 * Read and validate required environment variables.
 */
export function readEnv(runtime: RuntimeEnv = defaultRuntime): TelclaudeEnv {
	if (cachedEnv) return cachedEnv;

	const token = process.env.TELEGRAM_BOT_TOKEN;
	if (!token) {
		runtime.error("TELEGRAM_BOT_TOKEN environment variable is required");
		runtime.error("Get a token from @BotFather on Telegram");
		runtime.exit(1);
	}

	const env: TelclaudeEnv = {
		telegramBotToken: token,
		anthropicApiKey: process.env.ANTHROPIC_API_KEY,
	};

	// Validate
	const result = TelclaudeEnvSchema.safeParse(env);
	if (!result.success) {
		runtime.error("Invalid environment configuration:");
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
 */
export function hasValidEnv(): boolean {
	return !!process.env.TELEGRAM_BOT_TOKEN;
}

/**
 * Reset cached environment (for testing).
 */
export function resetEnvCache() {
	cachedEnv = null;
}
