import path from "node:path";
import { CONFIG_DIR } from "../utils.js";

const DEFAULT_CONFIG_PATH = path.join(CONFIG_DIR, "telclaude.json");

/**
 * Global config path override. Set via CLI or programmatically.
 */
let configPathOverride: string | null = null;

/**
 * Resolve the config file path from:
 * 1. Programmatic override (set via setConfigPath)
 * 2. TELCLAUDE_CONFIG environment variable
 * 3. Default: ~/.telclaude/telclaude.json
 */
export function resolveConfigPath(): string {
	// 1. Check programmatic override (set from CLI)
	if (configPathOverride) {
		return configPathOverride;
	}

	// 2. Check environment variable
	const envPath = process.env.TELCLAUDE_CONFIG;
	if (envPath) {
		return envPath;
	}

	// 3. Default path
	return DEFAULT_CONFIG_PATH;
}

/**
 * Set the config path override. Called from CLI parsing.
 */
export function setConfigPath(configPath: string | null): void {
	configPathOverride = configPath;
}

/**
 * Reset config path to default (for testing).
 */
export function resetConfigPath(): void {
	configPathOverride = null;
}
