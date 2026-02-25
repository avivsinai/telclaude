/**
 * Google Services sidecar configuration.
 * Loaded from environment variables with validation.
 */

import { z } from "zod";

const ConfigSchema = z.object({
	port: z.coerce.number().default(3002),
	vaultSocketPath: z.string().default("/run/vault/vault.sock"),
	dataDir: z.string().default("/data"),
	sidecarId: z.string().default("google-services"),
	logLevel: z.enum(["debug", "info", "warn", "error"]).default("info"),
});

export type Config = z.infer<typeof ConfigSchema>;

export function loadConfig(): Config {
	return ConfigSchema.parse({
		port: process.env.PORT,
		vaultSocketPath: process.env.TELCLAUDE_VAULT_SOCKET,
		dataDir: process.env.DATA_DIR,
		sidecarId: process.env.SIDECAR_ID,
		logLevel: process.env.LOG_LEVEL,
	});
}
