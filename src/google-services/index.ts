/**
 * Google Services sidecar entry point.
 */

import { VaultClient } from "../vault-daemon/client.js";
import { JtiStore } from "./approval.js";
import { loadConfig } from "./config.js";
import { HealthStore } from "./health.js";
import { buildServer } from "./server.js";
import { TokenManager } from "./token-manager.js";

const config = loadConfig();

const vault = new VaultClient({ socketPath: config.vaultSocketPath });
const health = new HealthStore();
const tokenManager = new TokenManager(vault, health);
const jtiStore = new JtiStore(config.dataDir);

const server = await buildServer({
	tokenManager,
	jtiStore,
	healthStore: health,
	logLevel: config.logLevel,
});

// Periodic JTI cleanup (every 10 minutes)
const cleanupInterval = setInterval(() => jtiStore.cleanup(), 10 * 60 * 1000);

const shutdown = async () => {
	clearInterval(cleanupInterval);
	jtiStore.close();
	await server.close();
	process.exit(0);
};
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

await server.listen({ port: config.port, host: "0.0.0.0" });
console.log(`Google Services sidecar listening on :${config.port}`);
