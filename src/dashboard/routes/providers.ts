import type { FastifyInstance } from "fastify";
import { loadConfig } from "../../config/config.js";
import { getChildLogger } from "../../logging.js";
import { listCatalogOAuthServices, listProviderCatalogEntries } from "../../providers/catalog.js";

const logger = getChildLogger({ module: "dashboard-providers" });

/**
 * Expose the provider catalog (W7) alongside what's configured in this
 * installation. We deliberately surface both so the UI can show "available but
 * not configured" entries, which is often the actionable signal.
 */
export async function registerProvidersRoute(server: FastifyInstance): Promise<void> {
	server.get("/api/providers", async (_request, reply) => {
		try {
			const cfg = loadConfig();
			const catalog = listProviderCatalogEntries();
			const oauthServices = listCatalogOAuthServices().map((svc) => ({
				id: svc.id,
				displayName: svc.displayName,
			}));
			const configured = (cfg.providers ?? []).map((p) => ({
				id: p.id,
				baseUrl: p.baseUrl,
			}));
			return reply.send({ ok: true, catalog, oauthServices, configured });
		} catch (err) {
			logger.warn({ error: String(err) }, "provider catalog lookup failed");
			return reply.status(500).send({
				ok: false,
				error: err instanceof Error ? err.message : String(err),
			});
		}
	});
}
