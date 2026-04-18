import type { FastifyInstance } from "fastify";
import { loadConfig } from "../../config/config.js";
import { getChildLogger } from "../../logging.js";
import { createAuditLogger } from "../../security/audit.js";

const logger = getChildLogger({ module: "dashboard-audit" });

const DEFAULT_LIMIT = 100;
const MAX_LIMIT = 500;

function parseLimit(raw: string | undefined): number {
	if (!raw) return DEFAULT_LIMIT;
	const n = Number.parseInt(raw, 10);
	if (Number.isNaN(n) || n <= 0) return DEFAULT_LIMIT;
	return Math.min(n, MAX_LIMIT);
}

/**
 * Tail of the structured audit log.
 *
 * The AuditLogger already redacts secrets from `messagePreview` before
 * persisting, so surfacing recent entries to the dashboard does not re-expose
 * credentials. We clamp the limit to 500 to protect the UI from a pathological
 * tail query.
 */
export async function registerAuditRoute(server: FastifyInstance): Promise<void> {
	server.get("/api/audit/tail", async (request, reply) => {
		try {
			const cfg = loadConfig();
			if (cfg?.security?.audit?.enabled === false) {
				return reply.send({ ok: true, entries: [], enabled: false });
			}
			const limit = parseLimit((request.query as Record<string, string | undefined>).limit);
			const auditLogger = createAuditLogger({
				enabled: true,
				logFile: cfg?.security?.audit?.logFile,
			});
			const entries = await auditLogger.readRecent(limit);
			// Serialize timestamps; entries may otherwise ship Date instances to the client.
			const serialized = entries.map((entry) => ({
				...entry,
				timestamp: entry.timestamp.toISOString(),
			}));
			return reply.send({ ok: true, enabled: true, entries: serialized });
		} catch (err) {
			logger.warn({ error: String(err) }, "audit tail failed");
			return reply.status(500).send({
				ok: false,
				error: err instanceof Error ? err.message : String(err),
			});
		}
	});
}
