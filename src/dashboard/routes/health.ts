import type { FastifyInstance } from "fastify";
import { getChildLogger } from "../../logging.js";
import { collectSystemHealth } from "../../telegram/status-overview.js";

const logger = getChildLogger({ module: "dashboard-health" });

export async function registerHealthRoute(server: FastifyInstance): Promise<void> {
	server.get("/api/health", async (_request, reply) => {
		try {
			const snapshot = await collectSystemHealth();
			return reply.send({ ok: true, snapshot });
		} catch (err) {
			logger.warn({ error: String(err) }, "collectSystemHealth failed");
			return reply.status(500).send({
				ok: false,
				error: err instanceof Error ? err.message : String(err),
			});
		}
	});
}
