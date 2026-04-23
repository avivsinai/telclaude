import type { FastifyInstance } from "fastify";
import { getChildLogger } from "../../logging.js";
import { getRemediation } from "../../telegram/remediation-commands.js";
import { collectSystemHealth } from "../../telegram/status-overview.js";

const logger = getChildLogger({ module: "dashboard-health" });

export async function registerHealthRoute(server: FastifyInstance): Promise<void> {
	server.get("/api/health", async (_request, reply) => {
		try {
			const snapshot = await collectSystemHealth();
			const enriched = {
				...snapshot,
				items: snapshot.items.map((item) => {
					const remediation = item.remediation ? getRemediation(item.remediation) : undefined;
					return {
						...item,
						...(remediation
							? {
									remediationCommand: remediation.command,
									remediationTitle: remediation.title,
								}
							: {}),
					};
				}),
			};
			return reply.send({ ok: true, snapshot: enriched });
		} catch (err) {
			logger.warn({ error: String(err) }, "collectSystemHealth failed");
			return reply.status(500).send({
				ok: false,
				error: err instanceof Error ? err.message : String(err),
			});
		}
	});
}
