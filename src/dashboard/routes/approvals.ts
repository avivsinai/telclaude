import type { FastifyInstance } from "fastify";
import { getChildLogger } from "../../logging.js";
import { listAllowlist } from "../../security/approvals.js";

const logger = getChildLogger({ module: "dashboard-approvals" });

/**
 * READ-ONLY view over the W1 graduated-approval allowlist.
 *
 * Revocation is deliberately NOT exposed: the spec forbids granting or
 * revoking from the dashboard, and mutations should continue to flow through
 * `telclaude approvals revoke` (audit-trailed, operator-initiated).
 */
export async function registerApprovalsRoute(server: FastifyInstance): Promise<void> {
	server.get("/api/approvals/allowlist", async (request, reply) => {
		try {
			const userId = (request.query as Record<string, string | undefined>).userId;
			const entries = listAllowlist(userId ? { userId } : {});
			return reply.send({ ok: true, entries });
		} catch (err) {
			logger.warn({ error: String(err) }, "listAllowlist failed");
			return reply.status(500).send({
				ok: false,
				error: err instanceof Error ? err.message : String(err),
			});
		}
	});
}
