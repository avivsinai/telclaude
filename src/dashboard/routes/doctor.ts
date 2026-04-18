import type { FastifyInstance } from "fastify";
import { runDoctor } from "../../commands/doctor.js";
import { getChildLogger } from "../../logging.js";

const logger = getChildLogger({ module: "dashboard-doctor" });

/**
 * On-demand doctor execution. Uses POST because runDoctor fans out probes
 * (network, sidecar health, provider HTTP, etc.) that have observable side
 * effects on rate limits and logs — not a pure GET.
 *
 * `runDoctor` does not write to disk or mutate state, so this route cannot
 * grant any new authority, satisfying the spec's "read-only in effect" rule.
 */
export async function registerDoctorRoute(server: FastifyInstance): Promise<void> {
	server.post("/api/doctor/run", async (_request, reply) => {
		try {
			const report = await runDoctor();
			return reply.send({ ok: true, report });
		} catch (err) {
			logger.warn({ error: String(err) }, "runDoctor failed");
			return reply.status(500).send({
				ok: false,
				error: err instanceof Error ? err.message : String(err),
			});
		}
	});
}
