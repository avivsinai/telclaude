import type { FastifyInstance } from "fastify";
import { listActiveSkills, listDraftSkills } from "../../commands/skills-promote.js";
import { getChildLogger } from "../../logging.js";

const logger = getChildLogger({ module: "dashboard-skills" });

export async function registerSkillsRoute(server: FastifyInstance): Promise<void> {
	server.get("/api/skills", async (_request, reply) => {
		try {
			const active = listActiveSkills();
			const drafts = listDraftSkills();
			return reply.send({ ok: true, active, drafts });
		} catch (err) {
			logger.warn({ error: String(err) }, "skill listing failed");
			return reply.status(500).send({
				ok: false,
				error: err instanceof Error ? err.message : String(err),
			});
		}
	});
}
