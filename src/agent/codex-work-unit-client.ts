/**
 * Remote Codex work-unit executor.
 *
 * In Docker mode the background runner lives in the relay, which deliberately
 * mounts no workspace and holds the secrets. Codex work units must therefore
 * execute in the agent container (workspace + tool/network boundary) rather
 * than locally in the relay. This executor delegates a `codex-work-unit` job to
 * the agent's `POST /v1/codex-work-unit` endpoint over the internal-auth channel
 * and returns the agent's `BackgroundExecutorResult` verbatim.
 *
 * Cancellation propagates: the runner's AbortSignal aborts the outgoing fetch,
 * which closes the connection; the agent endpoint binds that close to the Codex
 * child's AbortController so the subprocess dies.
 */

import type { BackgroundExecutorResult } from "../background/runner.js";
import type { BackgroundJob } from "../background/types.js";
import { buildInternalAuthHeaders } from "../internal-auth.js";
import { getChildLogger } from "../logging.js";
import { stripTrailingSlash } from "../utils.js";

const logger = getChildLogger({ module: "codex-work-unit-client" });

const CODEX_WORK_UNIT_PATH = "/v1/codex-work-unit";

export async function remoteCodexWorkUnitExecutor(
	job: BackgroundJob,
	signal: AbortSignal,
): Promise<BackgroundExecutorResult> {
	if (job.payload.kind !== "codex-work-unit") {
		return { ok: false, error: `Unsupported payload kind: ${job.payload.kind}` };
	}

	const agentUrl = process.env.TELCLAUDE_AGENT_URL;
	if (!agentUrl) {
		return { ok: false, error: "TELCLAUDE_AGENT_URL is not configured" };
	}

	const payload = JSON.stringify({
		prompt: job.payload.prompt,
		tier: job.tier,
		cwd: job.payload.cwd,
		sandbox: job.payload.sandbox,
		model: job.payload.model,
		timeoutMs: job.payload.timeoutMs,
	});

	// Mirror the runner's abort onto a local controller so we can both honor an
	// already-aborted signal and tear down the in-flight fetch on cancellation.
	const controller = new AbortController();
	if (signal.aborted) {
		controller.abort();
	} else {
		signal.addEventListener("abort", () => controller.abort(), { once: true });
	}

	const endpoint = `${stripTrailingSlash(agentUrl)}${CODEX_WORK_UNIT_PATH}`;

	try {
		const response = await fetch(endpoint, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				...buildInternalAuthHeaders("POST", CODEX_WORK_UNIT_PATH, payload, { scope: "telegram" }),
			},
			body: payload,
			signal: controller.signal,
		});

		if (!response.ok) {
			const detail = (await response.text()).slice(0, 500);
			return {
				ok: false,
				error: `Agent codex work unit failed (${response.status} ${response.statusText}): ${detail}`,
			};
		}

		const outcome = (await response.json()) as BackgroundExecutorResult;
		if (typeof outcome?.ok !== "boolean") {
			return { ok: false, error: "Agent returned a malformed codex work unit result" };
		}
		return outcome;
	} catch (err) {
		if (controller.signal.aborted) {
			return { ok: false, error: "Aborted" };
		}
		logger.warn({ error: String(err) }, "remote codex work unit fetch failed");
		return { ok: false, error: err instanceof Error ? err.message : String(err) };
	}
}
