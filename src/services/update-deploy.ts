import { getChildLogger } from "../logging.js";
import { buildRuntimeSnapshot, type RuntimeSnapshot } from "../system-metadata.js";
import { getOctokit } from "./github-app.js";

const logger = getChildLogger({ module: "update-deploy" });

export const TELCLAUDE_REPOSITORY_OWNER = "avivsinai";
export const TELCLAUDE_REPOSITORY_NAME = "telclaude";
export const TELCLAUDE_MAIN_REF = "main";
export const TELCLAUDE_CI_WORKFLOW_ID = "ci.yml";
const TELCLAUDE_REPOSITORY = `${TELCLAUDE_REPOSITORY_OWNER}/${TELCLAUDE_REPOSITORY_NAME}`;
export const TELCLAUDE_ACTIONS_WORKFLOW_URL = `https://github.com/${TELCLAUDE_REPOSITORY_OWNER}/${TELCLAUDE_REPOSITORY_NAME}/actions/workflows/${TELCLAUDE_CI_WORKFLOW_ID}`;

type UpdateErrorCode = "not_configured" | "forbidden" | "upstream_error";

export type UpdateStatusResult =
	| {
			ok: true;
			runtime: RuntimeSnapshot;
			mainSha: string;
			mainShortSha: string;
			relation: "current" | "behind" | "different" | "unknown";
			aheadBy?: number;
			workflowUrl: string;
	  }
	| {
			ok: false;
			code: UpdateErrorCode;
			message: string;
			runtime: RuntimeSnapshot;
			workflowUrl: string;
	  };

export type UpdateDeployResult =
	| {
			ok: true;
			workflowUrl: string;
			runUrl?: string;
	  }
	| {
			ok: false;
			code: UpdateErrorCode;
			message: string;
			workflowUrl: string;
	  };

function runtimeSnapshot(): RuntimeSnapshot {
	const now = Date.now();
	return buildRuntimeSnapshot(now - Math.floor(process.uptime() * 1000), now);
}

function shortSha(sha: string): string {
	return sha.slice(0, 7);
}

function errorStatus(error: unknown): number | undefined {
	if (typeof error !== "object" || error === null) return undefined;
	const status = (error as { status?: unknown }).status;
	return typeof status === "number" ? status : undefined;
}

function forbiddenMessage(): string {
	return [
		"GitHub App permission denied.",
		"Ask the operator to grant the GitHub App Actions: write permission for this repo, then rerun /update deploy.",
		`Fallback: gh workflow run ${TELCLAUDE_CI_WORKFLOW_ID} --ref ${TELCLAUDE_MAIN_REF}`,
	].join(" ");
}

async function compareMainAhead(
	octokit: NonNullable<Awaited<ReturnType<typeof getOctokit>>>,
	runningRevision: string,
): Promise<number | undefined> {
	if (!runningRevision || runningRevision === "unknown") return undefined;
	try {
		const { data } = await octokit.rest.repos.compareCommitsWithBasehead({
			owner: TELCLAUDE_REPOSITORY_OWNER,
			repo: TELCLAUDE_REPOSITORY_NAME,
			basehead: `${runningRevision}...${TELCLAUDE_MAIN_REF}`,
		});
		return typeof data.ahead_by === "number" ? data.ahead_by : undefined;
	} catch (err) {
		logger.debug(
			{ error: String(err), runningRevision },
			"github compare for update status failed",
		);
		return undefined;
	}
}

function isNewDispatchRun(
	run: { created_at?: string | null },
	dispatchStartedAtMs: number,
): boolean {
	const createdAtMs = Date.parse(run.created_at ?? "");
	if (!Number.isFinite(createdAtMs)) return false;
	return createdAtMs >= dispatchStartedAtMs - 15_000;
}

export async function collectUpdateStatus(): Promise<UpdateStatusResult> {
	const runtime = runtimeSnapshot();
	const octokit = await getOctokit({
		repository: TELCLAUDE_REPOSITORY,
		permissions: { contents: "read" },
	});
	if (!octokit) {
		return {
			ok: false,
			code: "not_configured",
			message: "GitHub App is not configured. Run telclaude secrets setup-github-app.",
			runtime,
			workflowUrl: TELCLAUDE_ACTIONS_WORKFLOW_URL,
		};
	}

	try {
		const { data } = await octokit.rest.repos.getCommit({
			owner: TELCLAUDE_REPOSITORY_OWNER,
			repo: TELCLAUDE_REPOSITORY_NAME,
			ref: TELCLAUDE_MAIN_REF,
		});
		const mainSha = data.sha;
		const runningRevision = runtime.revision;
		const isCurrent =
			runningRevision !== "unknown" &&
			(mainSha === runningRevision || mainSha.startsWith(runningRevision));
		const aheadBy = isCurrent ? 0 : await compareMainAhead(octokit, runningRevision);
		const relation = isCurrent
			? "current"
			: aheadBy === undefined
				? runningRevision === "unknown"
					? "unknown"
					: "different"
				: aheadBy > 0
					? "behind"
					: "different";
		return {
			ok: true,
			runtime,
			mainSha,
			mainShortSha: shortSha(mainSha),
			relation,
			aheadBy,
			workflowUrl: TELCLAUDE_ACTIONS_WORKFLOW_URL,
		};
	} catch (err) {
		if (errorStatus(err) === 403) {
			return {
				ok: false,
				code: "forbidden",
				message: "GitHub App permission denied while checking main.",
				runtime,
				workflowUrl: TELCLAUDE_ACTIONS_WORKFLOW_URL,
			};
		}
		logger.warn({ error: String(err) }, "failed to collect update status");
		return {
			ok: false,
			code: "upstream_error",
			message: "Could not check GitHub main right now.",
			runtime,
			workflowUrl: TELCLAUDE_ACTIONS_WORKFLOW_URL,
		};
	}
}

export async function dispatchMainDeploy(): Promise<UpdateDeployResult> {
	const octokit = await getOctokit({
		repository: TELCLAUDE_REPOSITORY,
		permissions: { actions: "write" },
	});
	if (!octokit) {
		return {
			ok: false,
			code: "not_configured",
			message: "GitHub App is not configured. Run telclaude secrets setup-github-app.",
			workflowUrl: TELCLAUDE_ACTIONS_WORKFLOW_URL,
		};
	}

	try {
		const dispatchStartedAtMs = Date.now();
		await octokit.rest.actions.createWorkflowDispatch({
			owner: TELCLAUDE_REPOSITORY_OWNER,
			repo: TELCLAUDE_REPOSITORY_NAME,
			workflow_id: TELCLAUDE_CI_WORKFLOW_ID,
			ref: TELCLAUDE_MAIN_REF,
		});
		const runs = await octokit.rest.actions
			.listWorkflowRuns({
				owner: TELCLAUDE_REPOSITORY_OWNER,
				repo: TELCLAUDE_REPOSITORY_NAME,
				workflow_id: TELCLAUDE_CI_WORKFLOW_ID,
				branch: TELCLAUDE_MAIN_REF,
				event: "workflow_dispatch",
				per_page: 1,
			})
			.catch((err) => {
				logger.debug({ error: String(err) }, "failed to resolve dispatched workflow run");
				return null;
			});
		const runUrl = runs?.data.workflow_runs.find((run) =>
			isNewDispatchRun(run, dispatchStartedAtMs),
		)?.html_url;
		return {
			ok: true,
			workflowUrl: TELCLAUDE_ACTIONS_WORKFLOW_URL,
			runUrl: runUrl || undefined,
		};
	} catch (err) {
		if (errorStatus(err) === 403) {
			return {
				ok: false,
				code: "forbidden",
				message: forbiddenMessage(),
				workflowUrl: TELCLAUDE_ACTIONS_WORKFLOW_URL,
			};
		}
		logger.warn({ error: String(err) }, "failed to dispatch update deploy workflow");
		return {
			ok: false,
			code: "upstream_error",
			message: "Could not dispatch the deploy workflow right now.",
			workflowUrl: TELCLAUDE_ACTIONS_WORKFLOW_URL,
		};
	}
}
