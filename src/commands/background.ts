/**
 * `telclaude background` CLI commands.
 *
 * The `spawn` subcommand is the primary integration surface for agents: an
 * agent running under Bash (WRITE_LOCAL / SOCIAL / FULL_ACCESS) invokes
 * `telclaude background spawn --title "..." -- <command…>` to register a
 * long-running task. The command persists the job, returns a short id, and
 * exits immediately so the turn is never blocked.
 *
 * Tier gating is belt-and-suspenders: the Bash layer already refuses the call
 * for READ_ONLY users (no Bash access), and here we reject READ_ONLY too in
 * case the CLI is invoked by a non-agent actor. Callers identify their tier
 * via `TELCLAUDE_REQUEST_USER_ID` env (set by the SDK client for Docker mode)
 * or an explicit `--tier` flag.
 */

import type { Command } from "commander";
import { cancelJob, createJob, getJob, getJobByShortId, listJobs } from "../background/index.js";
import type { BackgroundJobPayload, BackgroundJobStatus } from "../background/types.js";
import type { PermissionTier } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import { getUserPermissionTier } from "../security/permissions.js";

const logger = getChildLogger({ module: "cmd-background" });

const VALID_TIERS: PermissionTier[] = ["READ_ONLY", "WRITE_LOCAL", "SOCIAL", "FULL_ACCESS"];

function resolveTier(explicit?: string): PermissionTier {
	if (explicit) {
		if (!VALID_TIERS.includes(explicit as PermissionTier)) {
			throw new Error(`Invalid --tier: ${explicit}. Must be one of ${VALID_TIERS.join(", ")}.`);
		}
		return explicit as PermissionTier;
	}

	const requestUserId = process.env.TELCLAUDE_REQUEST_USER_ID;
	if (requestUserId) {
		return getUserPermissionTier(requestUserId);
	}

	// When we can't infer, fail closed.
	return "READ_ONLY";
}

function ensureCanSpawn(tier: PermissionTier): void {
	if (tier === "READ_ONLY") {
		throw new Error(
			"READ_ONLY tier cannot spawn background jobs. Ask an operator to raise your tier first.",
		);
	}
}

function parseOptionalNumber(raw: string | undefined): number | undefined {
	if (!raw) return undefined;
	const parsed = Number.parseInt(raw, 10);
	if (Number.isNaN(parsed)) {
		throw new Error(`Invalid number: ${raw}`);
	}
	return parsed;
}

export function registerBackgroundCommand(program: Command): void {
	const background = program
		.command("background")
		.description("Register and inspect background jobs");

	background
		.command("spawn")
		.description("Register a long-running task; returns a job id immediately")
		.requiredOption("--title <text>", "Human-readable title for the job")
		.option("--description <text>", "Longer description (optional)")
		.option("--command <cmd>", "Shell command to execute (use quotes)")
		.option("--cwd <path>", "Working directory for the command")
		.option("--timeout-ms <ms>", "Soft timeout in milliseconds")
		.option("--chat-id <id>", "Originating Telegram chat id (auto-inferred if omitted)")
		.option("--thread-id <id>", "Originating Telegram thread id")
		.option("--user-id <id>", "Local user id (auto-inferred if omitted)")
		.option(
			"--tier <tier>",
			"Explicit permission tier; defaults to inferred tier from request context",
		)
		.option("--noop", "Register a noop job (for tests)", false)
		.option("--json", "Emit job metadata as JSON", false)
		.action(async (opts) => {
			const tier = resolveTier(opts.tier);
			ensureCanSpawn(tier);

			const userId =
				opts.userId ?? process.env.TELCLAUDE_REQUEST_USER_ID ?? process.env.USER ?? "unknown";

			const chatId = parseOptionalNumber(opts.chatId) ?? null;
			const threadId = parseOptionalNumber(opts.threadId) ?? null;
			const timeoutMs = parseOptionalNumber(opts.timeoutMs);

			let payload: BackgroundJobPayload;
			if (opts.noop) {
				payload = { kind: "noop", message: "noop" };
			} else if (opts.command) {
				payload = {
					kind: "command",
					command: String(opts.command),
					...(opts.cwd ? { cwd: String(opts.cwd) } : {}),
					...(timeoutMs ? { timeoutMs } : {}),
				};
			} else {
				throw new Error("Either --command or --noop is required.");
			}

			const job = createJob({
				title: String(opts.title),
				description: opts.description ? String(opts.description) : undefined,
				userId,
				chatId,
				threadId,
				tier,
				payload,
			});

			logger.info(
				{
					jobId: job.id,
					shortId: job.shortId,
					tier: job.tier,
					payloadKind: job.payload.kind,
					userId: job.userId,
				},
				"background job registered via CLI",
			);

			if (opts.json) {
				console.log(
					JSON.stringify({
						id: job.id,
						shortId: job.shortId,
						status: job.status,
						tier: job.tier,
						createdAt: new Date(job.createdAtMs).toISOString(),
					}),
				);
			} else {
				console.log(`Queued ${job.shortId} (${job.title})`);
			}
		});

	background
		.command("list")
		.description("List recent background jobs")
		.option("--limit <n>", "Maximum entries (default 25)", "25")
		.option("--status <status>", "Filter by status (comma-separated)")
		.option("--json", "Emit as JSON", false)
		.action(async (opts) => {
			const limit = parseOptionalNumber(opts.limit) ?? 25;
			const statuses = opts.status
				? String(opts.status)
						.split(",")
						.map((s) => s.trim())
						.filter(Boolean)
				: undefined;
			const jobs = listJobs({
				limit,
				...(statuses ? { statuses: statuses as BackgroundJobStatus[] } : {}),
			});
			if (opts.json) {
				console.log(
					JSON.stringify(
						jobs.map((j) => ({
							id: j.id,
							shortId: j.shortId,
							title: j.title,
							status: j.status,
							tier: j.tier,
							createdAt: new Date(j.createdAtMs).toISOString(),
							completedAt: j.completedAtMs ? new Date(j.completedAtMs).toISOString() : null,
						})),
						null,
						2,
					),
				);
				return;
			}
			if (jobs.length === 0) {
				console.log("No background jobs");
				return;
			}
			for (const job of jobs) {
				console.log(
					`${job.shortId}  ${job.status.padEnd(11)}  ${job.title}  (${new Date(job.createdAtMs).toISOString()})`,
				);
			}
		});

	background
		.command("show")
		.description("Show one job by short id")
		.argument("<shortId>", "Short id of the job")
		.option("--json", "Emit as JSON", false)
		.action(async (shortId: string, opts) => {
			const job = getJobByShortId(shortId) ?? getJob(shortId);
			if (!job) {
				throw new Error(`Background job ${shortId} not found`);
			}
			if (opts.json) {
				console.log(JSON.stringify(job, null, 2));
				return;
			}
			console.log(`Title:       ${job.title}`);
			console.log(`Short id:    ${job.shortId}`);
			console.log(`Status:      ${job.status}`);
			console.log(`Tier:        ${job.tier}`);
			console.log(`User:        ${job.userId}`);
			console.log(`Payload:     ${job.payload.kind}`);
			console.log(`Created:     ${new Date(job.createdAtMs).toISOString()}`);
			if (job.startedAtMs) console.log(`Started:     ${new Date(job.startedAtMs).toISOString()}`);
			if (job.completedAtMs)
				console.log(`Completed:   ${new Date(job.completedAtMs).toISOString()}`);
			if (job.error) console.log(`Error:       ${job.error}`);
			if (job.result?.message) console.log(`Result:      ${job.result.message}`);
			if (job.result?.stdout) console.log(`\n--- stdout ---\n${job.result.stdout}`);
			if (job.result?.stderr) console.log(`\n--- stderr ---\n${job.result.stderr}`);
		});

	background
		.command("cancel")
		.description("Cancel a queued or running job")
		.argument("<shortId>", "Short id of the job")
		.action(async (shortId: string) => {
			const job = getJobByShortId(shortId);
			if (!job) {
				throw new Error(`Background job ${shortId} not found`);
			}
			const { transitioned, job: updated } = cancelJob(job.id);
			if (transitioned) {
				console.log(`Cancelled ${job.shortId}`);
			} else {
				console.log(`No-op: job ${job.shortId} is ${updated?.status ?? "unknown"}`);
			}
		});
}
