import type { Command } from "commander";
import { loadConfig } from "../config/config.js";
import { executeCronAction } from "../cron/actions.js";
import { parseDurationMs, validateCronExpression } from "../cron/parse.js";
import { runCronJobNow } from "../cron/scheduler.js";
import {
	addCronJob,
	getCronCoverage,
	getCronJob,
	getCronStatusSummary,
	listCronJobs,
	listCronRuns,
	removeCronJob,
	setCronJobEnabled,
} from "../cron/store.js";
import type { CronAction, CronAddInput, CronJob, CronSchedule } from "../cron/types.js";
import { getChildLogger } from "../logging.js";

const logger = getChildLogger({ module: "cmd-cron" });

function formatTimestamp(ms: number | null): string {
	if (ms === null) {
		return "-";
	}
	return new Date(ms).toISOString();
}

function parseSchedule(opts: { at?: string; every?: string; cron?: string }): CronSchedule {
	const chosen = [Boolean(opts.at), Boolean(opts.every), Boolean(opts.cron)].filter(Boolean).length;
	if (chosen !== 1) {
		throw new Error("Choose exactly one schedule: --at, --every, or --cron");
	}
	if (opts.at) {
		const at = opts.at.trim();
		if (!at) {
			throw new Error("--at requires an ISO timestamp");
		}
		return { kind: "at", at };
	}
	if (opts.every) {
		return { kind: "every", everyMs: parseDurationMs(opts.every) };
	}
	const expr = opts.cron?.trim();
	if (!expr) {
		throw new Error("--cron requires an expression");
	}
	validateCronExpression(expr);
	return { kind: "cron", expr };
}

function parseAction(opts: { social?: string | boolean; private?: boolean }): CronAction {
	const hasSocial = opts.social !== undefined;
	const hasPrivate = opts.private === true;
	const chosen = [hasSocial, hasPrivate].filter(Boolean).length;
	if (chosen !== 1) {
		throw new Error("Choose exactly one action: --social [serviceId] or --private");
	}
	if (hasPrivate) {
		return { kind: "private-heartbeat" };
	}
	if (opts.social === true) {
		return { kind: "social-heartbeat" };
	}
	const serviceId = typeof opts.social === "string" ? opts.social.trim() : "";
	if (!serviceId) {
		return { kind: "social-heartbeat" };
	}
	return { kind: "social-heartbeat", serviceId };
}

function formatSchedule(schedule: CronSchedule): string {
	switch (schedule.kind) {
		case "at":
			return `at ${schedule.at}`;
		case "every":
			return `every ${schedule.everyMs}ms`;
		case "cron":
			return `cron ${schedule.expr}`;
		default: {
			const exhaustiveCheck: never = schedule;
			return String(exhaustiveCheck);
		}
	}
}

function formatAction(action: CronAction): string {
	if (action.kind === "private-heartbeat") {
		return "private heartbeat";
	}
	if (action.serviceId) {
		return `social heartbeat (${action.serviceId})`;
	}
	return "social heartbeat (all enabled)";
}

function printJobs(jobs: CronJob[]): void {
	if (jobs.length === 0) {
		console.log("No cron jobs.");
		return;
	}
	console.log(
		"ID           Name                 Enabled Next Run                Schedule                    Action",
	);
	for (const job of jobs) {
		const id = job.id.padEnd(12).slice(0, 12);
		const name = job.name.padEnd(20).slice(0, 20);
		const enabled = (job.enabled ? "yes" : "no").padEnd(7);
		const nextRun = formatTimestamp(job.nextRunAtMs).padEnd(23).slice(0, 23);
		const schedule = formatSchedule(job.schedule).padEnd(27).slice(0, 27);
		const action = formatAction(job.action);
		console.log(`${id} ${name} ${enabled} ${nextRun} ${schedule} ${action}`);
	}
}

export function registerCronCommand(program: Command): void {
	const cron = program
		.command("cron")
		.description("Manage local cron jobs for heartbeat automation");

	cron
		.command("status")
		.description("Show scheduler status and cron coverage")
		.option("--json", "Output as JSON")
		.action((opts: { json?: boolean }) => {
			const cfg = loadConfig();
			const summary = getCronStatusSummary();
			const coverage = getCronCoverage();
			const payload = {
				enabled: cfg.cron.enabled,
				pollIntervalSeconds: cfg.cron.pollIntervalSeconds,
				timeoutSeconds: cfg.cron.timeoutSeconds,
				summary,
				coverage,
			};
			if (opts.json) {
				console.log(JSON.stringify(payload, null, 2));
				return;
			}
			console.log("Cron scheduler:");
			console.log(`  Enabled in config: ${cfg.cron.enabled ? "yes" : "no"}`);
			console.log(`  Poll interval: ${cfg.cron.pollIntervalSeconds}s`);
			console.log(`  Job timeout: ${cfg.cron.timeoutSeconds}s`);
			console.log(`  Jobs: ${summary.totalJobs} total, ${summary.enabledJobs} enabled`);
			console.log(`  Running now: ${summary.runningJobs}`);
			console.log(`  Next run: ${formatTimestamp(summary.nextRunAtMs)}`);
			console.log(
				`  Coverage: social(all=${coverage.allSocial ? "yes" : "no"}, specific=${coverage.socialServiceIds.length}), private=${coverage.hasPrivateHeartbeat ? "yes" : "no"}`,
			);
		});

	cron
		.command("list")
		.description("List cron jobs")
		.option("--all", "Include disabled jobs")
		.option("--json", "Output as JSON")
		.action((opts: { all?: boolean; json?: boolean }) => {
			const jobs = listCronJobs({ includeDisabled: opts.all === true });
			if (opts.json) {
				console.log(JSON.stringify({ jobs }, null, 2));
				return;
			}
			printJobs(jobs);
		});

	cron
		.command("add")
		.description("Add a cron job")
		.option("--id <id>", "Optional explicit job id")
		.option("--name <name>", "Job name")
		.option("--at <iso>", "One-shot run at ISO timestamp")
		.option("--every <duration>", "Fixed interval, e.g. 5m or 1h")
		.option("--cron <expr>", "5-field cron expression in UTC")
		.option("--social [serviceId]", "Run social heartbeat (optional service id)")
		.option("--private", "Run private heartbeat")
		.option("--disabled", "Create disabled")
		.option("--json", "Output as JSON")
		.action(
			(opts: {
				id?: string;
				name?: string;
				at?: string;
				every?: string;
				cron?: string;
				social?: string | boolean;
				private?: boolean;
				disabled?: boolean;
				json?: boolean;
			}) => {
				try {
					const schedule = parseSchedule(opts);
					const action = parseAction(opts);
					const input: CronAddInput = {
						...(opts.id?.trim() ? { id: opts.id.trim() } : {}),
						name: opts.name?.trim() || `${action.kind}-${schedule.kind}`,
						enabled: opts.disabled !== true,
						schedule,
						action,
					};
					const job = addCronJob(input);
					if (opts.json) {
						console.log(JSON.stringify({ job }, null, 2));
						return;
					}
					console.log(`Added job ${job.id}`);
					console.log(`  Name: ${job.name}`);
					console.log(`  Schedule: ${formatSchedule(job.schedule)}`);
					console.log(`  Action: ${formatAction(job.action)}`);
					console.log(`  Next run: ${formatTimestamp(job.nextRunAtMs)}`);
				} catch (err) {
					console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
					process.exitCode = 1;
				}
			},
		);

	cron
		.command("remove")
		.description("Remove a cron job")
		.argument("<id>", "Job id")
		.action((id: string) => {
			const removed = removeCronJob(id);
			if (!removed) {
				console.error(`Error: unknown cron job id '${id}'`);
				process.exitCode = 1;
				return;
			}
			console.log(`Removed job ${id}`);
		});

	cron
		.command("enable")
		.description("Enable a cron job")
		.argument("<id>", "Job id")
		.action((id: string) => {
			const job = setCronJobEnabled(id, true);
			if (!job) {
				console.error(`Error: unknown cron job id '${id}'`);
				process.exitCode = 1;
				return;
			}
			console.log(`Enabled job ${id}. Next run: ${formatTimestamp(job.nextRunAtMs)}`);
		});

	cron
		.command("disable")
		.description("Disable a cron job")
		.argument("<id>", "Job id")
		.action((id: string) => {
			const job = setCronJobEnabled(id, false);
			if (!job) {
				console.error(`Error: unknown cron job id '${id}'`);
				process.exitCode = 1;
				return;
			}
			console.log(`Disabled job ${id}`);
		});

	cron
		.command("run")
		.description("Run a cron job now")
		.argument("<id>", "Job id")
		.option("--json", "Output as JSON")
		.action(async (id: string, opts: { json?: boolean }) => {
			try {
				const cfg = loadConfig();
				const existing = getCronJob(id);
				if (!existing) {
					throw new Error(`unknown cron job id '${id}'`);
				}
				const result = await runCronJobNow({
					jobId: id,
					timeoutMs: cfg.cron.timeoutSeconds * 1000,
					executor: (job, signal) => executeCronAction(job, cfg, signal),
				});
				const runs = listCronRuns(id, 1);
				if (opts.json) {
					console.log(
						JSON.stringify(
							{
								result,
								lastRun: runs[0] ?? null,
								job: getCronJob(id),
							},
							null,
							2,
						),
					);
					return;
				}
				console.log(result.message);
				if (runs[0]) {
					console.log(`  Status: ${runs[0].status}`);
					console.log(`  Message: ${runs[0].message}`);
				}
			} catch (err) {
				logger.warn({ error: String(err), jobId: id }, "manual cron run failed");
				console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
				process.exitCode = 1;
			}
		});
}
