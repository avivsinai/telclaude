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
import type {
	CronAction,
	CronAddInput,
	CronCoverage,
	CronDeliveryTarget,
	CronJob,
	CronSchedule,
	CronStatusSummary,
} from "../cron/types.js";
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

function parsePositiveInteger(raw: string | undefined, label: string): number | undefined {
	if (!raw) return undefined;
	const parsed = Number.parseInt(raw, 10);
	if (Number.isNaN(parsed)) {
		throw new Error(`${label} must be an integer`);
	}
	return parsed;
}

function parseAction(opts: {
	social?: string | boolean;
	private?: boolean;
	prompt?: string;
}): CronAction {
	const hasSocial = opts.social !== undefined;
	const hasPrivate = opts.private === true;
	const hasPrompt = Boolean(opts.prompt?.trim());
	const chosen = [hasSocial, hasPrivate, hasPrompt].filter(Boolean).length;
	if (chosen !== 1) {
		throw new Error("Choose exactly one action: --social [serviceId], --private, or --prompt");
	}
	if (hasPrivate) {
		return { kind: "private-heartbeat" };
	}
	if (hasPrompt) {
		const prompt = opts.prompt?.trim();
		if (!prompt) {
			throw new Error("--prompt requires text");
		}
		return { kind: "agent-prompt", prompt };
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

function parseDeliveryTarget(opts: {
	delivery?: string;
	chatId?: string;
	threadId?: string;
}): CronDeliveryTarget {
	const delivery = opts.delivery?.trim().toLowerCase() ?? "origin";
	if (delivery === "home") {
		return { kind: "home" };
	}

	const chatId = parsePositiveInteger(opts.chatId, "--chat-id");
	const threadId = parsePositiveInteger(opts.threadId, "--thread-id");
	if (delivery === "chat") {
		if (chatId === undefined) {
			throw new Error("--delivery chat requires --chat-id");
		}
		return {
			kind: "chat",
			chatId,
			...(threadId === undefined ? {} : { threadId }),
		};
	}
	if (delivery === "origin") {
		return {
			kind: "origin",
			...(chatId === undefined ? {} : { chatId }),
			...(threadId === undefined ? {} : { threadId }),
		};
	}

	throw new Error("Delivery must be one of: origin, home, chat");
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
	if (action.kind === "agent-prompt") {
		return `agent prompt (${action.prompt.slice(0, 32)})`;
	}
	if (action.serviceId) {
		return `social heartbeat (${action.serviceId})`;
	}
	return "social heartbeat (all automatic-enabled)";
}

function formatDeliveryTarget(target: CronDeliveryTarget): string {
	switch (target.kind) {
		case "home":
			return "home";
		case "chat":
			return target.threadId === undefined
				? `chat:${target.chatId}`
				: `chat:${target.chatId}/${target.threadId}`;
		case "origin":
			if (target.chatId === undefined) {
				return "origin";
			}
			return target.threadId === undefined
				? `origin:${target.chatId}`
				: `origin:${target.chatId}/${target.threadId}`;
		default: {
			const exhaustiveCheck: never = target;
			return String(exhaustiveCheck);
		}
	}
}

export type CronOverview = {
	enabled: boolean;
	pollIntervalSeconds: number;
	timeoutSeconds: number;
	summary: CronStatusSummary;
	coverage: CronCoverage;
	jobs: CronJob[];
};

export function collectCronOverview(options?: {
	includeDisabled?: boolean;
	limit?: number;
}): CronOverview {
	const cfg = loadConfig();
	const jobs = listCronJobs({ includeDisabled: options?.includeDisabled });
	return {
		enabled: cfg.cron.enabled,
		pollIntervalSeconds: cfg.cron.pollIntervalSeconds,
		timeoutSeconds: cfg.cron.timeoutSeconds,
		summary: getCronStatusSummary(),
		coverage: getCronCoverage(),
		jobs: typeof options?.limit === "number" ? jobs.slice(0, options.limit) : jobs,
	};
}

export function formatCronOverview(overview: CronOverview): string {
	const lines = [
		"Cron scheduler",
		`Enabled in config: ${overview.enabled ? "yes" : "no"}`,
		`Poll interval: ${overview.pollIntervalSeconds}s`,
		`Job timeout: ${overview.timeoutSeconds}s`,
		`Jobs: ${overview.summary.enabledJobs}/${overview.summary.totalJobs} enabled`,
		`Running now: ${overview.summary.runningJobs}`,
		`Next run: ${formatTimestamp(overview.summary.nextRunAtMs)}`,
		`Coverage: social(all=${overview.coverage.allSocial ? "yes" : "no"}, specific=${overview.coverage.socialServiceIds.length}), private=${overview.coverage.hasPrivateHeartbeat ? "yes" : "no"}`,
	];

	if (overview.jobs.length > 0) {
		lines.push("", "Recent jobs:");
		for (const job of overview.jobs) {
			const status = job.lastStatus ? `, last=${job.lastStatus}` : "";
			lines.push(
				`- ${job.id}: ${job.name} (${job.enabled ? "enabled" : "disabled"}, next=${formatTimestamp(job.nextRunAtMs)}, delivery=${formatDeliveryTarget(job.deliveryTarget)}, action=${formatAction(job.action)}${status})`,
			);
		}
	}

	return lines.join("\n");
}

function printJobs(jobs: CronJob[]): void {
	if (jobs.length === 0) {
		console.log("No cron jobs.");
		return;
	}
	console.log(
		"ID           Name                 Enabled Next Run                Delivery          Schedule                    Action",
	);
	for (const job of jobs) {
		const id = job.id.padEnd(12).slice(0, 12);
		const name = job.name.padEnd(20).slice(0, 20);
		const enabled = (job.enabled ? "yes" : "no").padEnd(7);
		const nextRun = formatTimestamp(job.nextRunAtMs).padEnd(23).slice(0, 23);
		const delivery = formatDeliveryTarget(job.deliveryTarget).padEnd(16).slice(0, 16);
		const schedule = formatSchedule(job.schedule).padEnd(27).slice(0, 27);
		const action = formatAction(job.action);
		console.log(`${id} ${name} ${enabled} ${nextRun} ${delivery} ${schedule} ${action}`);
	}
}

export function registerCronCommand(program: Command): void {
	const cron = program
		.command("cron")
		.description("Manage local cron jobs for scheduled automation");

	cron
		.command("status")
		.description("Show scheduler status and cron coverage")
		.option("--json", "Output as JSON")
		.action((opts: { json?: boolean }) => {
			const payload = collectCronOverview();
			if (opts.json) {
				console.log(JSON.stringify(payload, null, 2));
				return;
			}
			console.log(formatCronOverview(payload));
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
		.option("--prompt <text>", "Run a scheduled agent prompt")
		.option("--delivery <target>", "Delivery target: origin, home, or chat", "origin")
		.option("--owner <id>", "Owner id required for --delivery home")
		.option("--chat-id <id>", "Chat id for --delivery chat or explicit origin metadata")
		.option("--thread-id <id>", "Thread/topic id for explicit delivery metadata")
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
				prompt?: string;
				delivery?: string;
				owner?: string;
				chatId?: string;
				threadId?: string;
				disabled?: boolean;
				json?: boolean;
			}) => {
				try {
					const schedule = parseSchedule(opts);
					const action = parseAction(opts);
					const deliveryTarget = parseDeliveryTarget(opts);
					const input: CronAddInput = {
						...(opts.id?.trim() ? { id: opts.id.trim() } : {}),
						name: opts.name?.trim() || `${action.kind}-${schedule.kind}`,
						enabled: opts.disabled !== true,
						...(opts.owner?.trim() ? { ownerId: opts.owner.trim() } : {}),
						deliveryTarget,
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
					console.log(`  Delivery: ${formatDeliveryTarget(job.deliveryTarget)}`);
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
