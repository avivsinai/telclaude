import path from "node:path";
import { listCronJobs } from "../cron/store.js";
import type { CronJob } from "../cron/types.js";
import { redactSecrets } from "../security/output-filter.js";
import type { CuratorItemInput } from "./types.js";

function isShellExecutable(command: string): boolean {
	return ["sh", "bash", "zsh", "fish", "dash", "ksh"].includes(path.basename(command.trim()));
}

function safeLabel(value: string): string {
	return redactSecrets(value).replace(/\s+/g, " ").trim().slice(0, 120);
}

export function collectCronHardeningItems(
	jobs: CronJob[] = listCronJobs({ includeDisabled: true }),
): CuratorItemInput[] {
	const items: CuratorItemInput[] = [];
	for (const job of jobs) {
		if (job.action.kind !== "agent-prompt") {
			continue;
		}
		const jobLabel = safeLabel(job.name) || job.id;
		const evidence = {
			jobId: job.id,
			name: jobLabel,
			enabled: job.enabled,
			actionKind: job.action.kind,
			hasAllowedSkills: job.action.allowedSkills !== undefined,
			allowedSkillsCount: job.action.allowedSkills?.length ?? null,
			hasPreprocess: job.action.preprocess !== undefined,
			preprocessCommand: job.action.preprocess
				? path.basename(job.action.preprocess.command)
				: null,
		};
		if (job.action.allowedSkills === undefined) {
			items.push({
				fingerprint: `cron_hardening:${job.id}:missing-allowed-skills:v1`,
				kind: "cron_hardening",
				severity: "medium",
				source: "cron",
				title: `Cron job ${jobLabel} needs a skill allowlist`,
				summary:
					"Scheduled agent prompts can run unattended. Add explicit --skill flags or intentionally set an empty allowlist for no-skill routines.",
				rationale:
					"Unattended automation should not inherit broad private-agent skill access by accident.",
				entityRef: `cron:${job.id}`,
				proposedAction: {
					type: "manual_cron_hardening",
					command: "telclaude maintenance cron remove/add with explicit --skill flags",
				},
				evidence,
				producerKind: "system",
			});
		}
		if (job.action.preprocess && isShellExecutable(job.action.preprocess.command)) {
			items.push({
				fingerprint: `cron_hardening:${job.id}:shell-preprocess:v1`,
				kind: "cron_hardening",
				severity: "high",
				source: "cron",
				title: `Cron job ${jobLabel} uses a shell preprocessor`,
				summary: "Preprocessors should be executable-plus-argv routines, not shell entrypoints.",
				rationale:
					"Shell preprocessors make unattended routines harder to reason about and increase injection risk.",
				entityRef: `cron:${job.id}`,
				proposedAction: {
					type: "manual_cron_hardening",
					command: "replace shell preprocessor with a direct executable and argv",
				},
				evidence,
				producerKind: "system",
			});
		}
	}
	return items;
}
