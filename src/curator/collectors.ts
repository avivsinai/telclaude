import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { listCronJobs } from "../cron/store.js";
import type { CronJob } from "../cron/types.js";
import { redactSecrets } from "../security/output-filter.js";
import { listSkillInventory, type SkillInventoryEntry } from "../skills/persona.js";
import {
	listSkillInvocationSummaries,
	type SkillInvocationSummary,
} from "../storage/skill-telemetry.js";
import type { CuratorItemInput } from "./types.js";

const DEFAULT_UNUSED_SKILL_THRESHOLD_MS = 30 * 24 * 60 * 60 * 1000;

function isShellExecutable(command: string): boolean {
	return ["sh", "bash", "zsh", "fish", "dash", "ksh"].includes(path.basename(command.trim()));
}

function safeLabel(value: string): string {
	return redactSecrets(value).replace(/\s+/g, " ").trim().slice(0, 120);
}

function telemetryKeyFor(
	source: "telegram" | "social",
	serviceId: string | null,
	skillName: string,
): string {
	return `${source}:${serviceId ?? ""}:${skillName}`;
}

function telemetryKeyForSkill(entry: SkillInventoryEntry): string | null {
	if (entry.provenance.kind !== "agent") return null;
	if (entry.provenance.persona === "telegram") {
		return telemetryKeyFor("telegram", null, entry.name);
	}
	return telemetryKeyFor("social", entry.provenance.serviceId, entry.name);
}

function personaLabel(entry: SkillInventoryEntry): string {
	if (entry.provenance.kind !== "agent") return "user";
	if (entry.provenance.persona === "telegram") return "telegram";
	return `social:${entry.provenance.serviceId}`;
}

function skillEntityRef(entry: SkillInventoryEntry): string {
	if (entry.provenance.kind !== "agent") return `skill:user:${entry.name}`;
	if (entry.provenance.persona === "telegram") return `skill:agent:telegram:${entry.name}`;
	return `skill:agent:social:${entry.provenance.serviceId}:${entry.name}`;
}

function archiveCommandFor(entry: SkillInventoryEntry, contentSha256: string | null): string {
	if (entry.provenance.kind !== "agent") return "manual review";
	const personaArg =
		entry.provenance.persona === "telegram"
			? "--persona telegram"
			: `--persona social --service-id ${entry.provenance.serviceId}`;
	const expectedArg = contentSha256 ? ` --expected-sha256 ${contentSha256}` : "";
	return `telclaude skill-manage archive --name ${entry.name} ${personaArg} --actor-tier WRITE_LOCAL${expectedArg}`;
}

function readSkillFileMetadata(entry: SkillInventoryEntry): {
	contentSha256: string | null;
	updatedAtMs: number;
} {
	const skillMdPath = path.join(entry.dir, "SKILL.md");
	try {
		const stat = fs.lstatSync(skillMdPath);
		if (!stat.isFile() || stat.isSymbolicLink()) {
			return { contentSha256: null, updatedAtMs: stat.mtimeMs };
		}
		const content = fs.readFileSync(skillMdPath);
		return {
			contentSha256: crypto.createHash("sha256").update(content).digest("hex"),
			updatedAtMs: stat.mtimeMs,
		};
	} catch {
		return { contentSha256: null, updatedAtMs: 0 };
	}
}

function dedupeAgentSkills(entries: SkillInventoryEntry[]): SkillInventoryEntry[] {
	const seen = new Set<string>();
	const out: SkillInventoryEntry[] = [];
	for (const entry of entries) {
		if (entry.provenance.kind !== "agent") continue;
		const entityRef = skillEntityRef(entry);
		if (seen.has(entityRef)) continue;
		seen.add(entityRef);
		out.push(entry);
	}
	return out;
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

export function collectUnusedSkillItems(options?: {
	cwd?: string;
	nowMs?: number;
	staleAfterMs?: number;
	inventory?: SkillInventoryEntry[];
	invocationSummaries?: SkillInvocationSummary[];
}): CuratorItemInput[] {
	const nowMs = options?.nowMs ?? Date.now();
	const staleAfterMs = Math.max(1, options?.staleAfterMs ?? DEFAULT_UNUSED_SKILL_THRESHOLD_MS);
	const cutoffMs = nowMs - staleAfterMs;
	const summaries = new Map<string, SkillInvocationSummary>();
	for (const summary of options?.invocationSummaries ?? listSkillInvocationSummaries()) {
		summaries.set(telemetryKeyFor(summary.source, summary.serviceId, summary.skillName), summary);
	}

	const items: CuratorItemInput[] = [];
	for (const entry of dedupeAgentSkills(options?.inventory ?? listSkillInventory(options?.cwd))) {
		const telemetryKey = telemetryKeyForSkill(entry);
		if (!telemetryKey) continue;
		const summary = summaries.get(telemetryKey);
		const fileMetadata = readSkillFileMetadata(entry);
		const lastAllowedAt = summary?.lastAllowedAt ?? null;
		const lastActivityAt = Math.max(lastAllowedAt ?? 0, fileMetadata.updatedAtMs);
		if (lastActivityAt <= 0 || lastActivityAt >= cutoffMs) {
			continue;
		}

		const contentSha256 = fileMetadata.contentSha256;
		const persona = personaLabel(entry);
		const evidence = {
			skillName: entry.name,
			persona,
			relativeDir: entry.relativeDir,
			lastAllowedAt,
			lastInvokedAt: summary?.lastInvokedAt ?? null,
			totalInvocations: summary?.totalCount ?? 0,
			allowedInvocations: summary?.allowedCount ?? 0,
			deniedInvocations: summary?.deniedCount ?? 0,
			skillUpdatedAt: Math.trunc(fileMetadata.updatedAtMs),
			staleAfterDays: Math.ceil(staleAfterMs / (24 * 60 * 60 * 1000)),
			contentSha256,
		};
		items.push({
			fingerprint: `${skillEntityRef(entry)}:unused:${Math.ceil(staleAfterMs / (24 * 60 * 60 * 1000))}d:v1`,
			kind: "skill_review",
			severity: "low",
			source: "skills",
			title: `Agent skill ${safeLabel(entry.name)} looks unused`,
			summary:
				lastAllowedAt === null
					? `No allowed invocations recorded for ${persona} skill ${safeLabel(entry.name)}.`
					: `No allowed invocations recorded since ${new Date(lastAllowedAt).toISOString()} for ${persona} skill ${safeLabel(entry.name)}.`,
			rationale:
				"Agent-authored skills should stay small and intentional; stale skills add prompt surface area and maintenance load.",
			entityRef: skillEntityRef(entry),
			proposedAction: {
				type: "archive_managed_skill",
				command: archiveCommandFor(entry, contentSha256),
			},
			evidence,
			producerKind: "system",
		});
	}
	return items;
}
