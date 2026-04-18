import type { Api } from "grammy";
import { SkillRootUnavailableError } from "../commands/skill-path.js";
import { type SkillTemplate, scaffoldSkill } from "../commands/skill-scaffold.js";
import {
	formatReportForTelegram as formatDoctorReport,
	runSkillsDoctor,
} from "../commands/skills-doctor.js";
import { listActiveSkills, listDraftSkills } from "../commands/skills-promote.js";
import { loadConfig, type TelclaudeConfig } from "../config/config.js";
import { deleteSession } from "../config/sessions.js";
import { getChildLogger } from "../logging.js";
import { getSessionManager } from "../sdk/session-manager.js";
import { isAdmin } from "../security/linking.js";
import { sendPendingQueueCard, sendSkillDraftCard } from "./cards/create-helpers.js";
import { getEnabledSocialServices, type SocialServiceConfig } from "./cards/menu-state.js";
import { loadPendingQueueEntries } from "./cards/renderers/pending-queue.js";
import type { CardActorScope } from "./cards/types.js";
import { createTypingControllerFromCallback } from "./typing.js";
import { createWizardPrompter, WizardCancelledError, WizardTimeoutError } from "./wizard/index.js";

const logger = getChildLogger({ module: "telegram-control-command-actions" });

export type CommandUiResult = {
	callbackText: string;
	callbackAlert?: boolean;
};

type ThreadOptions = {
	message_thread_id?: number;
};

type SocialAskWizardScope = {
	actorId: number;
	chatId: number;
	threadId?: number;
};

const activeSocialAskWizardScopes = new Set<string>();

type SkillNewWizardScope = {
	actorId: number;
	chatId: number;
	threadId?: number;
};

const activeSkillNewWizardScopes = new Set<string>();

function skillNewWizardScopeKey(scope: SkillNewWizardScope): string {
	return `${scope.chatId}:${scope.threadId ?? "root"}:${scope.actorId}`;
}

function threadOptions(threadId?: number): ThreadOptions {
	return threadId === undefined ? {} : { message_thread_id: threadId };
}

function socialAskWizardScopeKey(scope: SocialAskWizardScope): string {
	return `${scope.chatId}:${scope.threadId ?? "root"}:${scope.actorId}`;
}

export function hasActiveSocialAskWizard(scope: SocialAskWizardScope): boolean {
	return activeSocialAskWizardScopes.has(socialAskWizardScopeKey(scope));
}

export async function openSocialQueueCard(
	api: Api,
	opts: {
		chatId: number;
		actorScope: CardActorScope;
		threadId?: number;
	},
): Promise<CommandUiResult> {
	if (!isAdmin(opts.chatId)) {
		await api.sendMessage(
			opts.chatId,
			"Only admin can view pending entries.",
			threadOptions(opts.threadId),
		);
		return { callbackText: "Only admin can view pending entries.", callbackAlert: true };
	}

	const entries = loadPendingQueueEntries(String(opts.chatId));
	if (entries.length === 0) {
		await api.sendMessage(opts.chatId, "No pending posts.", threadOptions(opts.threadId));
		return { callbackText: "No pending posts.", callbackAlert: true };
	}

	await sendPendingQueueCard(api, opts.chatId, {
		entries,
		actorScope: opts.actorScope,
		threadId: opts.threadId,
	});
	return { callbackText: "Opened pending queue" };
}

export async function openSkillDraftCard(
	api: Api,
	opts: {
		chatId: number;
		actorScope: CardActorScope;
		threadId?: number;
	},
): Promise<CommandUiResult> {
	if (!isAdmin(opts.chatId)) {
		await api.sendMessage(opts.chatId, "Only admin can list drafts.", threadOptions(opts.threadId));
		return { callbackText: "Only admin can list drafts.", callbackAlert: true };
	}

	const drafts = listDraftSkills();
	if (drafts.length === 0) {
		await api.sendMessage(
			opts.chatId,
			"No draft skills awaiting promotion.",
			threadOptions(opts.threadId),
		);
		return { callbackText: "No draft skills awaiting promotion.", callbackAlert: true };
	}

	await sendSkillDraftCard(api, opts.chatId, {
		drafts: drafts.map((name) => ({ id: name, label: name })),
		actorScope: opts.actorScope,
		threadId: opts.threadId,
	});
	return { callbackText: "Opened skill drafts" };
}

export function reloadSkillsSession(sessionKey: string | undefined): CommandUiResult {
	if (!sessionKey) {
		return { callbackText: "No session to reload", callbackAlert: true };
	}
	deleteSession(sessionKey);
	getSessionManager().clearSession(sessionKey);
	return {
		callbackText: "Skills reloaded. Next message starts a fresh session.",
	};
}

export async function sendSkillsListCommand(
	api: Api,
	opts: { chatId: number; threadId?: number },
): Promise<CommandUiResult> {
	if (!isAdmin(opts.chatId)) {
		await api.sendMessage(opts.chatId, "Only admin can list skills.", threadOptions(opts.threadId));
		return { callbackText: "Only admin can list skills.", callbackAlert: true };
	}

	const active = listActiveSkills();
	const drafts = listDraftSkills();
	const lines: string[] = [];
	lines.push(`Skills: ${active.length} active, ${drafts.length} draft`);
	lines.push("");
	if (active.length > 0) {
		lines.push("Active:");
		for (const name of active) {
			lines.push(`  - ${name}`);
		}
		lines.push("");
	}
	if (drafts.length > 0) {
		lines.push("Drafts (awaiting promotion):");
		for (const name of drafts) {
			lines.push(`  - ${name}`);
		}
	}
	if (active.length === 0 && drafts.length === 0) {
		lines.push("No skills found.");
	}

	await api.sendMessage(opts.chatId, lines.join("\n"), threadOptions(opts.threadId));
	return { callbackText: "Sent skills list" };
}

export async function sendSkillsDoctorCommand(
	api: Api,
	opts: { chatId: number; threadId?: number },
): Promise<CommandUiResult> {
	if (!isAdmin(opts.chatId)) {
		await api.sendMessage(
			opts.chatId,
			"Only admin can run skills doctor.",
			threadOptions(opts.threadId),
		);
		return { callbackText: "Only admin.", callbackAlert: true };
	}
	const report = runSkillsDoctor();
	const text = formatDoctorReport(report);
	await api.sendMessage(opts.chatId, text, threadOptions(opts.threadId));
	return {
		callbackText: `Doctor: ${report.passCount} pass, ${report.warnCount} warn, ${report.failCount} fail`,
	};
}

export async function sendSkillsScanCommand(
	api: Api,
	opts: { chatId: number; threadId?: number },
): Promise<CommandUiResult> {
	if (!isAdmin(opts.chatId)) {
		await api.sendMessage(opts.chatId, "Only admin can scan skills.", threadOptions(opts.threadId));
		return { callbackText: "Only admin.", callbackAlert: true };
	}

	const report = runSkillsDoctor();
	const lines: string[] = [];
	let blocked = 0;
	let findings = 0;
	for (const entry of report.entries) {
		const total = entry.counts.critical + entry.counts.high + entry.counts.medium;
		findings += total + entry.counts.info;
		const block = entry.counts.critical > 0 || entry.counts.high > 0;
		if (block) blocked++;
		const icon = block ? "BLOCK" : total > 0 ? "WARN" : "OK";
		lines.push(
			`[${icon}] ${entry.kind} ${entry.name} (c=${entry.counts.critical} h=${entry.counts.high} m=${entry.counts.medium})`,
		);
	}
	const header = `Scanned ${report.entries.length} skills: ${blocked} blocked, ${findings} findings`;
	const body = [header, "", ...lines].join("\n");
	await api.sendMessage(opts.chatId, body, threadOptions(opts.threadId));
	return { callbackText: `Scanned ${report.entries.length} skills` };
}

export async function sendSkillsImportCommand(
	api: Api,
	opts: { chatId: number; threadId?: number },
): Promise<CommandUiResult> {
	const message = [
		"`/skills import` runs from the CLI (requires filesystem source path):",
		"",
		"  telclaude skills import-openclaw <source>",
		"",
		"Imports land in `.claude/skills-draft/` and can be promoted via /skills promote.",
	].join("\n");
	await api.sendMessage(opts.chatId, message, threadOptions(opts.threadId));
	return { callbackText: "Run `telclaude skills import-openclaw` from the CLI." };
}

const SKILL_NAME_PATTERN = /^[a-z0-9][a-z0-9-]*$/;

export function startSkillsNewWizard(
	api: Api,
	opts: {
		actorId: number;
		chatId: number;
		threadId?: number;
		initialName?: string;
	},
): CommandUiResult {
	if (!isAdmin(opts.chatId)) {
		return { callbackText: "Only admin can scaffold skills.", callbackAlert: true };
	}

	const scopeKey = skillNewWizardScopeKey(opts);
	if (activeSkillNewWizardScopes.has(scopeKey)) {
		return {
			callbackText: "Already running a scaffold wizard in this chat.",
			callbackAlert: true,
		};
	}

	activeSkillNewWizardScopes.add(scopeKey);
	void (async () => {
		const wizard = createWizardPrompter({
			api,
			actorId: opts.actorId,
			chatId: opts.chatId,
			threadId: opts.threadId,
		});

		try {
			let name = opts.initialName?.trim();
			if (!name) {
				name = (
					await wizard.text({
						message: "Name the new skill:",
						placeholder: "lowercase-with-hyphens",
						validate: (value) => {
							const trimmed = value.trim();
							if (!trimmed) return "Name cannot be empty.";
							if (!SKILL_NAME_PATTERN.test(trimmed)) {
								return "Use lowercase letters, digits, and hyphens only (e.g. my-skill).";
							}
							return undefined;
						},
					})
				).trim();
			} else if (!SKILL_NAME_PATTERN.test(name)) {
				await api.sendMessage(
					opts.chatId,
					`Invalid skill name "${name}". Use lowercase-with-hyphens.`,
					threadOptions(opts.threadId),
				);
				return;
			}

			const template = await wizard.select<SkillTemplate>({
				message: "Pick a template:",
				options: [
					{ value: "basic", label: "basic", hint: "Read/Grep/Glob only", emoji: "📝" },
					{
						value: "api-client",
						label: "api-client",
						hint: "Calls `telclaude provider-query`",
						emoji: "🔌",
					},
					{
						value: "telegram-render",
						label: "telegram-render",
						hint: "Telegram-friendly formatting",
						emoji: "💬",
					},
				],
			});

			const description = (
				await wizard.text({
					message: `Describe WHEN to invoke "${name}":`,
					placeholder: "Use when users ask ...",
					validate: (value) => {
						const trimmed = value.trim();
						if (trimmed.length < 10) return "Description must be at least 10 characters.";
						return undefined;
					},
				})
			).trim();

			const result = scaffoldSkill({ name, template, description });
			if (!result.success) {
				await api.sendMessage(
					opts.chatId,
					`Scaffold failed: ${result.error}`,
					threadOptions(opts.threadId),
				);
				return;
			}

			const reply = [
				`Draft skill "${name}" scaffolded (template: ${template}).`,
				`  SKILL.md:   ${result.skillMdPath}`,
				`  PREVIEW.md: ${result.previewPath}`,
				"",
				"Next steps:",
				"  1. Edit SKILL.md to match the skill's actual behaviour.",
				"  2. /skills doctor  (verifies frontmatter + scanner)",
				`  3. /skills promote ${name}`,
			].join("\n");
			await api.sendMessage(opts.chatId, reply, threadOptions(opts.threadId));
		} catch (err) {
			if (err instanceof WizardTimeoutError || err instanceof WizardCancelledError) {
				return;
			}
			if (err instanceof SkillRootUnavailableError) {
				await api.sendMessage(
					opts.chatId,
					`Cannot scaffold skill: no writable skill root.\n\n${err.message}`,
					threadOptions(opts.threadId),
				);
				return;
			}
			logger.warn({ error: String(err) }, "skills scaffold wizard failed");
			await api.sendMessage(
				opts.chatId,
				"Failed to scaffold skill. Check logs.",
				threadOptions(opts.threadId),
			);
		} finally {
			await wizard.dismiss().catch(() => {});
			activeSkillNewWizardScopes.delete(scopeKey);
		}
	})();

	return {
		callbackText: opts.initialName
			? `Scaffolding ${opts.initialName}. Answer the prompts above.`
			: "Answer the prompts to scaffold a new skill.",
	};
}

export async function runSocialHeartbeatCommand(
	api: Api,
	opts: {
		chatId: number;
		threadId?: number;
		cfg?: TelclaudeConfig;
		serviceId?: string;
	},
): Promise<CommandUiResult> {
	if (!isAdmin(opts.chatId)) {
		await api.sendMessage(
			opts.chatId,
			"Only admin can trigger heartbeats.",
			threadOptions(opts.threadId),
		);
		return { callbackText: "Only admin can trigger heartbeats.", callbackAlert: true };
	}

	const enabledServices = getEnabledSocialServices(opts.cfg);
	if (enabledServices.length === 0) {
		await api.sendMessage(
			opts.chatId,
			"No social services are enabled.",
			threadOptions(opts.threadId),
		);
		return { callbackText: "No social services are enabled.", callbackAlert: true };
	}

	const targets = opts.serviceId
		? enabledServices.filter((service) => service.id === opts.serviceId)
		: enabledServices;
	if (targets.length === 0) {
		const ids = enabledServices.map((service) => service.id).join(", ");
		await api.sendMessage(
			opts.chatId,
			`Unknown service. Available: ${ids}`,
			threadOptions(opts.threadId),
		);
		return { callbackText: "Unknown service.", callbackAlert: true };
	}

	const label = targets.map((service) => service.id).join(", ");
	await api.sendMessage(
		opts.chatId,
		`Running heartbeat: ${label}...`,
		threadOptions(opts.threadId),
	);
	await api.sendChatAction(opts.chatId, "typing", threadOptions(opts.threadId)).catch(() => {});

	const { createSocialClient, handleSocialHeartbeat } = await import("../social/index.js");
	const results = await Promise.allSettled(
		targets.map(async (service) => {
			const client = await createSocialClient(service);
			if (!client) {
				return { serviceId: service.id, ok: false, message: "client not configured" };
			}
			const result = await handleSocialHeartbeat(service.id, client, service);
			return { serviceId: service.id, ...result };
		}),
	);

	const lines = results.map((result, index) => {
		const serviceId = targets[index].id;
		if (result.status === "rejected") {
			return `${serviceId}: failed - ${String(result.reason).slice(0, 80)}`;
		}
		const { ok, message } = result.value;
		return `${serviceId}: ${ok ? message || "done" : `failed - ${message}`}`;
	});
	await api.sendMessage(opts.chatId, lines.join("\n"), threadOptions(opts.threadId));

	return {
		callbackText:
			targets.length === 1
				? `Heartbeat finished for ${targets[0].id}`
				: `Heartbeat finished for ${targets.length} services`,
	};
}

export async function sendSocialActivityLogCommand(
	api: Api,
	opts: {
		chatId: number;
		threadId?: number;
		serviceId?: string;
		hours?: number;
	},
): Promise<CommandUiResult> {
	if (!isAdmin(opts.chatId)) {
		await api.sendMessage(
			opts.chatId,
			"Only admin can view public activity.",
			threadOptions(opts.threadId),
		);
		return { callbackText: "Only admin can view public activity.", callbackAlert: true };
	}

	const hours = opts.hours ?? 4;
	const { formatActivityLog, getActivitySummary } = await import("../social/activity-log.js");
	const summary = getActivitySummary(opts.serviceId, hours);
	await api.sendMessage(
		opts.chatId,
		formatActivityLog(summary, hours),
		threadOptions(opts.threadId),
	);
	return {
		callbackText:
			opts.serviceId === undefined
				? `Sent activity log (${hours}h)`
				: `Sent ${opts.serviceId} activity log (${hours}h)`,
	};
}

export async function sendSocialAskResponse(
	api: Api,
	opts: {
		chatId: number;
		threadId?: number;
		service: SocialServiceConfig;
		question: string;
	},
): Promise<void> {
	const typing = createTypingControllerFromCallback(() => {
		api.sendChatAction(opts.chatId, "typing", threadOptions(opts.threadId)).catch(() => {});
	});

	typing.start();
	try {
		const { queryPublicPersona } = await import("../social/handler.js");
		const response = await queryPublicPersona(opts.question, opts.service.id, opts.service);
		await api.sendMessage(
			opts.chatId,
			response || "No response from public persona.",
			threadOptions(opts.threadId),
		);
	} catch (err) {
		logger.warn({ error: String(err), serviceId: opts.service.id }, "/social ask query failed");
		await api.sendMessage(
			opts.chatId,
			"Failed to reach public persona. Check logs.",
			threadOptions(opts.threadId),
		);
	} finally {
		typing.stop();
	}
}

export function startSocialAskWizard(
	api: Api,
	opts: {
		actorId: number;
		chatId: number;
		threadId?: number;
		cfg?: TelclaudeConfig;
	},
): CommandUiResult {
	if (!isAdmin(opts.chatId)) {
		return { callbackText: "Only admin can query the public persona.", callbackAlert: true };
	}

	const services = getEnabledSocialServices(opts.cfg ?? loadConfig());
	if (services.length === 0) {
		return { callbackText: "No social services are enabled.", callbackAlert: true };
	}

	const scopeKey = socialAskWizardScopeKey(opts);
	if (activeSocialAskWizardScopes.has(scopeKey)) {
		return {
			callbackText: "Already waiting for your question.",
			callbackAlert: true,
		};
	}

	activeSocialAskWizardScopes.add(scopeKey);
	void (async () => {
		const wizard = createWizardPrompter({
			api,
			actorId: opts.actorId,
			chatId: opts.chatId,
			threadId: opts.threadId,
		});

		try {
			let service = services[0];
			if (services.length > 1) {
				service = await wizard.select({
					message: "Choose a social persona to query:",
					options: services.map((candidate) => ({
						value: candidate,
						label: candidate.id,
						emoji: "🌐",
					})),
				});
			}

			const question = await wizard.text({
				message: `Send the question for ${service.id}:`,
				placeholder: "Reply with your question",
				validate: (value) => (value.trim().length === 0 ? "Question cannot be empty." : undefined),
			});

			await api.sendMessage(opts.chatId, `Querying ${service.id}...`, threadOptions(opts.threadId));
			await sendSocialAskResponse(api, {
				chatId: opts.chatId,
				threadId: opts.threadId,
				service,
				question: question.trim(),
			});
		} catch (err) {
			if (err instanceof WizardTimeoutError || err instanceof WizardCancelledError) {
				return;
			}
			logger.warn({ error: String(err) }, "social ask wizard failed");
			await api.sendMessage(
				opts.chatId,
				"Failed to start social ask flow. Check logs.",
				threadOptions(opts.threadId),
			);
		} finally {
			await wizard.dismiss().catch(() => {});
			activeSocialAskWizardScopes.delete(scopeKey);
		}
	})();

	return {
		callbackText:
			services.length === 1
				? `Reply with a question for ${services[0].id}`
				: "Choose a service, then reply with your question",
	};
}
