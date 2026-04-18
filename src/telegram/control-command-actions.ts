import type { Api } from "grammy";
import {
	cancelJob as cancelBackgroundJob,
	getJobByShortId as getBackgroundJobByShortId,
	listJobs as listBackgroundJobs,
} from "../background/index.js";
import { listDraftSkills } from "../commands/skills-promote.js";
import { loadConfig, type TelclaudeConfig } from "../config/config.js";
import { deleteSession } from "../config/sessions.js";
import { getChildLogger } from "../logging.js";
import { getSessionManager } from "../sdk/session-manager.js";
import { isAdmin } from "../security/linking.js";
import {
	sendBackgroundJobCard,
	sendBackgroundJobListCard,
	sendPendingQueueCard,
	sendSkillDraftCard,
} from "./cards/create-helpers.js";
import { getEnabledSocialServices, type SocialServiceConfig } from "./cards/menu-state.js";
import { loadPendingQueueEntries } from "./cards/renderers/pending-queue.js";
import type {
	BackgroundJobCardState,
	BackgroundJobListCardState,
	CardActorScope,
} from "./cards/types.js";
import { CardKind } from "./cards/types.js";
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

// ═══════════════════════════════════════════════════════════════════════════════
// Background jobs
// ═══════════════════════════════════════════════════════════════════════════════

const BACKGROUND_LIST_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;

export async function sendBackgroundJobList(
	api: Api,
	opts: { chatId: number; threadId?: number; actorScope: CardActorScope },
): Promise<CommandUiResult> {
	const sinceMs = Date.now() - BACKGROUND_LIST_WINDOW_MS;
	const jobs = listBackgroundJobs({ sinceMs, limit: 25 });
	const state: BackgroundJobListCardState = {
		kind: CardKind.BackgroundJobList,
		title: "Background Jobs",
		entries: jobs.map((j) => ({
			shortId: j.shortId,
			label: j.title,
			status: j.status as BackgroundJobCardState["status"],
			createdAtMs: j.createdAtMs,
		})),
		lastRefreshedAtMs: Date.now(),
	};
	await sendBackgroundJobListCard(api, opts.chatId, {
		state,
		actorScope: opts.actorScope,
		threadId: opts.threadId,
	});
	return { callbackText: `Background jobs: ${jobs.length}` };
}

export async function sendBackgroundJobDetail(
	api: Api,
	opts: {
		chatId: number;
		threadId?: number;
		actorScope: CardActorScope;
		shortId: string;
	},
): Promise<CommandUiResult> {
	const job = getBackgroundJobByShortId(opts.shortId);
	if (!job) {
		await api.sendMessage(opts.chatId, `Background job \`${opts.shortId}\` not found.`, {
			...threadOptions(opts.threadId),
			parse_mode: "MarkdownV2",
		});
		return { callbackText: "Job not found", callbackAlert: true };
	}

	const outputPreview = [job.result?.stdout, job.result?.stderr].filter(Boolean).join("\n---\n");

	const state: BackgroundJobCardState = {
		kind: CardKind.BackgroundJob,
		title: job.title,
		description: job.description ?? undefined,
		shortId: job.shortId,
		payloadKind: job.payload.kind,
		status: job.status as BackgroundJobCardState["status"],
		resultSummary: job.result?.message,
		outputPreview: outputPreview || undefined,
		errorMessage: job.error ?? undefined,
		createdAtMs: job.createdAtMs,
		startedAtMs: job.startedAtMs ?? undefined,
		completedAtMs: job.completedAtMs ?? undefined,
		lastRefreshedAtMs: Date.now(),
	};

	await sendBackgroundJobCard(api, opts.chatId, {
		state,
		actorScope: opts.actorScope,
		threadId: opts.threadId,
	});
	return { callbackText: `Status: ${job.status}` };
}

export async function cancelBackgroundJobCommand(
	api: Api,
	opts: { chatId: number; threadId?: number; shortId: string },
): Promise<CommandUiResult> {
	const job = getBackgroundJobByShortId(opts.shortId);
	if (!job) {
		await api.sendMessage(opts.chatId, `Background job \`${opts.shortId}\` not found.`, {
			...threadOptions(opts.threadId),
			parse_mode: "MarkdownV2",
		});
		return { callbackText: "Not found", callbackAlert: true };
	}
	const { transitioned, job: updated } = cancelBackgroundJob(job.id);
	const text = transitioned
		? `Cancelled ${job.shortId}.`
		: `No-op: job ${job.shortId} is ${updated?.status ?? "unknown"}.`;
	await api.sendMessage(opts.chatId, text, threadOptions(opts.threadId));
	return { callbackText: transitioned ? "Cancelled" : `No-op (${updated?.status})` };
}
