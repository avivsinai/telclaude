import { executeRemoteQuery } from "../agent/client.js";
import type { TelclaudeConfig } from "../config/config.js";
import { formatHomeTarget, getHomeTarget } from "../config/sessions.js";
import { getChildLogger } from "../logging.js";
import {
	buildTelegramMemoryBundle,
	buildTelegramMemoryPolicyPrompt,
} from "../memory/telegram-memory.js";
import { executePooledQuery, type PooledQueryOptions, type StreamChunk } from "../sdk/client.js";
import { sendTelegramMessage } from "../telegram/outbound.js";
import type { CronActionResult, CronJob } from "./types.js";

const logger = getChildLogger({ module: "cron-agent-action" });

export type CronTelegramDestination = {
	chatId: number;
	threadId?: number;
};

type ScheduledAgentActionDeps = {
	executeRemote?: (
		prompt: string,
		options: PooledQueryOptions,
	) => AsyncGenerator<StreamChunk, void, unknown>;
	executeLocal?: (
		prompt: string,
		options: PooledQueryOptions,
	) => AsyncGenerator<StreamChunk, void, unknown>;
	sendMessage?: typeof sendTelegramMessage;
};

export function resolveCronDeliveryDestination(job: CronJob): CronTelegramDestination | null {
	switch (job.deliveryTarget.kind) {
		case "home": {
			if (!job.ownerId) {
				return null;
			}
			const homeTarget = getHomeTarget(job.ownerId);
			if (!homeTarget) {
				return null;
			}
			return {
				chatId: homeTarget.chatId,
				threadId: homeTarget.threadId,
			};
		}
		case "chat":
			return {
				chatId: job.deliveryTarget.chatId,
				threadId: job.deliveryTarget.threadId,
			};
		case "origin":
			if (job.deliveryTarget.chatId === undefined) {
				return null;
			}
			return {
				chatId: job.deliveryTarget.chatId,
				threadId: job.deliveryTarget.threadId,
			};
		default: {
			const exhaustiveCheck: never = job.deliveryTarget;
			throw new Error(`Unsupported delivery target: ${String(exhaustiveCheck)}`);
		}
	}
}

async function collectQueryResponse(
	queryStream: AsyncGenerator<StreamChunk, void, unknown>,
): Promise<{ success: boolean; response: string; error?: string }> {
	let responseText = "";

	for await (const chunk of queryStream) {
		if (chunk.type === "text") {
			responseText += chunk.content;
			continue;
		}
		if (chunk.type === "done") {
			if (!chunk.result.success) {
				return {
					success: false,
					response: responseText,
					error: chunk.result.error ?? "scheduled prompt failed",
				};
			}
			return {
				success: true,
				response: chunk.result.response || responseText,
			};
		}
	}

	return {
		success: true,
		response: responseText,
	};
}

export async function executeScheduledAgentPromptAction(
	job: CronJob,
	cfg: TelclaudeConfig,
	signal: AbortSignal,
	deps: ScheduledAgentActionDeps = {},
): Promise<CronActionResult> {
	if (job.action.kind !== "agent-prompt") {
		return {
			ok: false,
			message: `unsupported scheduled action: ${job.action.kind}`,
		};
	}

	const destination = resolveCronDeliveryDestination(job);
	if (!destination) {
		const homeDescription =
			job.ownerId && job.deliveryTarget.kind === "home"
				? formatHomeTarget(getHomeTarget(job.ownerId))
				: "not set";
		return {
			ok: false,
			message:
				job.deliveryTarget.kind === "home"
					? `home delivery target unavailable (${homeDescription}). Run /sethome in the destination chat first.`
					: "cron delivery target is missing chat metadata",
		};
	}

	const botToken = cfg.telegram?.botToken ?? process.env.TELEGRAM_BOT_TOKEN;
	if (!botToken) {
		return {
			ok: false,
			message: "telegram bot token is not configured",
		};
	}

	const abortController = new AbortController();
	if (signal.aborted) {
		abortController.abort(signal.reason);
	} else {
		signal.addEventListener("abort", () => abortController.abort(signal.reason), { once: true });
	}

	const chatContext = `<chat-context chat-id="${destination.chatId}"${destination.threadId === undefined ? "" : ` thread-id="${destination.threadId}"`} />`;
	const scheduleContext = [
		"<scheduled-task>",
		"This message was triggered automatically by a cron job.",
		"Reply with the exact Telegram message that should be sent to the destination chat.",
		"Keep the response concise and user-facing. Do not mention internal job ids unless relevant.",
		"</scheduled-task>",
	].join("\n");
	const memoryBundle = buildTelegramMemoryBundle({
		chatId: String(destination.chatId),
		query: job.action.prompt,
		includeRecentHistory: true,
	});
	const systemPromptAppend = [
		chatContext,
		scheduleContext,
		memoryBundle.promptContext
			? `<user-memory type="data" read-only="true">\n${memoryBundle.promptContext}\n</user-memory>`
			: undefined,
		buildTelegramMemoryPolicyPrompt(),
	]
		.filter(Boolean)
		.join("\n\n");

	const queryOptions: PooledQueryOptions = {
		cwd: process.cwd(),
		tier: "WRITE_LOCAL",
		poolKey: `cron:${job.id}`,
		userId: job.ownerId ?? `cron:${job.id}`,
		enableSkills: true,
		timeoutMs: cfg.cron.timeoutSeconds * 1000,
		systemPromptAppend,
		compiledMemoryMd: memoryBundle.compiledMemoryMd,
		abortController,
		betas: cfg.sdk?.betas,
	};

	const queryStream = process.env.TELCLAUDE_AGENT_URL
		? (deps.executeRemote ?? executeRemoteQuery)(job.action.prompt, {
				...queryOptions,
				scope: "telegram",
			})
		: (deps.executeLocal ?? executePooledQuery)(job.action.prompt, queryOptions);

	const queryResult = await collectQueryResponse(queryStream);
	if (!queryResult.success) {
		logger.warn({ jobId: job.id, error: queryResult.error }, "scheduled agent prompt failed");
		return {
			ok: false,
			message: queryResult.error ?? "scheduled prompt failed",
		};
	}

	const responseText = queryResult.response.trim();
	if (!responseText || responseText === "[IDLE]" || responseText.toUpperCase().includes("[IDLE]")) {
		return {
			ok: true,
			message: "scheduled prompt completed with no outbound message",
		};
	}

	const sendResult = await (deps.sendMessage ?? sendTelegramMessage)({
		token: botToken,
		chatId: destination.chatId,
		text: responseText,
		messageThreadId: destination.threadId,
		secretFilterConfig: cfg.security?.secretFilter,
	});
	if (!sendResult.success) {
		return {
			ok: false,
			message: sendResult.error ?? "failed to send cron message to Telegram",
		};
	}

	const preview = responseText.split(/\n/)[0]?.slice(0, 120) ?? "sent";
	return {
		ok: true,
		message: `scheduled prompt sent to chat ${destination.chatId}: ${preview}`,
	};
}
