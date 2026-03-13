import type { Api } from "grammy";
import type { AuditLogger } from "../security/audit.js";
import { consumeLinkCode } from "../security/linking.js";
import { sendAuthCard, sendStatusCard } from "./cards/create-helpers.js";
import type { CardActorScope } from "./cards/types.js";
import { collectStatusOverview } from "./status-overview.js";
import type { TelegramInboundMessage } from "./types.js";

const START_COMMAND_REGEX = /^\/start(?:@[A-Za-z0-9_]+)?(?:\s+(\S+))?\s*$/i;
const LINK_CODE_REGEX = /^[A-F0-9]{4}(?:-?[A-F0-9]{4})$/i;
const INVALID_LINK_CODE_MESSAGE =
	"Link code expired or invalid. Generate a new one with `telclaude identity deep-link`.";

function resolveActorScope(chatId: number): CardActorScope {
	return `chat:${chatId}`;
}

export function format2FASetupInstructions(localUserId: string): string {
	return (
		"*Setting up Two-Factor Authentication*\n\n" +
		"For security reasons, TOTP secrets cannot be sent via Telegram.\n\n" +
		"*To set up 2FA:*\n" +
		`1. Run this command on your local machine:\n   \`telclaude auth totp-setup ${localUserId}\`\n\n` +
		"2. Scan the QR code or enter the secret in your authenticator app\n\n" +
		"3. Return here and send `/auth verify <6-digit-code>` to confirm your setup\n\n" +
		"Tip: confirm your linked identity with /me."
	);
}

export async function sendPostAuthStatusCard(
	api: Api,
	chatId: number,
	options: {
		localUserId?: string;
		actorScope?: CardActorScope;
		threadId?: number;
		entityRef?: string;
		title?: string;
	},
): Promise<void> {
	const overview = await collectStatusOverview({ localUserId: options.localUserId });

	await sendStatusCard(api, chatId, {
		title: options.title ?? "System Overview",
		summary: overview.summary,
		details: overview.details,
		actorScope: options.actorScope ?? resolveActorScope(chatId),
		threadId: options.threadId,
		entityRef: options.entityRef ?? `status:onboarding:${chatId}`,
	});
}

export function matchStartCommand(body: string): { payload?: string } | null {
	const match = START_COMMAND_REGEX.exec(body.trim());
	if (!match) {
		return null;
	}

	const payload = match[1]?.trim();
	return payload ? { payload } : {};
}

function isLikelyLinkCode(payload: string): boolean {
	return LINK_CODE_REGEX.test(payload.trim());
}

export async function handleStartOnboarding(options: {
	msg: TelegramInboundMessage;
	api: Api;
	auditLogger: AuditLogger;
}): Promise<boolean> {
	const { msg, api, auditLogger } = options;
	const start = matchStartCommand(msg.body);

	if (!start?.payload) {
		return false;
	}

	if ((msg.chatType ?? "private") !== "private") {
		await msg.reply("For security, /start onboarding only works in a private chat.");
		return true;
	}

	if (!isLikelyLinkCode(start.payload)) {
		await msg.reply(INVALID_LINK_CODE_MESSAGE);
		await auditLogger.log({
			timestamp: new Date(),
			requestId: `start_${Date.now()}`,
			telegramUserId: String(msg.chatId),
			telegramUsername: msg.username,
			chatId: msg.chatId,
			messagePreview: "/start <invalid-payload>",
			permissionTier: "READ_ONLY",
			outcome: "blocked",
			errorType: "onboarding_invalid_payload",
		});
		return true;
	}

	const result = consumeLinkCode(start.payload, msg.chatId, msg.username ?? String(msg.chatId));

	if (!result.success) {
		await msg.reply(INVALID_LINK_CODE_MESSAGE);
		await auditLogger.log({
			timestamp: new Date(),
			requestId: `start_${Date.now()}`,
			telegramUserId: String(msg.chatId),
			telegramUsername: msg.username,
			chatId: msg.chatId,
			messagePreview: "/start <expired-link-code>",
			permissionTier: "READ_ONLY",
			outcome: "blocked",
			errorType: "onboarding_link_invalid_or_expired",
		});
		return true;
	}

	await sendAuthCard(api, msg.chatId, {
		step: "setup",
		summary: `Welcome! This chat is linked as ${result.data.localUserId}. Set up 2FA for secure access?`,
		localUserId: result.data.localUserId,
		actorScope: resolveActorScope(msg.chatId),
		threadId: msg.messageThreadId,
	});

	await auditLogger.log({
		timestamp: new Date(),
		requestId: `start_${Date.now()}`,
		telegramUserId: String(msg.chatId),
		telegramUsername: msg.username,
		chatId: msg.chatId,
		messagePreview: "/start <link-code>",
		permissionTier: "READ_ONLY",
		outcome: "success",
		errorType: `onboarding_linked:${result.data.localUserId}`,
	});

	return true;
}
