import { type Api, Bot } from "grammy";
import { readEnv } from "../env.js";
import { redactSecrets } from "../security/output-filter.js";
import { sendApprovalCard } from "./cards/create-helpers.js";
import { initCardSystem } from "./cards/init.js";

export type HouseholdProviderApprovalNotification = {
	readonly chatId: number;
	readonly nonce: string;
	readonly service: string;
	readonly action: string;
};

let configuredTelegramApi: Promise<Api> | null = null;

export async function sendConfiguredHouseholdProviderApprovalNotificationCard(
	input: HouseholdProviderApprovalNotification,
): Promise<void> {
	if (!configuredTelegramApi) {
		configuredTelegramApi = readEnv().then(({ telegramBotToken }) => {
			initCardSystem();
			return new Bot(telegramBotToken).api;
		});
	}
	await sendHouseholdProviderApprovalNotificationCard(await configuredTelegramApi, input);
}

export async function sendHouseholdProviderApprovalNotificationCard(
	api: Api,
	input: HouseholdProviderApprovalNotification,
): Promise<void> {
	const service = redactSecrets(input.service);
	const action = redactSecrets(input.action);
	const nonce = redactSecrets(input.nonce);
	await sendApprovalCard(api, input.chatId, {
		title: redactSecrets("Household provider approval required"),
		body: redactSecrets(
			[
				`Administrative action: ${service}.${action}`,
				"No medical details or account identifiers are shown on this card.",
				`Approve with /approve ${nonce}`,
			].join("\n"),
		),
		nonce,
		actorScope: `chat:${input.chatId}`,
		notificationOnly: true,
	});
}
