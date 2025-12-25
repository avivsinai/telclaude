import type { Command } from "commander";
import { loadConfig } from "../config/config.js";
import { readEnv } from "../env.js";
import { getChildLogger } from "../logging.js";
import { sendTelegramMessage } from "../telegram/outbound.js";

const logger = getChildLogger({ module: "cmd-send" });

export type SendOptions = {
	verbose?: boolean;
	media?: string;
	caption?: string;
};

export function registerSendCommand(program: Command): void {
	program
		.command("send")
		.description("Send a message to a Telegram chat")
		.argument("<chatId>", "Telegram chat ID (numeric)")
		.argument("[message]", "Message text to send")
		.option("-m, --media <path>", "Path to media file to send")
		.option("--caption <text>", "Caption for media")
		.action(async (chatId: string, message: string | undefined, opts: SendOptions) => {
			const verbose = program.opts().verbose || opts.verbose;

			try {
				const env = readEnv();
				const cfg = loadConfig();
				const token = env.telegramBotToken;

				const numericChatId = Number.parseInt(chatId, 10);
				if (Number.isNaN(numericChatId)) {
					console.error("Error: chatId must be a numeric value");
					process.exit(1);
				}

				if (!message && !opts.media) {
					console.error("Error: Either message or --media must be provided");
					process.exit(1);
				}

				if (verbose) {
					console.log(`Sending to chat ${numericChatId}...`);
				}

				const result = await sendTelegramMessage({
					token,
					chatId: numericChatId,
					text: message,
					mediaPath: opts.media,
					caption: opts.caption,
					secretFilterConfig: cfg.security?.secretFilter,
				});

				if (result.success) {
					console.log(`Message sent successfully (ID: ${result.messageId})`);
				} else {
					console.error(`Failed to send message: ${result.error}`);
					process.exit(1);
				}
			} catch (err) {
				logger.error({ error: String(err) }, "send command failed");
				console.error(`Error: ${err}`);
				process.exit(1);
			}
		});
}
