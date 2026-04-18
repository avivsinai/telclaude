import type { PermissionTier } from "../config/config.js";
import {
	formatHomeTarget,
	getHomeTargetForChat,
	resolveHomeTargetOwnerId,
} from "../config/sessions.js";
import { addCronJob } from "../cron/store.js";
import type { CronJob, CronSchedule } from "../cron/types.js";

const WEEKDAY_TO_CRON: Record<string, string> = {
	sunday: "0",
	monday: "1",
	tuesday: "2",
	wednesday: "3",
	thursday: "4",
	friday: "5",
	saturday: "6",
};

export const READ_ONLY_CRON_MESSAGE =
	"READ_ONLY tier cannot configure scheduled jobs. Ask an operator to raise your tier first.";

export type ParsedConversationalCronRequest = {
	schedule: CronSchedule;
	scheduleLabel: string;
	prompt: string;
};

export type ConversationalCronHandleResult =
	| {
			handled: false;
	  }
	| {
			handled: true;
			replyText: string;
			job?: CronJob;
	  };

function parseTimeOfDay(raw: string): { hour: number; minute: number; label: string } | null {
	const match = raw
		.trim()
		.toLowerCase()
		.match(/^(\d{1,2})(?::(\d{2}))?\s*(am|pm)?$/);
	if (!match) {
		return null;
	}
	const hourValue = Number.parseInt(match[1], 10);
	const minuteValue = match[2] ? Number.parseInt(match[2], 10) : 0;
	const meridiem = match[3];
	if (Number.isNaN(hourValue) || Number.isNaN(minuteValue) || minuteValue < 0 || minuteValue > 59) {
		return null;
	}

	if (meridiem) {
		if (hourValue < 1 || hourValue > 12) {
			return null;
		}
		const normalizedHour =
			meridiem === "am"
				? hourValue === 12
					? 0
					: hourValue
				: hourValue === 12
					? 12
					: hourValue + 12;
		return {
			hour: normalizedHour,
			minute: minuteValue,
			label: `${String(normalizedHour).padStart(2, "0")}:${String(minuteValue).padStart(2, "0")} UTC`,
		};
	}

	if (hourValue < 0 || hourValue > 23) {
		return null;
	}
	return {
		hour: hourValue,
		minute: minuteValue,
		label: `${String(hourValue).padStart(2, "0")}:${String(minuteValue).padStart(2, "0")} UTC`,
	};
}

function parseRecurrence(raw: string): { cronDay: string; label: string } | null {
	const normalized = raw.trim().toLowerCase();
	if (normalized === "weekday" || normalized === "weekdays") {
		return { cronDay: "1-5", label: "weekdays" };
	}
	if (normalized === "day" || normalized === "daily" || normalized === "everyday") {
		return { cronDay: "*", label: "daily" };
	}
	const day = WEEKDAY_TO_CRON[normalized];
	if (day) {
		return { cronDay: day, label: normalized };
	}
	return null;
}

function buildJobName(prompt: string, scheduleLabel: string): string {
	const excerpt = prompt.replace(/\s+/g, " ").trim().slice(0, 40);
	return `cron ${scheduleLabel} - ${excerpt}`;
}

export function parseConversationalCronRequest(
	body: string,
): ParsedConversationalCronRequest | null {
	const match = body
		.trim()
		.match(
			/^every\s+(weekday|weekdays|day|daily|everyday|monday|tuesday|wednesday|thursday|friday|saturday|sunday)\s+at\s+([0-9]{1,2}(?::[0-9]{2})?\s*(?:am|pm)?)(?:\s*[,;:-]\s*|\s+)(.+)$/i,
		);
	if (!match) {
		return null;
	}

	const recurrence = parseRecurrence(match[1]);
	const timeOfDay = parseTimeOfDay(match[2]);
	const prompt = match[3]?.trim() ?? "";
	if (!recurrence || !timeOfDay || !prompt) {
		return null;
	}

	return {
		schedule: {
			kind: "cron",
			expr: `${timeOfDay.minute} ${timeOfDay.hour} * * ${recurrence.cronDay}`,
		},
		scheduleLabel: `${recurrence.label} at ${timeOfDay.label}`,
		prompt,
	};
}

export function tryHandleConversationalCronRequest(params: {
	body: string;
	chatId: number;
	threadId?: number;
	tier: PermissionTier;
	nowMs?: number;
}): ConversationalCronHandleResult {
	const parsed = parseConversationalCronRequest(params.body);
	if (!parsed) {
		return { handled: false };
	}

	if (params.tier === "READ_ONLY") {
		return {
			handled: true,
			replyText: READ_ONLY_CRON_MESSAGE,
		};
	}

	const homeTarget = getHomeTargetForChat(params.chatId);
	if (!homeTarget) {
		return {
			handled: true,
			replyText:
				"No home target is set yet. Run /sethome in the chat or topic where scheduled replies should land, then try again.",
		};
	}

	const ownerId = resolveHomeTargetOwnerId(params.chatId);
	const job = addCronJob(
		{
			name: buildJobName(parsed.prompt, parsed.scheduleLabel),
			ownerId,
			deliveryTarget: { kind: "home" },
			schedule: parsed.schedule,
			action: { kind: "agent-prompt", prompt: parsed.prompt },
		},
		params.nowMs,
	);

	return {
		handled: true,
		job,
		replyText: `Scheduled \`${job.id}\` for ${parsed.scheduleLabel}. Delivery target: ${formatHomeTarget(homeTarget)}.`,
	};
}
