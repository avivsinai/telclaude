import type { HouseholdReminderOneShotSchedule } from "./types.js";

export const HOUSEHOLD_REMINDER_TIME_ZONE = "Asia/Jerusalem" as const;
export const HOUSEHOLD_REMINDER_MAX_HORIZON_MS = 365 * 24 * 60 * 60 * 1_000;
export const HOUSEHOLD_REMINDER_RECURRING_DECLINE_HE =
	"כרגע אפשר לקבוע רק תזכורת חד-פעמית. אני יכולה לקבוע תזכורת חד-פעמית — למשל למחר ב-9:00.";

const LOCAL_MINUTE_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$/;
const MINUTE_MS = 60_000;
const MAX_ZONE_OFFSET_MINUTES = 14 * 60;

type LocalParts = {
	readonly year: number;
	readonly month: number;
	readonly day: number;
	readonly hour: number;
	readonly minute: number;
};

export function resolveJerusalemOneShot(
	localDateTime: string,
	options: { readonly nowMs?: number; readonly maxHorizonMs?: number } = {},
): HouseholdReminderOneShotSchedule {
	const { localEpochMs, resolvedAtMs } = resolveJerusalemLocalMinute(localDateTime);
	const nowMs = options.nowMs ?? Date.now();
	const maxHorizonMs = options.maxHorizonMs ?? HOUSEHOLD_REMINDER_MAX_HORIZON_MS;
	validateScheduleWindow(resolvedAtMs, nowMs, maxHorizonMs);

	return {
		timeZone: HOUSEHOLD_REMINDER_TIME_ZONE,
		localDateTime,
		resolvedAtMs,
		resolvedAt: new Date(resolvedAtMs).toISOString(),
		offsetMinutes: (localEpochMs - resolvedAtMs) / MINUTE_MS,
	};
}

export function validateJerusalemOneShotSchedule(
	schedule: HouseholdReminderOneShotSchedule,
	options: { readonly nowMs?: number; readonly maxHorizonMs?: number } = {},
): void {
	if (schedule.timeZone !== HOUSEHOLD_REMINDER_TIME_ZONE) {
		throw new Error("invalid reminder time zone");
	}
	const { localEpochMs, resolvedAtMs } = resolveJerusalemLocalMinute(schedule.localDateTime);
	if (
		schedule.resolvedAtMs !== resolvedAtMs ||
		schedule.resolvedAt !== new Date(resolvedAtMs).toISOString() ||
		schedule.offsetMinutes !== (localEpochMs - resolvedAtMs) / MINUTE_MS
	) {
		throw new Error("reminder wall time, UTC instant, and offset do not match");
	}
	if (options.nowMs !== undefined) {
		validateScheduleWindow(
			resolvedAtMs,
			options.nowMs,
			options.maxHorizonMs ?? HOUSEHOLD_REMINDER_MAX_HORIZON_MS,
		);
	}
}

function validateScheduleWindow(resolvedAtMs: number, nowMs: number, maxHorizonMs: number): void {
	if (!Number.isSafeInteger(nowMs) || !Number.isSafeInteger(maxHorizonMs) || maxHorizonMs <= 0) {
		throw new Error("Household reminder time window is invalid");
	}
	if (resolvedAtMs <= nowMs) {
		throw new Error("Household reminder time must be in the future");
	}
	if (resolvedAtMs - nowMs > maxHorizonMs) {
		throw new Error("Household reminder time must be within 365 days");
	}
}

function resolveJerusalemLocalMinute(localDateTime: string): {
	readonly localEpochMs: number;
	readonly resolvedAtMs: number;
} {
	const local = parseLocalMinute(localDateTime);
	const localEpochMs = Date.UTC(local.year, local.month - 1, local.day, local.hour, local.minute);
	const formatter = localFormatter();
	const candidates: number[] = [];

	for (
		let candidateMs = localEpochMs - MAX_ZONE_OFFSET_MINUTES * MINUTE_MS;
		candidateMs <= localEpochMs + MAX_ZONE_OFFSET_MINUTES * MINUTE_MS;
		candidateMs += MINUTE_MS
	) {
		if (sameLocalParts(formatLocalParts(formatter, candidateMs), local)) {
			candidates.push(candidateMs);
		}
	}

	if (candidates.length === 0) {
		throw new Error("Jerusalem local time does not exist because of the DST transition");
	}
	if (candidates.length > 1) {
		throw new Error("Jerusalem local time is ambiguous because of the DST transition");
	}
	return { localEpochMs, resolvedAtMs: candidates[0] };
}

function parseLocalMinute(value: string): LocalParts {
	const match = LOCAL_MINUTE_RE.exec(value);
	if (!match) {
		throw new Error("Household reminder local time must use minute precision: YYYY-MM-DDTHH:mm");
	}
	const parts: LocalParts = {
		year: Number(match[1]),
		month: Number(match[2]),
		day: Number(match[3]),
		hour: Number(match[4]),
		minute: Number(match[5]),
	};
	const roundTrip = new Date(
		Date.UTC(parts.year, parts.month - 1, parts.day, parts.hour, parts.minute),
	);
	if (
		parts.year < 1970 ||
		roundTrip.getUTCFullYear() !== parts.year ||
		roundTrip.getUTCMonth() + 1 !== parts.month ||
		roundTrip.getUTCDate() !== parts.day ||
		roundTrip.getUTCHours() !== parts.hour ||
		roundTrip.getUTCMinutes() !== parts.minute
	) {
		throw new Error("Household reminder local time is invalid");
	}
	return parts;
}

function localFormatter(): Intl.DateTimeFormat {
	return new Intl.DateTimeFormat("en-CA", {
		timeZone: HOUSEHOLD_REMINDER_TIME_ZONE,
		year: "numeric",
		month: "2-digit",
		day: "2-digit",
		hour: "2-digit",
		minute: "2-digit",
		hourCycle: "h23",
	});
}

function formatLocalParts(formatter: Intl.DateTimeFormat, atMs: number): LocalParts {
	const values = Object.fromEntries(
		formatter
			.formatToParts(atMs)
			.filter((part) => part.type !== "literal")
			.map((part) => [part.type, Number(part.value)]),
	);
	return {
		year: values.year,
		month: values.month,
		day: values.day,
		hour: values.hour,
		minute: values.minute,
	};
}

function sameLocalParts(left: LocalParts, right: LocalParts): boolean {
	return (
		left.year === right.year &&
		left.month === right.month &&
		left.day === right.day &&
		left.hour === right.hour &&
		left.minute === right.minute
	);
}
