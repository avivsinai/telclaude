import type { CronSchedule } from "./types.js";

type ParsedField = {
	any: boolean;
	values: Set<number>;
};

type ParsedCron = {
	minute: ParsedField;
	hour: ParsedField;
	dayOfMonth: ParsedField;
	month: ParsedField;
	dayOfWeek: ParsedField;
};

const MINUTE_MS = 60_000;
const TWO_YEARS_IN_MINUTES = 60 * 24 * 366 * 2;

function parsePositiveInt(raw: string): number {
	const parsed = Number.parseInt(raw, 10);
	if (!Number.isFinite(parsed)) {
		throw new Error(`Invalid integer value: ${raw}`);
	}
	return parsed;
}

function parseFieldRange(
	segment: string,
	min: number,
	max: number,
): { start: number; end: number } {
	if (segment === "*") {
		return { start: min, end: max };
	}
	if (segment.includes("-")) {
		const [startRaw, endRaw] = segment.split("-", 2);
		const start = parsePositiveInt(startRaw);
		const end = parsePositiveInt(endRaw);
		if (start > end) {
			throw new Error(`Invalid range '${segment}'`);
		}
		return { start, end };
	}
	const value = parsePositiveInt(segment);
	return { start: value, end: value };
}

function parseField(
	raw: string,
	min: number,
	max: number,
	options?: { allowSundaySeven?: boolean },
): ParsedField {
	const field = raw.trim();
	if (!field) {
		throw new Error("Empty cron field");
	}
	if (field === "*") {
		return { any: true, values: new Set<number>() };
	}

	const values = new Set<number>();
	for (const partRaw of field.split(",")) {
		const part = partRaw.trim();
		if (!part) {
			throw new Error(`Invalid cron field part: '${raw}'`);
		}
		const [rangeExprRaw, stepExprRaw] = part.split("/", 2);
		const rangeExpr = rangeExprRaw.trim();
		const step = stepExprRaw ? parsePositiveInt(stepExprRaw) : 1;
		if (step <= 0) {
			throw new Error(`Invalid cron step '${part}'`);
		}

		const { start, end } = parseFieldRange(rangeExpr, min, max);
		if (start < min || end > max) {
			throw new Error(`Cron value out of range '${part}'`);
		}
		for (let value = start; value <= end; value += step) {
			if (options?.allowSundaySeven && value === 7) {
				values.add(0);
			} else {
				values.add(value);
			}
		}
	}

	if (values.size === 0) {
		throw new Error(`No values resolved for cron field '${raw}'`);
	}
	return { any: false, values };
}

function parseCronExpression(expr: string): ParsedCron {
	const normalized = expr.trim().replace(/\s+/g, " ");
	const parts = normalized.split(" ");
	if (parts.length !== 5) {
		throw new Error("Cron expression must have exactly 5 fields (minute hour day month weekday)");
	}
	return {
		minute: parseField(parts[0], 0, 59),
		hour: parseField(parts[1], 0, 23),
		dayOfMonth: parseField(parts[2], 1, 31),
		month: parseField(parts[3], 1, 12),
		dayOfWeek: parseField(parts[4], 0, 7, { allowSundaySeven: true }),
	};
}

function matchesField(field: ParsedField, value: number): boolean {
	if (field.any) {
		return true;
	}
	return field.values.has(value);
}

function matchesDay(parsed: ParsedCron, date: Date): boolean {
	const dayOfMonth = date.getUTCDate();
	const dayOfWeek = date.getUTCDay();
	const domAny = parsed.dayOfMonth.any;
	const dowAny = parsed.dayOfWeek.any;
	const domMatch = matchesField(parsed.dayOfMonth, dayOfMonth);
	const dowMatch = matchesField(parsed.dayOfWeek, dayOfWeek);

	if (domAny && dowAny) {
		return true;
	}
	if (domAny) {
		return dowMatch;
	}
	if (dowAny) {
		return domMatch;
	}
	return domMatch || dowMatch;
}

function matchesCron(parsed: ParsedCron, date: Date): boolean {
	return (
		matchesField(parsed.minute, date.getUTCMinutes()) &&
		matchesField(parsed.hour, date.getUTCHours()) &&
		matchesField(parsed.month, date.getUTCMonth() + 1) &&
		matchesDay(parsed, date)
	);
}

export function validateCronExpression(expr: string): void {
	void parseCronExpression(expr);
}

export function parseDurationMs(raw: string): number {
	const normalized = raw.trim().toLowerCase();
	const match = normalized.match(/^(\d+)(ms|s|m|h|d)$/);
	if (!match) {
		throw new Error("Duration must be like 30s, 5m, 2h, 1d, or 250ms");
	}
	const amount = Number.parseInt(match[1], 10);
	if (!Number.isFinite(amount) || amount <= 0) {
		throw new Error("Duration value must be positive");
	}
	const unit = match[2];
	const multiplier =
		unit === "ms"
			? 1
			: unit === "s"
				? 1000
				: unit === "m"
					? 60_000
					: unit === "h"
						? 3_600_000
						: 86_400_000;
	const value = amount * multiplier;
	if (!Number.isSafeInteger(value) || value <= 0) {
		throw new Error("Duration value is too large");
	}
	return value;
}

export function parseAtTimestampMs(raw: string): number {
	const atMs = Date.parse(raw);
	if (!Number.isFinite(atMs)) {
		throw new Error(`Invalid ISO timestamp: ${raw}`);
	}
	return atMs;
}

export function getNextCronRunAtMs(expr: string, fromMs: number): number | null {
	const parsed = parseCronExpression(expr);
	const startMs = Math.floor(fromMs / MINUTE_MS) * MINUTE_MS + MINUTE_MS;
	for (let i = 0; i < TWO_YEARS_IN_MINUTES; i += 1) {
		const candidateMs = startMs + i * MINUTE_MS;
		const date = new Date(candidateMs);
		if (matchesCron(parsed, date)) {
			return candidateMs;
		}
	}
	return null;
}

export function computeNextRunAtMs(schedule: CronSchedule, fromMs: number): number | null {
	switch (schedule.kind) {
		case "at": {
			const atMs = parseAtTimestampMs(schedule.at);
			return atMs > fromMs ? atMs : null;
		}
		case "every": {
			if (!Number.isFinite(schedule.everyMs) || schedule.everyMs <= 0) {
				throw new Error("everyMs must be a positive number");
			}
			return fromMs + schedule.everyMs;
		}
		case "cron": {
			return getNextCronRunAtMs(schedule.expr, fromMs);
		}
		default: {
			const exhaustiveCheck: never = schedule;
			throw new Error(`Unsupported schedule type: ${String(exhaustiveCheck)}`);
		}
	}
}
