import type { CronActionResult } from "../cron/types.js";
import { collectHouseholdMetricRollups, type HouseholdMetricRollup } from "./store.js";

const TIME_ZONE = "Asia/Jerusalem";
const MINUTE_MS = 60_000;
const MAX_OFFSET_MINUTES = 14 * 60;

type LocalDate = { readonly year: number; readonly month: number; readonly day: number };

export function resolveNextJerusalemDigestAt(nowMs: number, atHour: number): number {
	assertAtHour(atHour);
	let localDate = localDateAt(nowMs);
	let candidate = resolveJerusalemLocalMinute(localDate, atHour, 0);
	if (candidate <= nowMs) {
		localDate = addLocalDays(localDate, 1);
		candidate = resolveJerusalemLocalMinute(localDate, atHour, 0);
	}
	return candidate;
}

export function priorJerusalemCalendarDayWindow(nowMs: number): {
	readonly localDate: string;
	readonly fromMs: number;
	readonly toMs: number;
} {
	const today = localDateAt(nowMs);
	const prior = addLocalDays(today, -1);
	return {
		localDate: formatLocalDate(prior),
		fromMs: resolveJerusalemLocalMinute(prior, 0, 0),
		toMs: resolveJerusalemLocalMinute(today, 0, 0),
	};
}

export function createHouseholdMetricsDigestExecutor(dependencies: {
	readonly nowMs?: () => number;
	readonly collectRollups?: (options: {
		readonly fromMs: number;
		readonly toMs: number;
	}) => HouseholdMetricRollup[];
	readonly sendAdminAlert: (alert: {
		readonly level: "info";
		readonly title: string;
		readonly message: string;
	}) => Promise<void>;
}): () => Promise<CronActionResult> {
	return async () => {
		const window = priorJerusalemCalendarDayWindow(dependencies.nowMs?.() ?? Date.now());
		const rows = (dependencies.collectRollups ?? collectHouseholdMetricRollups)({
			fromMs: window.fromMs,
			toMs: window.toMs,
		});
		await dependencies.sendAdminAlert({
			level: "info",
			title: `Household metrics — ${window.localDate}`,
			message: formatDigestRows(rows),
		});
		return { ok: true, message: `household metrics digest sent for ${window.localDate}` };
	};
}

function formatDigestRows(rows: readonly HouseholdMetricRollup[]): string {
	if (rows.length === 0) return "No household activity recorded.";
	return rows.map((row) => `${row.bindingKey} · ${row.metricKind}: ${row.count}`).join("\n");
}

function localDateAt(atMs: number): LocalDate {
	const values = Object.fromEntries(
		new Intl.DateTimeFormat("en-CA", {
			timeZone: TIME_ZONE,
			year: "numeric",
			month: "2-digit",
			day: "2-digit",
		})
			.formatToParts(atMs)
			.filter((part) => part.type !== "literal")
			.map((part) => [part.type, Number(part.value)]),
	);
	return { year: values.year, month: values.month, day: values.day };
}

function addLocalDays(date: LocalDate, days: number): LocalDate {
	const shifted = new Date(Date.UTC(date.year, date.month - 1, date.day + days));
	return {
		year: shifted.getUTCFullYear(),
		month: shifted.getUTCMonth() + 1,
		day: shifted.getUTCDate(),
	};
}

function resolveJerusalemLocalMinute(date: LocalDate, hour: number, minute: number): number {
	const localEpochMs = Date.UTC(date.year, date.month - 1, date.day, hour, minute);
	const formatter = new Intl.DateTimeFormat("en-CA", {
		timeZone: TIME_ZONE,
		year: "numeric",
		month: "2-digit",
		day: "2-digit",
		hour: "2-digit",
		minute: "2-digit",
		hourCycle: "h23",
	});
	const matches: number[] = [];
	for (
		let candidate = localEpochMs - MAX_OFFSET_MINUTES * MINUTE_MS;
		candidate <= localEpochMs + MAX_OFFSET_MINUTES * MINUTE_MS;
		candidate += MINUTE_MS
	) {
		const parts = Object.fromEntries(
			formatter
				.formatToParts(candidate)
				.filter((part) => part.type !== "literal")
				.map((part) => [part.type, Number(part.value)]),
		);
		if (
			parts.year === date.year &&
			parts.month === date.month &&
			parts.day === date.day &&
			parts.hour === hour &&
			parts.minute === minute
		) {
			matches.push(candidate);
		}
	}
	if (matches.length !== 1) {
		throw new Error("Jerusalem digest wall time is missing or ambiguous at the DST boundary");
	}
	return matches[0];
}

function formatLocalDate(date: LocalDate): string {
	return `${String(date.year).padStart(4, "0")}-${String(date.month).padStart(2, "0")}-${String(date.day).padStart(2, "0")}`;
}

function assertAtHour(atHour: number): void {
	if (!Number.isInteger(atHour) || atHour < 0 || atHour > 23) {
		throw new Error("household metrics digest hour must be an integer from 0 through 23");
	}
}
