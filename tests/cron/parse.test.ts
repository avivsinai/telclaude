import { describe, expect, it } from "vitest";
import {
	computeNextRunAtMs,
	getNextCronRunAtMs,
	parseDurationMs,
	validateCronExpression,
} from "../../src/cron/parse.js";

describe("cron parse helpers", () => {
	it("parses duration strings", () => {
		expect(parseDurationMs("5m")).toBe(300000);
		expect(parseDurationMs("30s")).toBe(30000);
		expect(parseDurationMs("250ms")).toBe(250);
	});

	it("rejects invalid duration format", () => {
		expect(() => parseDurationMs("10")).toThrow();
		expect(() => parseDurationMs("-5m")).toThrow();
	});

	it("validates 5-field cron expression", () => {
		expect(() => validateCronExpression("*/5 * * * *")).not.toThrow();
		expect(() => validateCronExpression("* * * *")).toThrow();
	});

	it("computes next run for cron expression", () => {
		const from = Date.parse("2026-02-21T10:03:00.000Z");
		const next = getNextCronRunAtMs("*/5 * * * *", from);
		expect(next).toBe(Date.parse("2026-02-21T10:05:00.000Z"));
	});

	it("computes next run for schedule variants", () => {
		const from = Date.parse("2026-02-21T10:00:00.000Z");
		expect(computeNextRunAtMs({ kind: "every", everyMs: 60000 }, from)).toBe(
			Date.parse("2026-02-21T10:01:00.000Z"),
		);
		expect(computeNextRunAtMs({ kind: "at", at: "2026-02-21T10:02:00.000Z" }, from)).toBe(
			Date.parse("2026-02-21T10:02:00.000Z"),
		);
	});
});
