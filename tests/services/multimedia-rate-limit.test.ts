import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	type FeatureRateLimitConfig,
	MultimediaRateLimiter,
} from "../../src/services/multimedia-rate-limit.js";
import { getDb, resetDatabase } from "../../src/storage/db.js";

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;
const LIMITS: FeatureRateLimitConfig = {
	maxPerHourPerUser: 5,
	maxPerDayPerUser: 10,
};

const MINUTE_LIMITS: FeatureRateLimitConfig = {
	maxPerMinutePerUser: 5,
	maxPerHourPerUser: 300,
	maxPerDayPerUser: 7_200,
};

describe("multimedia rate-limit windows", () => {
	let tempDir: string;
	let limiter: MultimediaRateLimiter;

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tc-multimedia-rate-limit-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		resetDatabase();
		limiter = new MultimediaRateLimiter();
		vi.useFakeTimers();
	});

	afterEach(() => {
		vi.useRealTimers();
		resetDatabase();
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) delete process.env.TELCLAUDE_DATA_DIR;
		else process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
	});

	it.each([
		["midnight UTC", "2026-07-19T00:30:00.000Z"],
		["midday UTC", "2026-07-19T12:30:00.000Z"],
	])("counts one point in each independent window at %s", (_label, now) => {
		vi.setSystemTime(new Date(now));

		for (let index = 0; index < LIMITS.maxPerHourPerUser; index += 1) {
			expect(limiter.checkLimit("skill_request", "operator", LIMITS).allowed).toBe(true);
			limiter.consume("skill_request", "operator");
		}

		expect(limiter.getUsage("skill_request", "operator")).toEqual({ hour: 5, day: 5 });
		expect(limiter.checkLimit("skill_request", "operator", LIMITS)).toMatchObject({
			allowed: false,
			reason: expect.stringContaining("Hourly limit reached"),
		});
	});

	it("stores hour and day usage in distinct rows and resets legacy usage", () => {
		vi.setSystemTime(new Date("2026-07-19T00:30:00.000Z"));
		limiter.consume("skill_request", "operator");
		getDb()
			.prepare(
				"INSERT INTO rate_limits (limiter_type, key, window_start, points) VALUES (?, ?, ?, ?)",
			)
			.run("multimedia_skill_request", "operator", Date.now(), 3);

		const rows = getDb()
			.prepare("SELECT limiter_type, points FROM rate_limits WHERE key = ? ORDER BY limiter_type")
			.all("operator");
		expect(rows).toEqual([
			{ limiter_type: "multimedia_skill_request", points: 3 },
			{ limiter_type: "multimedia_skill_request_day", points: 1 },
			{ limiter_type: "multimedia_skill_request_hour", points: 1 },
		]);

		limiter.resetUser("skill_request", "operator");
		expect(
			getDb().prepare("SELECT COUNT(*) AS count FROM rate_limits WHERE key = ?").get("operator"),
		).toEqual({ count: 0 });
	});

	it("enforces the daily threshold independently of the hourly threshold", () => {
		vi.setSystemTime(new Date("2026-07-19T00:30:00.000Z"));
		const dailyFirstLimits = { maxPerHourPerUser: 10, maxPerDayPerUser: 2 };

		for (let index = 0; index < dailyFirstLimits.maxPerDayPerUser; index += 1) {
			expect(limiter.checkLimit("skill_request", "operator", dailyFirstLimits).allowed).toBe(true);
			limiter.consume("skill_request", "operator");
		}

		expect(limiter.checkLimit("skill_request", "operator", dailyFirstLimits)).toMatchObject({
			allowed: false,
			reason: expect.stringContaining("Daily limit reached"),
		});
	});

	it("atomically reserves at most five points per fixed minute", () => {
		vi.setSystemTime(new Date("2026-07-19T12:30:30.000Z"));

		for (let index = 0; index < 5; index += 1) {
			expect(() =>
				limiter.reserve("household_auto_grant_outbound", "household:parent-a", MINUTE_LIMITS),
			).not.toThrow();
		}
		expect(() =>
			limiter.reserve("household_auto_grant_outbound", "household:parent-a", MINUTE_LIMITS),
		).toThrow("Minute limit reached (5/minute)");

		const rows = getDb()
			.prepare("SELECT limiter_type, points FROM rate_limits WHERE key = ? ORDER BY limiter_type")
			.all("household:parent-a");
		expect(rows).toEqual([
			{ limiter_type: "multimedia_household_auto_grant_outbound_day", points: 5 },
			{ limiter_type: "multimedia_household_auto_grant_outbound_hour", points: 5 },
			{ limiter_type: "multimedia_household_auto_grant_outbound_minute", points: 5 },
		]);
	});

	it("opens a fresh fixed-minute reservation window", () => {
		vi.setSystemTime(new Date("2026-07-19T12:30:59.000Z"));
		for (let index = 0; index < 5; index += 1) {
			limiter.reserve("household_auto_grant_outbound", "household:parent-a", MINUTE_LIMITS);
		}
		expect(() =>
			limiter.reserve("household_auto_grant_outbound", "household:parent-a", MINUTE_LIMITS),
		).toThrow("Minute limit reached");

		vi.setSystemTime(new Date("2026-07-19T12:31:00.000Z"));
		expect(() =>
			limiter.reserve("household_auto_grant_outbound", "household:parent-a", MINUTE_LIMITS),
		).not.toThrow();
	});

	it("throws and reserves nothing when the transactional reservation fails", () => {
		getDb().exec("DROP TABLE rate_limits");

		expect(() =>
			limiter.reserve("household_auto_grant_outbound", "household:parent-a", MINUTE_LIMITS),
		).toThrow();
	});
});
