import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;
const HOUR_MS = 60 * 60 * 1_000;
const NOW_MS = Date.parse("2026-07-18T09:15:00.000Z");

describe("household metrics store", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-household-metrics-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		vi.resetModules();
		const { resetDatabase } = await import("../../src/storage/db.js");
		resetDatabase();
	});

	afterEach(async () => {
		const { closeDb } = await import("../../src/storage/db.js");
		closeDb();
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) delete process.env.TELCLAUDE_DATA_DIR;
		else process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
	});

	it("stays dark until globally enabled", async () => {
		const metrics = await import("../../src/household-metrics/store.js");

		expect(metrics.recordHouseholdMetric("inbound_received", "mom", NOW_MS)).toBe(false);
		expect(metrics.collectHouseholdMetricRollups()).toEqual([]);
	});

	it("atomically rolls up fixed counters per binding and UTC hour", async () => {
		const metrics = await import("../../src/household-metrics/store.js");
		metrics.configureHouseholdMetrics({ enabled: true });

		expect(metrics.recordHouseholdMetric("inbound_received", "mom", NOW_MS)).toBe(true);
		expect(metrics.recordHouseholdMetric("inbound_received", "mom", NOW_MS + 1_000)).toBe(true);
		expect(metrics.recordHouseholdMetric("proposal_confirmed", "mom", NOW_MS)).toBe(true);
		expect(metrics.recordHouseholdMetric("inbound_received", "dad", NOW_MS + HOUR_MS)).toBe(true);

		expect(metrics.collectHouseholdMetricRollups()).toEqual([
			{ bindingKey: "dad", metricKind: "inbound_received", count: 1 },
			{ bindingKey: "mom", metricKind: "inbound_received", count: 2 },
			{ bindingKey: "mom", metricKind: "proposal_confirmed", count: 1 },
		]);
		expect(
			metrics.collectHouseholdMetricRollups({
				fromMs: Math.floor(NOW_MS / HOUR_MS) * HOUR_MS,
				toMs: Math.floor(NOW_MS / HOUR_MS) * HOUR_MS + HOUR_MS,
			}),
		).toEqual([
			{ bindingKey: "mom", metricKind: "inbound_received", count: 2 },
			{ bindingKey: "mom", metricKind: "proposal_confirmed", count: 1 },
		]);
	});

	it("swallows metric persistence failures without exposing content", async () => {
		const metrics = await import("../../src/household-metrics/store.js");
		metrics.configureHouseholdMetrics({ enabled: true });
		const failingDatabase = {
			prepare: () => {
				throw new Error("payload must never escape");
			},
		};

		expect(() =>
			metrics.recordHouseholdMetric("inbound_received", "mom", NOW_MS, {
				database: failingDatabase as never,
			}),
		).not.toThrow();
		expect(
			metrics.recordHouseholdMetric("inbound_received", "mom", NOW_MS, {
				database: failingDatabase as never,
			}),
		).toBe(false);
	});

	it("derives an opaque binding id only from the canonical household subject", async () => {
		const metrics = await import("../../src/household-metrics/store.js");

		expect(metrics.householdMetricBindingKeyFromSubject("household:mom")).toBe("mom");
		expect(metrics.householdMetricBindingKeyFromSubject("mom")).toBeNull();
		expect(metrics.householdMetricBindingKeyFromSubject("household:+972501234567")).toBeNull();
	});
});
