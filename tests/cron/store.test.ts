import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

describe("cron store", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-cron-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		vi.resetModules();
		const { resetDatabase } = await import("../../src/storage/db.js");
		resetDatabase();
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) {
			delete process.env.TELCLAUDE_DATA_DIR;
		} else {
			process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
		}
	});

	it("adds and lists cron jobs", async () => {
		const { addCronJob, listCronJobs } = await import("../../src/cron/store.js");
		const now = Date.parse("2026-02-21T10:00:00.000Z");

		const job = addCronJob(
			{
				name: "every minute",
				schedule: { kind: "every", everyMs: 60_000 },
				action: { kind: "social-heartbeat", serviceId: "xtwitter" },
			},
			now,
		);

		expect(job.id).toMatch(/^cron-/);
		const jobs = listCronJobs({ includeDisabled: true });
		expect(jobs).toHaveLength(1);
		expect(jobs[0].name).toBe("every minute");
		expect(jobs[0].nextRunAtMs).toBe(now + 60_000);
		expect(jobs[0].deliveryTarget).toEqual({ kind: "origin" });
	});

	it("persists delivery targets and agent prompts", async () => {
		const { addCronJob, getCronJob } = await import("../../src/cron/store.js");
		const now = Date.parse("2026-02-21T10:00:00.000Z");

		const created = addCronJob(
			{
				id: "cron-hn",
				name: "weekday hn",
				ownerId: "alice",
				deliveryTarget: { kind: "home" },
				schedule: { kind: "cron", expr: "0 9 * * 1-5" },
				action: {
					kind: "agent-prompt",
					prompt: "check HN and post here",
					allowedSkills: ["summarize", "memory"],
					preprocess: {
						command: "node",
						args: ["scripts/hn-context.js"],
						cwd: "scripts",
						timeoutMs: 5_000,
						maxStdoutBytes: 2_048,
					},
				},
			},
			now,
		);

		expect(created.ownerId).toBe("alice");
		expect(created.deliveryTarget).toEqual({ kind: "home" });
		expect(created.action).toEqual({
			kind: "agent-prompt",
			prompt: "check HN and post here",
			allowedSkills: ["summarize", "memory"],
			preprocess: {
				command: "node",
				args: ["scripts/hn-context.js"],
				cwd: "scripts",
				timeoutMs: 5_000,
				maxStdoutBytes: 2_048,
			},
		});
		expect(getCronJob("cron-hn")).toMatchObject({
			ownerId: "alice",
			deliveryTarget: { kind: "home" },
			action: {
				kind: "agent-prompt",
				prompt: "check HN and post here",
				allowedSkills: ["summarize", "memory"],
				preprocess: {
					command: "node",
					args: ["scripts/hn-context.js"],
					cwd: "scripts",
					timeoutMs: 5_000,
					maxStdoutBytes: 2_048,
				},
			},
		});
	});

	it("persists curator scan actions", async () => {
		const { addCronJob, getCronJob } = await import("../../src/cron/store.js");
		const now = Date.parse("2026-02-21T10:00:00.000Z");

		const created = addCronJob(
			{
				id: "cron-curator",
				name: "curator",
				schedule: { kind: "every", everyMs: 21_600_000 },
				action: { kind: "curator-scan" },
			},
			now,
		);

		expect(created.action).toEqual({ kind: "curator-scan" });
		expect(getCronJob("cron-curator")?.action).toEqual({ kind: "curator-scan" });
	});

	it("persists a content-free household reminder wake-up and reschedules only typed retries", async () => {
		const { addCronJob, claimDueCronJobs, completeClaimedCronJob, getCronJob, setCronJobEnabled } =
			await import("../../src/cron/store.js");
		const { getDb } = await import("../../src/storage/db.js");
		const now = Date.parse("2026-02-21T10:00:00.000Z");
		const dueAt = now + 60_000;
		const retryAt = dueAt + 30_000;

		const created = addCronJob(
			{
				id: "household-reminder:reminder-1",
				name: "household reminder wake-up",
				schedule: { kind: "at", at: new Date(dueAt).toISOString() },
				action: { kind: "household-reminder", reminderId: "reminder-1", revision: 2 },
			},
			now,
		);
		expect(created.action).toEqual({
			kind: "household-reminder",
			reminderId: "reminder-1",
			revision: 2,
		});
		expect(created.deliveryTarget).toEqual({ kind: "origin" });
		expect(
			getDb()
				.prepare(
					`SELECT action_prompt, action_service_id, owner_id, delivery_chat_id,
					        action_reminder_id, action_reminder_revision
					 FROM cron_jobs WHERE id = ?`,
				)
				.get(created.id),
		).toEqual({
			action_prompt: null,
			action_service_id: null,
			owner_id: null,
			delivery_chat_id: null,
			action_reminder_id: "reminder-1",
			action_reminder_revision: 2,
		});

		const first = claimDueCronJobs(dueAt, 1)[0];
		completeClaimedCronJob({
			job: first,
			startedAtMs: dueAt,
			finishedAtMs: dueAt + 1,
			status: "error",
			message: "transient",
			retryAtMs: retryAt,
		});
		expect(getCronJob(created.id)).toMatchObject({ enabled: true, nextRunAtMs: retryAt });

		const second = claimDueCronJobs(retryAt, 1)[0];
		setCronJobEnabled(created.id, false, retryAt);
		completeClaimedCronJob({
			job: second,
			startedAtMs: retryAt,
			finishedAtMs: retryAt + 1,
			status: "error",
			message: "transient after cancellation",
			retryAtMs: retryAt + 30_000,
		});
		expect(getCronJob(created.id)).toMatchObject({ enabled: false, nextRunAtMs: null });
	});

	it("keeps one Jerusalem daily household metrics digest job and rolls it to the next wall-clock day", async () => {
		const { claimDueCronJobs, completeClaimedCronJob, getCronJob, syncHouseholdMetricsDigestCron } =
			await import("../../src/cron/store.js");
		const now = Date.parse("2026-07-18T05:00:00.000Z");

		const created = syncHouseholdMetricsDigestCron({ enabled: true, atHour: 8, nowMs: now });
		if (!created) throw new Error("enabled digest job was not created");
		expect(created).toMatchObject({
			id: "household-metrics-digest",
			enabled: true,
			action: { kind: "household-metrics-digest", atHour: 8 },
			schedule: { kind: "at", at: "2026-07-19T05:00:00.000Z" },
			nextRunAtMs: Date.parse("2026-07-19T05:00:00.000Z"),
		});

		const [claimed] = claimDueCronJobs(Date.parse("2026-07-19T05:00:00.000Z"));
		const claimedAtMs = claimed.nextRunAtMs;
		if (claimedAtMs === null) throw new Error("digest claim is missing its scheduled instant");
		completeClaimedCronJob({
			job: claimed,
			startedAtMs: claimedAtMs,
			finishedAtMs: claimedAtMs + 1_000,
			status: "success",
			message: "sent",
		});
		expect(getCronJob(created.id)).toMatchObject({
			enabled: true,
			schedule: { kind: "at", at: "2026-07-20T05:00:00.000Z" },
			nextRunAtMs: Date.parse("2026-07-20T05:00:00.000Z"),
		});

		expect(
			syncHouseholdMetricsDigestCron({
				enabled: false,
				atHour: 8,
				nowMs: now + 2_000,
			}),
		).toMatchObject({ enabled: false, nextRunAtMs: null });
	});

	it("claims and completes due jobs", async () => {
		const { addCronJob, claimDueCronJobs, completeClaimedCronJob, getCronJob } = await import(
			"../../src/cron/store.js"
		);
		const now = Date.parse("2026-02-21T10:00:00.000Z");

		addCronJob(
			{
				id: "job-1",
				name: "job",
				schedule: { kind: "every", everyMs: 60_000 },
				action: { kind: "private-heartbeat" },
			},
			now,
		);

		const claimed = claimDueCronJobs(now + 60_000, 10);
		expect(claimed).toHaveLength(1);
		expect(claimed[0].id).toBe("job-1");

		completeClaimedCronJob({
			job: claimed[0],
			startedAtMs: now + 60_000,
			finishedAtMs: now + 61_000,
			status: "success",
			message: "ok",
		});

		const updated = getCronJob("job-1");
		expect(updated?.running).toBe(false);
		expect(updated?.lastStatus).toBe("success");
		expect(updated?.nextRunAtMs).toBe(now + 121_000);
	});

	it("does not let an old in-flight reminder disable its replacement revision", async () => {
		const {
			claimDueCronJobs,
			completeClaimedCronJob,
			getCronJob,
			upsertHouseholdReminderCronWakeup,
		} = await import("../../src/cron/store.js");
		const now = Date.parse("2026-02-21T10:00:00.000Z");
		const firstDueAt = now + 60_000;
		const replacementDueAt = now + 3_600_000;
		upsertHouseholdReminderCronWakeup({
			reminderId: "reminder-1",
			revision: 1,
			resolvedAtMs: firstDueAt,
			nowMs: now,
		});
		const first = claimDueCronJobs(firstDueAt, 1)[0];
		upsertHouseholdReminderCronWakeup({
			reminderId: "reminder-1",
			revision: 2,
			resolvedAtMs: replacementDueAt,
			nowMs: firstDueAt + 1,
		});

		completeClaimedCronJob({
			job: first,
			startedAtMs: firstDueAt,
			finishedAtMs: firstDueAt + 2,
			status: "error",
			message: "old revision lost authorization",
		});

		expect(getCronJob(first.id)).toMatchObject({
			enabled: true,
			running: false,
			nextRunAtMs: replacementDueAt,
			action: { kind: "household-reminder", reminderId: "reminder-1", revision: 2 },
			lastRunAtMs: null,
			lastStatus: null,
		});
	});

	it("computes cron coverage for social and private jobs", async () => {
		const { addCronJob, getCronCoverage } = await import("../../src/cron/store.js");
		const now = Date.parse("2026-02-21T10:00:00.000Z");

		addCronJob(
			{
				name: "all social",
				schedule: { kind: "every", everyMs: 60_000 },
				action: { kind: "social-heartbeat" },
			},
			now,
		);
		addCronJob(
			{
				name: "private",
				schedule: { kind: "every", everyMs: 60_000 },
				action: { kind: "private-heartbeat" },
			},
			now,
		);

		const coverage = getCronCoverage();
		expect(coverage.allSocial).toBe(true);
		expect(coverage.hasPrivateHeartbeat).toBe(true);
	});
});
