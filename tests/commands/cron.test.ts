import { Command } from "commander";
import { describe, expect, it } from "vitest";
import {
	assertCronJobMayBeQueuedFromCli,
	formatCronOverview,
	registerCronCommand,
} from "../../src/commands/cron.js";

describe("cron command formatting", () => {
	it("includes delivery targets in the overview output", () => {
		const text = formatCronOverview({
			enabled: true,
			pollIntervalSeconds: 15,
			timeoutSeconds: 900,
			summary: {
				totalJobs: 1,
				enabledJobs: 1,
				runningJobs: 0,
				nextRunAtMs: null,
			},
			coverage: {
				allSocial: false,
				socialServiceIds: [],
				hasPrivateHeartbeat: false,
			},
			jobs: [
				{
					id: "cron-1",
					name: "weekday-hn",
					enabled: true,
					running: false,
					ownerId: "admin",
					deliveryTarget: { kind: "home" },
					schedule: { kind: "cron", expr: "0 9 * * 1-5" },
					action: {
						kind: "agent-prompt",
						prompt: "check HN and post here",
						allowedSkills: ["summarize"],
						preprocess: { command: "node", args: ["routine.js"] },
					},
					nextRunAtMs: null,
					lastRunAtMs: null,
					lastStatus: null,
					lastError: null,
					createdAtMs: 0,
					updatedAtMs: 0,
				},
			],
		});

		expect(text).toContain("delivery=home");
		expect(text).toContain("agent prompt");
		expect(text).toContain("skills=1");
		expect(text).toContain("preprocess=yes");
	});

	it("formats curator scan jobs", () => {
		const text = formatCronOverview({
			enabled: true,
			pollIntervalSeconds: 15,
			timeoutSeconds: 900,
			summary: {
				totalJobs: 1,
				enabledJobs: 1,
				runningJobs: 0,
				nextRunAtMs: null,
			},
			coverage: {
				allSocial: false,
				socialServiceIds: [],
				hasPrivateHeartbeat: false,
			},
			jobs: [
				{
					id: "cron-curator",
					name: "curator",
					enabled: true,
					running: false,
					ownerId: null,
					deliveryTarget: { kind: "origin" },
					schedule: { kind: "every", everyMs: 21_600_000 },
					action: { kind: "curator-scan" },
					nextRunAtMs: null,
					lastRunAtMs: null,
					lastStatus: null,
					lastError: null,
					createdAtMs: 0,
					updatedAtMs: 0,
				},
			],
		});

		expect(text).toContain("curator scan");
	});

	it("formats internal household wake-ups without content and rejects CLI creation", async () => {
		const text = formatCronOverview({
			enabled: true,
			pollIntervalSeconds: 15,
			timeoutSeconds: 900,
			summary: { totalJobs: 1, enabledJobs: 1, runningJobs: 0, nextRunAtMs: null },
			coverage: { allSocial: false, socialServiceIds: [], hasPrivateHeartbeat: false },
			jobs: [
				{
					id: "household-reminder:reminder-opaque",
					name: "household reminder wake-up",
					enabled: true,
					running: false,
					ownerId: null,
					deliveryTarget: { kind: "origin" },
					schedule: { kind: "at", at: "2026-08-01T06:00:00.000Z" },
					action: {
						kind: "household-reminder",
						reminderId: "reminder-opaque",
						revision: 2,
					},
					nextRunAtMs: null,
					lastRunAtMs: null,
					lastStatus: null,
					lastError: null,
					createdAtMs: 0,
					updatedAtMs: 0,
				},
			],
		});
		expect(text).toContain("household reminder (reminder-opaque, revision=2)");
		expect(text).not.toContain("תזכורת:");
		expect(() =>
			assertCronJobMayBeQueuedFromCli({
				id: "household-reminder:reminder-opaque",
				name: "household reminder wake-up",
				enabled: false,
				running: false,
				ownerId: null,
				deliveryTarget: { kind: "origin" },
				schedule: { kind: "at", at: "2026-08-01T06:00:00.000Z" },
				action: { kind: "household-reminder", reminderId: "reminder-opaque", revision: 2 },
				nextRunAtMs: null,
				lastRunAtMs: null,
				lastStatus: null,
				lastError: null,
				createdAtMs: 0,
				updatedAtMs: 0,
			}),
		).toThrow(/cannot be queued from the CLI/);

		const program = new Command().exitOverride();
		program.configureOutput({ writeErr: () => undefined });
		registerCronCommand(program);
		await expect(
			program.parseAsync([
				"node",
				"telclaude",
				"cron",
				"add",
				"--at",
				"2026-08-01T06:00:00.000Z",
				"--household-reminder",
				"reminder-opaque",
			]),
		).rejects.toMatchObject({ code: "commander.unknownOption" });

		await expect(
			program.parseAsync([
				"node",
				"telclaude",
				"cron",
				"add",
				"--at",
				"2026-08-01T06:00:00.000Z",
				"--household-metrics-digest",
			]),
		).rejects.toMatchObject({ code: "commander.unknownOption" });
	});
});
