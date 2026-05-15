import { describe, expect, it } from "vitest";
import { formatCronOverview } from "../../src/commands/cron.js";

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
});
