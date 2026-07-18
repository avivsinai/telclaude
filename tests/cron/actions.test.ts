import { beforeEach, describe, expect, it, vi } from "vitest";

const createSocialClientMock = vi.hoisted(() => vi.fn());
const handleSocialHeartbeatMock = vi.hoisted(() => vi.fn());
const handlePrivateHeartbeatMock = vi.hoisted(() => vi.fn());
const executeScheduledAgentPromptActionMock = vi.hoisted(() => vi.fn());
const runCuratorScanMock = vi.hoisted(() => vi.fn());

vi.mock("../../src/social/index.js", () => ({
	createSocialClient: createSocialClientMock,
	handleSocialHeartbeat: handleSocialHeartbeatMock,
}));

vi.mock("../../src/telegram/heartbeat.js", () => ({
	handlePrivateHeartbeat: handlePrivateHeartbeatMock,
}));

vi.mock("../../src/cron/agent-action.js", () => ({
	executeScheduledAgentPromptAction: executeScheduledAgentPromptActionMock,
}));

vi.mock("../../src/curator/actions.js", () => ({
	runCuratorScan: runCuratorScanMock,
}));

import { executeCronAction } from "../../src/cron/actions.js";

type CronActionJob = Parameters<typeof executeCronAction>[0];
type CronActionConfig = Parameters<typeof executeCronAction>[1];

describe("executeCronAction social heartbeat", () => {
	beforeEach(() => {
		createSocialClientMock.mockReset();
		handleSocialHeartbeatMock.mockReset();
		handlePrivateHeartbeatMock.mockReset();
		executeScheduledAgentPromptActionMock.mockReset();
		runCuratorScanMock.mockReset();
	});

	it("skips services with automatic heartbeat disabled", async () => {
		const result = await executeCronAction(
			{ id: "job-1", action: { kind: "social-heartbeat", serviceId: "xtwitter" } } as CronActionJob,
			{
				socialServices: [
					{ id: "xtwitter", type: "xtwitter", enabled: true, heartbeatEnabled: false },
				],
			} as CronActionConfig,
		);

		expect(result.ok).toBe(false);
		expect(result.message).toContain("automatic heartbeat");
		expect(createSocialClientMock).not.toHaveBeenCalled();
		expect(handleSocialHeartbeatMock).not.toHaveBeenCalled();
	});

	it("runs the deterministic curator scan action without an agent query", async () => {
		runCuratorScanMock.mockReturnValue({
			createdOrUpdated: 2,
			openItems: 3,
			byKind: { cron_hardening: 3 },
		});

		const result = await executeCronAction(
			{ id: "job-curator", action: { kind: "curator-scan" } } as CronActionJob,
			{} as CronActionConfig,
		);

		expect(result).toEqual({
			ok: true,
			message: "curator scan updated 2 item(s); 3 open",
		});
		expect(runCuratorScanMock).toHaveBeenCalledWith({ producerKind: "system" });
		expect(executeScheduledAgentPromptActionMock).not.toHaveBeenCalled();
	});

	it("routes household reminder wake-ups only to the injected deterministic executor", async () => {
		const executeHouseholdReminder = vi.fn(async () => ({
			ok: false,
			message: "retry",
			retryAtMs: 123_000,
		}));
		const job = {
			id: "household-reminder:reminder-1",
			action: { kind: "household-reminder", reminderId: "reminder-1", revision: 2 },
		} as CronActionJob;

		await expect(
			executeCronAction(job, {} as CronActionConfig, new AbortController().signal, {
				executeHouseholdReminder,
			}),
		).resolves.toEqual({ ok: false, message: "retry", retryAtMs: 123_000 });
		expect(executeHouseholdReminder).toHaveBeenCalledWith(
			{ reminderId: "reminder-1", revision: 2 },
			expect.any(AbortSignal),
		);
		expect(executeScheduledAgentPromptActionMock).not.toHaveBeenCalled();
		expect(handlePrivateHeartbeatMock).not.toHaveBeenCalled();
	});
});
