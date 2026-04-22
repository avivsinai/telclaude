import { beforeEach, describe, expect, it, vi } from "vitest";

const createSocialClientMock = vi.hoisted(() => vi.fn());
const handleSocialHeartbeatMock = vi.hoisted(() => vi.fn());
const handlePrivateHeartbeatMock = vi.hoisted(() => vi.fn());
const executeScheduledAgentPromptActionMock = vi.hoisted(() => vi.fn());

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

import { executeCronAction } from "../../src/cron/actions.js";

describe("executeCronAction social heartbeat", () => {
	beforeEach(() => {
		createSocialClientMock.mockReset();
		handleSocialHeartbeatMock.mockReset();
		handlePrivateHeartbeatMock.mockReset();
		executeScheduledAgentPromptActionMock.mockReset();
	});

	it("skips services with automatic heartbeat disabled", async () => {
		const result = await executeCronAction(
			{ id: "job-1", action: { kind: "social-heartbeat", serviceId: "xtwitter" } } as any,
			{
				socialServices: [
					{ id: "xtwitter", type: "xtwitter", enabled: true, heartbeatEnabled: false },
				],
			} as any,
		);

		expect(result.ok).toBe(false);
		expect(result.message).toContain("automatic heartbeat");
		expect(createSocialClientMock).not.toHaveBeenCalled();
		expect(handleSocialHeartbeatMock).not.toHaveBeenCalled();
	});
});
