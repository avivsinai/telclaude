import { describe, expect, it } from "vitest";

import {
	getAutomaticHeartbeatSocialServices,
	getEnabledSocialServices,
	isAutomaticHeartbeatEnabled,
} from "../../src/social/service-config.js";

describe("social service config selectors", () => {
	it("keeps manual availability separate from automatic heartbeat eligibility", () => {
		const cfg = {
			socialServices: [
				{ id: "xtwitter", enabled: true, heartbeatEnabled: false },
				{ id: "moltbook", enabled: true, heartbeatEnabled: true },
				{ id: "disabled", enabled: false, heartbeatEnabled: true },
			],
		} as any;

		expect(getEnabledSocialServices(cfg).map((service) => service.id)).toEqual([
			"xtwitter",
			"moltbook",
		]);
		expect(getAutomaticHeartbeatSocialServices(cfg).map((service) => service.id)).toEqual([
			"moltbook",
		]);
	});

	it("treats omitted heartbeatEnabled as enabled by default", () => {
		expect(isAutomaticHeartbeatEnabled({ id: "xtwitter", enabled: true } as any)).toBe(true);
	});
});
