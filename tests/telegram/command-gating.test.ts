import { describe, expect, it } from "vitest";
import {
	resolveCommandAuthorizedFromAuthorizers,
	resolveControlCommandGate,
} from "../../src/telegram/command-gating.js";

describe("resolveCommandAuthorizedFromAuthorizers", () => {
	it("denies when access groups are enabled and no configured authorizer allows", () => {
		expect(
			resolveCommandAuthorizedFromAuthorizers({
				useAccessGroups: true,
				authorizers: [{ configured: false, allowed: true }],
			}),
		).toBe(false);
	});

	it("allows when access groups are disabled by default", () => {
		expect(
			resolveCommandAuthorizedFromAuthorizers({
				useAccessGroups: false,
				authorizers: [{ configured: true, allowed: false }],
			}),
		).toBe(true);
	});

	it("honors modeWhenAccessGroupsOff=configured", () => {
		expect(
			resolveCommandAuthorizedFromAuthorizers({
				useAccessGroups: false,
				authorizers: [{ configured: true, allowed: false }],
				modeWhenAccessGroupsOff: "configured",
			}),
		).toBe(false);
	});
});

describe("resolveControlCommandGate", () => {
	it("blocks control commands when unauthorized", () => {
		const gate = resolveControlCommandGate({
			useAccessGroups: true,
			authorizers: [{ configured: true, allowed: false }],
			allowTextCommands: true,
			hasControlCommand: true,
		});
		expect(gate.commandAuthorized).toBe(false);
		expect(gate.shouldBlock).toBe(true);
	});

	it("does not block when control command bypass is disabled", () => {
		const gate = resolveControlCommandGate({
			useAccessGroups: true,
			authorizers: [{ configured: true, allowed: false }],
			allowTextCommands: false,
			hasControlCommand: true,
		});
		expect(gate.shouldBlock).toBe(false);
	});
});
