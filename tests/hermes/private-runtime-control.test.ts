import { describe, expect, it } from "vitest";
import { readHermesPrivateRuntimeEffectiveState } from "../../src/hermes/private-runtime-control.js";

describe("Hermes private-runtime durable control", () => {
	it("reports the fixed Hermes-only runtime state", () => {
		expect(readHermesPrivateRuntimeEffectiveState()).toEqual({
			ok: true,
			effectiveMode: "hermes",
			effectiveValue: "1",
			controlMode: "hermes",
			controlSource: "hermes-only",
		});
	});

	it("does not expose mutable control fields", () => {
		const state = readHermesPrivateRuntimeEffectiveState() as Record<string, unknown>;

		expect(Object.keys(state).sort()).toEqual([
			"controlMode",
			"controlSource",
			"effectiveMode",
			"effectiveValue",
			"ok",
		]);
	});
});
