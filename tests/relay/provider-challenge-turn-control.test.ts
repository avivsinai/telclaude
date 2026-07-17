import { describe, expect, it } from "vitest";
import { createProviderChallengeTurnControl } from "../../src/relay/provider-challenge-turn-control.js";

describe("provider challenge turn control", () => {
	it("aborts the active stream and keeps the MCP turn blocked until expiry", () => {
		let nowMs = 100_000;
		const control = createProviderChallengeTurnControl({ nowMs: () => nowMs });
		const controller = new AbortController();
		const turnRef = `turn_${"a".repeat(32)}`;
		const unregister = control.register(turnRef, controller);

		control.block(turnRef, 101_000);

		expect(controller.signal.aborted).toBe(true);
		expect(control.isBlocked(turnRef)).toBe(true);
		unregister();
		nowMs = 101_000;
		expect(control.isBlocked(turnRef)).toBe(false);
		expect(control.cleanup()).toBe(1);
	});

	it("immediately aborts a stream registered after the turn was blocked", () => {
		const control = createProviderChallengeTurnControl({ nowMs: () => 100_000 });
		const turnRef = `turn_${"b".repeat(32)}`;
		control.block(turnRef, 101_000);
		const controller = new AbortController();

		control.register(turnRef, controller);

		expect(controller.signal.aborted).toBe(true);
	});

	it("isolates independent parent turns", () => {
		const control = createProviderChallengeTurnControl({ nowMs: () => 100_000 });
		const parentA = new AbortController();
		const parentB = new AbortController();
		const turnA = `turn_${"a".repeat(32)}`;
		const turnB = `turn_${"b".repeat(32)}`;
		control.register(turnA, parentA);
		control.register(turnB, parentB);

		control.block(turnA, 101_000);

		expect(parentA.signal.aborted).toBe(true);
		expect(parentB.signal.aborted).toBe(false);
		expect(control.isBlocked(turnB)).toBe(false);
	});
});
