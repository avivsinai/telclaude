import { describe, expect, it } from "vitest";
import { resolveMentionGating, resolveMentionGatingWithBypass } from "../../src/telegram/mention-gating.js";

describe("resolveMentionGating", () => {
	it("combines explicit, implicit, and bypass mentions", () => {
		const res = resolveMentionGating({
			requireMention: true,
			canDetectMention: true,
			wasMentioned: false,
			implicitMention: true,
			shouldBypassMention: false,
		});
		expect(res.effectiveWasMentioned).toBe(true);
		expect(res.shouldSkip).toBe(false);
	});

	it("skips when mention is required and none detected", () => {
		const res = resolveMentionGating({
			requireMention: true,
			canDetectMention: true,
			wasMentioned: false,
			implicitMention: false,
			shouldBypassMention: false,
		});
		expect(res.effectiveWasMentioned).toBe(false);
		expect(res.shouldSkip).toBe(true);
	});
});

describe("resolveMentionGatingWithBypass", () => {
	it("enables bypass for authorized control commands", () => {
		const res = resolveMentionGatingWithBypass({
			isGroup: true,
			requireMention: true,
			canDetectMention: true,
			wasMentioned: false,
			hasAnyMention: false,
			allowTextCommands: true,
			hasControlCommand: true,
			commandAuthorized: true,
		});
		expect(res.shouldBypassMention).toBe(true);
		expect(res.shouldSkip).toBe(false);
	});

	it("does not bypass when command is not authorized", () => {
		const res = resolveMentionGatingWithBypass({
			isGroup: true,
			requireMention: true,
			canDetectMention: true,
			wasMentioned: false,
			hasAnyMention: false,
			allowTextCommands: true,
			hasControlCommand: true,
			commandAuthorized: false,
		});
		expect(res.shouldBypassMention).toBe(false);
		expect(res.shouldSkip).toBe(true);
	});
});
