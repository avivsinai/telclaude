import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

let resetDatabase: typeof import("../../src/storage/db.js").resetDatabase;
let clearChatModelPreference: typeof import("../../src/config/model-preferences.js").clearChatModelPreference;
let setChatModelPreference: typeof import("../../src/config/model-preferences.js").setChatModelPreference;
let resolveModelRoute: typeof import("../../src/config/model-routing.js").resolveModelRoute;
let assertExecutableModelId: typeof import("../../src/config/model-routing.js").assertExecutableModelId;

describe("model routing", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-model-routing-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;

		({ resetDatabase } = await import("../../src/storage/db.js"));
		resetDatabase();
		({ clearChatModelPreference, setChatModelPreference } = await import(
			"../../src/config/model-preferences.js"
		));
		({ assertExecutableModelId, resolveModelRoute } = await import(
			"../../src/config/model-routing.js"
		));
	});

	afterEach(() => {
		resetDatabase();
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) {
			delete process.env.TELCLAUDE_DATA_DIR;
		} else {
			process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
		}
	});

	it("uses the SDK default with no preference", () => {
		clearChatModelPreference(123);

		expect(resolveModelRoute(123)).toEqual({
			effectiveProviderId: "anthropic",
			fallbackState: "default",
			detail: "SDK default",
		});
	});

	it("passes executable Anthropic preferences through", () => {
		setChatModelPreference({
			chatId: 123,
			providerId: "anthropic",
			modelId: "claude-sonnet-4-5-20250929",
		});

		expect(resolveModelRoute(123)).toEqual(
			expect.objectContaining({
				effectiveProviderId: "anthropic",
				effectiveModel: "claude-sonnet-4-5-20250929",
				fallbackState: "override",
			}),
		);
	});

	it("falls back to SDK default for catalog-only providers", () => {
		setChatModelPreference({
			chatId: 123,
			providerId: "openai",
			modelId: "gpt-5",
		});

		const route = resolveModelRoute(123);
		expect(route.effectiveModel).toBeUndefined();
		expect(route).toEqual(
			expect.objectContaining({
				effectiveProviderId: "anthropic",
				fallbackState: "fallback",
				requestedProviderId: "openai",
				requestedModelId: "gpt-5",
			}),
		);
	});

	it("uses profile default model when there is no chat preference", () => {
		const route = resolveModelRoute(123, {
			profile: {
				id: "engineer",
				label: "Engineer",
				implicit: false,
				defaultModel: {
					providerId: "anthropic",
					modelId: "claude-haiku-4-5-20251001",
				},
			},
		});

		expect(route).toEqual(
			expect.objectContaining({
				effectiveModel: "claude-haiku-4-5-20251001",
				fallbackState: "profile",
				profileId: "engineer",
			}),
		);
	});

	it("lets executable chat preferences override profile defaults", () => {
		setChatModelPreference({
			chatId: 123,
			providerId: "anthropic",
			modelId: "claude-opus-4-5-20250929",
		});

		const route = resolveModelRoute(123, {
			profile: {
				id: "engineer",
				label: "Engineer",
				implicit: false,
				defaultModel: {
					providerId: "anthropic",
					modelId: "claude-haiku-4-5-20251001",
				},
			},
		});

		expect(route).toEqual(
			expect.objectContaining({
				effectiveModel: "claude-opus-4-5-20250929",
				fallbackState: "override",
			}),
		);
	});

	it("falls through stale chat preferences to a valid profile default", () => {
		setChatModelPreference({
			chatId: 123,
			providerId: "openai",
			modelId: "gpt-5",
		});

		const route = resolveModelRoute(123, {
			profile: {
				id: "engineer",
				label: "Engineer",
				implicit: false,
				defaultModel: {
					providerId: "anthropic",
					modelId: "claude-sonnet-4-5-20250929",
				},
			},
		});

		expect(route.effectiveModel).toBe("claude-sonnet-4-5-20250929");
		expect(route.fallbackState).toBe("fallback");
		expect(route.detail).toContain("ignored preference openai:gpt-5");
		expect(route.detail).toContain("profile default anthropic:claude-sonnet-4-5-20250929");
	});

	it("degrades to SDK default when profile default is not executable", () => {
		const route = resolveModelRoute(123, {
			profile: {
				id: "engineer",
				label: "Engineer",
				implicit: false,
				defaultModel: {
					providerId: "openai",
					modelId: "gpt-5",
				},
			},
		});

		expect(route.effectiveModel).toBeUndefined();
		expect(route.fallbackState).toBe("fallback");
		expect(route.detail).toContain("ignored profile openai:gpt-5");
	});

	it("rejects non-executable model IDs", () => {
		expect(assertExecutableModelId("claude-haiku-4-5-20251001")).toBe("claude-haiku-4-5-20251001");
		expect(() => assertExecutableModelId("gpt-5")).toThrow(/not executable/);
	});
});
