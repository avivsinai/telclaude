import { describe, expect, it } from "vitest";

import { resolveTelegramIntent } from "../../src/telegram/intent-router.js";

describe("telegram intent router", () => {
	describe("model picker intents", () => {
		it("routes 'switch to sonnet' to the anthropic provider + sonnet model", () => {
			const intent = resolveTelegramIntent("switch to sonnet");
			expect(intent).toEqual(
				expect.objectContaining({
					kind: "open-model-picker",
					providerHint: "anthropic",
					modelHint: expect.stringContaining("sonnet"),
				}),
			);
		});

		it("routes 'switch to opus' to the anthropic opus model", () => {
			const intent = resolveTelegramIntent("switch to opus");
			expect(intent).toEqual(
				expect.objectContaining({
					kind: "open-model-picker",
					providerHint: "anthropic",
					modelHint: expect.stringContaining("opus"),
				}),
			);
		});

		it("routes 'use haiku' to the anthropic haiku model", () => {
			const intent = resolveTelegramIntent("use haiku");
			expect(intent).toEqual(
				expect.objectContaining({
					kind: "open-model-picker",
					providerHint: "anthropic",
					modelHint: expect.stringContaining("haiku"),
				}),
			);
		});

		it("routes 'use gpt' to the openai provider", () => {
			const intent = resolveTelegramIntent("use gpt");
			expect(intent).toEqual(
				expect.objectContaining({
					kind: "open-model-picker",
					providerHint: "openai",
				}),
			);
		});

		it("opens the picker even when the model hint is unknown", () => {
			const intent = resolveTelegramIntent("switch model please");
			expect(intent?.kind).toBe("open-model-picker");
			expect(intent).toEqual({ kind: "open-model-picker" });
		});

		it("ignores bare model names without switching intent", () => {
			// Bare "sonnet" shouldn't open the picker — the user must express
			// switching intent ("switch to sonnet").
			expect(resolveTelegramIntent("sonnet")).toBeNull();
			expect(resolveTelegramIntent("what is sonnet?")).toBeNull();
		});

		it("tolerates filler words like 'the' and 'please'", () => {
			const intent = resolveTelegramIntent("please switch to sonnet");
			expect(intent?.kind).toBe("open-model-picker");
			expect(intent).toEqual(
				expect.objectContaining({
					providerHint: "anthropic",
					modelHint: expect.stringContaining("sonnet"),
				}),
			);
		});

		it("handles casing variations", () => {
			const intent = resolveTelegramIntent("Switch To Sonnet");
			expect(intent?.kind).toBe("open-model-picker");
			expect(intent).toEqual(
				expect.objectContaining({
					providerHint: "anthropic",
					modelHint: expect.stringContaining("sonnet"),
				}),
			);
		});
	});

	describe("provider list intents", () => {
		it("routes 'list providers' to provider list", () => {
			expect(resolveTelegramIntent("list providers")).toEqual({
				kind: "open-provider-list",
			});
		});

		it("routes 'provider health' to provider list", () => {
			expect(resolveTelegramIntent("provider health")).toEqual({
				kind: "open-provider-list",
			});
		});
	});

	describe("skill picker intents", () => {
		it("routes 'show skills' to skill picker", () => {
			expect(resolveTelegramIntent("show skills")).toEqual({
				kind: "open-skill-picker",
			});
		});

		it("routes 'promote skill' to skill picker", () => {
			expect(resolveTelegramIntent("promote skill")).toEqual({
				kind: "open-skill-picker",
			});
		});
	});

	describe("no-match cases", () => {
		it("returns null for unrelated messages", () => {
			expect(resolveTelegramIntent("hi there")).toBeNull();
			expect(resolveTelegramIntent("tell me about the weather")).toBeNull();
			expect(resolveTelegramIntent("")).toBeNull();
		});
	});
});
