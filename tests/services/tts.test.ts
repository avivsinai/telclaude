import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

const relayTextToSpeech = vi.hoisted(() => vi.fn());

vi.mock("../../src/relay/capabilities-client.js", () => ({
	relayTextToSpeech: (...args: unknown[]) => relayTextToSpeech(...args),
}));

vi.mock("../../src/logging.js", () => ({
	getChildLogger: () => ({
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		debug: vi.fn(),
	}),
}));

vi.mock("../../src/services/openai-client.js", () => ({
	getOpenAIClient: vi.fn(),
	isOpenAIConfigured: vi.fn(),
	isOpenAIConfiguredSync: vi.fn(),
}));

vi.mock("../../src/config/config.js", () => ({
	loadConfig: () => ({}),
}));

let textToSpeech: typeof import("../../src/services/tts.js").textToSpeech;

beforeAll(async () => {
	({ textToSpeech } = await import("../../src/services/tts.js"));
});

afterEach(() => {
	relayTextToSpeech.mockReset();
});

describe("tts relay", () => {
	it("forwards userId to relay when capabilities are enabled", async () => {
		const prevCapabilitiesUrl = process.env.TELCLAUDE_CAPABILITIES_URL;
		process.env.TELCLAUDE_CAPABILITIES_URL = "http://relay";

		relayTextToSpeech.mockResolvedValueOnce({
			path: "/tmp/relay-tts.mp3",
			bytes: 2048,
			format: "mp3",
			voice: "alloy",
			speed: 1.5,
		});

		const result = await textToSpeech("hello relay", {
			voice: "alloy",
			speed: 1.5,
			voiceMessage: false,
			userId: "user-tts",
		});

		expect(relayTextToSpeech).toHaveBeenCalledWith({
			text: "hello relay",
			voice: "alloy",
			speed: 1.5,
			voiceMessage: false,
			userId: "user-tts",
		});
		expect(result.path).toBe("/tmp/relay-tts.mp3");

		if (prevCapabilitiesUrl === undefined) {
			delete process.env.TELCLAUDE_CAPABILITIES_URL;
		} else {
			process.env.TELCLAUDE_CAPABILITIES_URL = prevCapabilitiesUrl;
		}
	});
});
