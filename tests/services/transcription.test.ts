import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

const relayTranscribe = vi.hoisted(() => vi.fn());

vi.mock("../../src/relay/capabilities-client.js", () => ({
	relayTranscribe: (...args: unknown[]) => relayTranscribe(...args),
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

let transcribeAudio: typeof import("../../src/services/transcription.js").transcribeAudio;

beforeAll(async () => {
	({ transcribeAudio } = await import("../../src/services/transcription.js"));
});

afterEach(() => {
	relayTranscribe.mockReset();
	delete process.env.TELCLAUDE_REQUEST_USER_ID;
});

describe("transcription relay", () => {
	it("forwards userId to relay when capabilities are enabled", async () => {
		const prevCapabilitiesUrl = process.env.TELCLAUDE_CAPABILITIES_URL;
		process.env.TELCLAUDE_CAPABILITIES_URL = "http://relay";

		relayTranscribe.mockResolvedValueOnce({
			text: "hello",
			language: "en",
			durationSeconds: 1,
		});

		const result = await transcribeAudio("/tmp/audio.mp3", { userId: "user-stt" });

		expect(relayTranscribe).toHaveBeenCalledWith({
			path: "/tmp/audio.mp3",
			language: undefined,
			model: undefined,
			userId: "user-stt",
		});
		expect(result.text).toBe("hello");

		if (prevCapabilitiesUrl === undefined) {
			delete process.env.TELCLAUDE_CAPABILITIES_URL;
		} else {
			process.env.TELCLAUDE_CAPABILITIES_URL = prevCapabilitiesUrl;
		}
	});

	it("falls back to TELCLAUDE_REQUEST_USER_ID when userId is missing", async () => {
		const prevCapabilitiesUrl = process.env.TELCLAUDE_CAPABILITIES_URL;
		process.env.TELCLAUDE_CAPABILITIES_URL = "http://relay";
		process.env.TELCLAUDE_REQUEST_USER_ID = "env-user";

		relayTranscribe.mockResolvedValueOnce({
			text: "env",
			language: "en",
			durationSeconds: 2,
		});

		await transcribeAudio("/tmp/audio.mp3");

		expect(relayTranscribe).toHaveBeenCalledWith({
			path: "/tmp/audio.mp3",
			language: undefined,
			model: undefined,
			userId: "env-user",
		});

		if (prevCapabilitiesUrl === undefined) {
			delete process.env.TELCLAUDE_CAPABILITIES_URL;
		} else {
			process.env.TELCLAUDE_CAPABILITIES_URL = prevCapabilitiesUrl;
		}
	});
});
