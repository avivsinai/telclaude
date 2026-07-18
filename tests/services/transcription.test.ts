import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

const relayTranscribe = vi.hoisted(() => vi.fn());
const getOpenAIClient = vi.hoisted(() => vi.fn());
const isOpenAIConfigured = vi.hoisted(() => vi.fn());
const transcriptionLogger = vi.hoisted(() => ({
	info: vi.fn(),
	warn: vi.fn(),
	error: vi.fn(),
	debug: vi.fn(),
}));

vi.mock("../../src/relay/capabilities-client.js", () => ({
	relayTranscribe: (...args: unknown[]) => relayTranscribe(...args),
}));

vi.mock("../../src/logging.js", () => ({
	getChildLogger: () => transcriptionLogger,
}));

vi.mock("../../src/services/openai-client.js", () => ({
	getOpenAIClient,
	isOpenAIConfigured,
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
	getOpenAIClient.mockReset();
	isOpenAIConfigured.mockReset();
	for (const method of Object.values(transcriptionLogger)) method.mockReset();
	delete process.env.TELCLAUDE_CAPABILITIES_URL;
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
		expect(result.confidenceSource).toBe("unavailable");

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

	it("surfaces OpenAI verbose segment evidence with the pinned production source id", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-transcription-"));
		const audioPath = path.join(tempDir, "voice.wav");
		fs.writeFileSync(audioPath, "wav");
		isOpenAIConfigured.mockResolvedValue(true);
		getOpenAIClient.mockResolvedValue({
			audio: {
				transcriptions: {
					create: vi.fn().mockResolvedValue({
						text: "שלום",
						language: "he",
						duration: 2.5,
						segments: [
							{ start: 0, end: 1, avg_logprob: -0.1, no_speech_prob: 0.02 },
							{ start: 1, end: 2.5, avg_logprob: -0.2, no_speech_prob: 0.03 },
						],
					}),
				},
			},
		});

		try {
			await expect(transcribeAudio(audioPath, { provider: "openai" })).resolves.toMatchObject({
				text: "שלום",
				language: "he",
				durationSeconds: 2.5,
				confidenceSource: "openai_whisper_verbose_segments_v1",
				segments: [
					{ durationSeconds: 1, avgLogprob: -0.1, noSpeechProbability: 0.02 },
					{ durationSeconds: 1.5, avgLogprob: -0.2, noSpeechProbability: 0.03 },
				],
			});
		} finally {
			fs.rmSync(tempDir, { recursive: true, force: true });
		}
	});

	it("fails the OpenAI production contract when verbose segment evidence is unavailable", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-transcription-"));
		const audioPath = path.join(tempDir, "voice.wav");
		fs.writeFileSync(audioPath, "wav");
		isOpenAIConfigured.mockResolvedValue(true);
		getOpenAIClient.mockResolvedValue({
			audio: {
				transcriptions: {
					create: vi.fn().mockResolvedValue({
						text: "שלום",
						language: "he",
						duration: 1,
					}),
				},
			},
		});

		try {
			await expect(transcribeAudio(audioPath, { provider: "openai" })).rejects.toThrow(
				"OpenAI verbose transcription response omitted valid segment evidence",
			);
		} finally {
			fs.rmSync(tempDir, { recursive: true, force: true });
		}
	});

	it("marks command evidence unavailable without logging paths, arguments, or stderr", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-transcription-"));
		const audioPath = path.join(tempDir, "private-voice.wav");
		fs.writeFileSync(audioPath, "wav");

		try {
			await expect(
				transcribeAudio(audioPath, {
					provider: "command",
					command: [process.execPath, "-e", "process.stdout.write('hello')", "{{file}}"],
				}),
			).resolves.toMatchObject({ text: "hello", confidenceSource: "unavailable" });
			const logged = JSON.stringify(
				Object.values(transcriptionLogger).flatMap((method) => method.mock.calls),
			);
			expect(logged).not.toContain(audioPath);
			expect(logged).not.toContain(process.execPath);
			expect(logged).not.toContain("process.stdout.write");
		} finally {
			fs.rmSync(tempDir, { recursive: true, force: true });
		}
	});
});
