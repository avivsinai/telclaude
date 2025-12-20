import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

const imagesGenerate = vi.hoisted(() => vi.fn());
const loadConfigMock = vi.hoisted(() => vi.fn());

vi.mock("../../src/services/openai-client.js", () => ({
	getOpenAIClient: () =>
		({
			images: {
				generate: (...args: unknown[]) => imagesGenerate(...args),
			},
		}) as any,
	isOpenAIConfigured: () => true,
}));

vi.mock("../../src/config/config.js", () => ({
	loadConfig: () => loadConfigMock(),
}));

vi.mock("../../src/logging.js", () => ({
	getChildLogger: () => ({
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		debug: vi.fn(),
	}),
}));

let workspaceDir: string;
let prevWorkspaceEnv: string | undefined;

let generateImage: typeof import("../../src/services/image-generation.js").generateImage;

beforeAll(async () => {
	workspaceDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-img-"));
	prevWorkspaceEnv = process.env.TELCLAUDE_WORKSPACE;
	process.env.TELCLAUDE_WORKSPACE = workspaceDir;

	({ generateImage } = await import("../../src/services/image-generation.js"));
});

afterAll(() => {
	if (prevWorkspaceEnv === undefined) {
		delete process.env.TELCLAUDE_WORKSPACE;
	} else {
		process.env.TELCLAUDE_WORKSPACE = prevWorkspaceEnv;
	}

	if (workspaceDir && fs.existsSync(workspaceDir)) {
		fs.rmSync(workspaceDir, { recursive: true, force: true });
	}
});

const oneByOnePng = Buffer.from(
	// Minimal 1x1 transparent PNG
	"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMBAAZ9pW0AAAAASUVORK5CYII=",
	"base64",
);

describe("image-generation", () => {
	it("uses base64 output for GPT Image 1.5", async () => {
		let capturedRequest: any;

		loadConfigMock.mockReturnValueOnce({
			imageGeneration: {
				provider: "gpt-image",
				model: "gpt-image-1.5",
				size: "1024x1024",
				quality: "medium",
				maxPerHourPerUser: 10,
				maxPerDayPerUser: 50,
			},
		});

		imagesGenerate.mockImplementationOnce(async (req: unknown) => {
			capturedRequest = req;
			return {
				data: [{ b64_json: oneByOnePng.toString("base64") }],
			};
		});

		const result = await generateImage("A tiny pixel art cat");

		expect(capturedRequest.model).toBe("gpt-image-1.5");
		expect(capturedRequest.output_format).toBe("png"); // GPT image models use output_format
		expect(capturedRequest.quality).toBe("medium");
		expect(fs.existsSync(result.path)).toBe(true);

		const saved = fs.readFileSync(result.path);
		expect(saved.subarray(0, 8).toString("hex")).toBe("89504e470d0a1a0a"); // PNG magic
	});

	it("validates supported sizes", async () => {
		loadConfigMock.mockReturnValueOnce({
			imageGeneration: {
				provider: "gpt-image",
				model: "gpt-image-1.5",
				size: "1792x1024", // Invalid for GPT Image
				quality: "medium",
				maxPerHourPerUser: 10,
				maxPerDayPerUser: 50,
			},
		});

		await expect(generateImage("test")).rejects.toThrow(/not supported/);
	});
});
