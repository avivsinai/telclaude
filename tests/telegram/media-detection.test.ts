import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { extractGeneratedMediaPaths, inferMediaType } from "../../src/telegram/media-detection.js";

describe("media-detection", () => {
	let tempDir: string;
	let audioPath: string;
	let imagePath: string;
	// Real paths after symlink resolution (e.g., /var -> /private/var on macOS)
	let realAudioPath: string;
	let realImagePath: string;

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-media-"));
		const ttsDir = path.join(tempDir, ".telclaude-media", "tts");
		const genDir = path.join(tempDir, ".telclaude-media", "generated");
		fs.mkdirSync(ttsDir, { recursive: true });
		fs.mkdirSync(genDir, { recursive: true });
		audioPath = path.join(ttsDir, "sample.aac");
		imagePath = path.join(genDir, "image.png");
		fs.writeFileSync(audioPath, "fake audio data");
		fs.writeFileSync(imagePath, "fake image data");
		// Get the real paths (resolves symlinks like /var -> /private/var on macOS)
		realAudioPath = fs.realpathSync(audioPath);
		realImagePath = fs.realpathSync(imagePath);
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
	});

	describe("inferMediaType", () => {
		it("infers AAC audio files", () => {
			expect(inferMediaType(audioPath)).toBe("audio");
		});

		it("infers PNG image files", () => {
			expect(inferMediaType(imagePath)).toBe("photo");
		});

		it("returns null for unsupported extensions", () => {
			expect(inferMediaType("/path/to/file.txt")).toBeNull();
		});
	});

	describe("extractGeneratedMediaPaths", () => {
		it("detects absolute paths", () => {
			const text = `Saved audio to ${audioPath}.`;
			const results = extractGeneratedMediaPaths(text);
			// Result uses real path (symlinks resolved)
			expect(results).toEqual([{ path: realAudioPath, type: "audio" }]);
		});

		it("detects relative paths without prefix", () => {
			// Create a file in current working directory structure
			const cwd = process.cwd();
			const relativeDir = path.join(cwd, ".telclaude-media", "tts");
			fs.mkdirSync(relativeDir, { recursive: true });
			const relativeFile = path.join(relativeDir, "relative.mp3");
			fs.writeFileSync(relativeFile, "fake audio");
			const realRelativeFile = fs.realpathSync(relativeFile);

			try {
				const text = "Generated audio at .telclaude-media/tts/relative.mp3 for you.";
				const results = extractGeneratedMediaPaths(text, cwd);
				expect(results).toEqual([{ path: realRelativeFile, type: "audio" }]);
			} finally {
				fs.rmSync(path.join(cwd, ".telclaude-media"), { recursive: true, force: true });
			}
		});

		it("detects paths followed by punctuation", () => {
			const text = `Here's your image: ${imagePath}!`;
			const results = extractGeneratedMediaPaths(text);
			// Result uses real path (symlinks resolved)
			expect(results).toEqual([{ path: realImagePath, type: "photo" }]);
		});

		it("detects multiple paths in same text", () => {
			const text = `Audio: ${audioPath} and image: ${imagePath}.`;
			const results = extractGeneratedMediaPaths(text);
			expect(results).toHaveLength(2);
			// Results use real paths (symlinks resolved)
			expect(results).toContainEqual({ path: realAudioPath, type: "audio" });
			expect(results).toContainEqual({ path: realImagePath, type: "photo" });
		});

		it("deduplicates repeated paths", () => {
			const text = `${audioPath} ... ${audioPath}`;
			const results = extractGeneratedMediaPaths(text);
			expect(results).toHaveLength(1);
		});

		it("rejects symlinks for security", () => {
			const symlinkPath = path.join(tempDir, ".telclaude-media", "tts", "symlink.mp3");
			fs.symlinkSync("/etc/passwd", symlinkPath);

			const text = `Audio at ${symlinkPath}`;
			const results = extractGeneratedMediaPaths(text);
			expect(results).toEqual([]);
		});

		it("rejects non-existent files", () => {
			const fakePath = path.join(tempDir, ".telclaude-media", "tts", "nonexistent.mp3");
			const text = `Audio at ${fakePath}`;
			const results = extractGeneratedMediaPaths(text);
			expect(results).toEqual([]);
		});
	});
});
