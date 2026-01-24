import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

let extractGeneratedMediaPaths: typeof import("../../src/telegram/media-detection.js").extractGeneratedMediaPaths;
let inferMediaType: typeof import("../../src/telegram/media-detection.js").inferMediaType;
let __resetPatternCache: typeof import("../../src/telegram/media-detection.js").__resetPatternCache;

const ORIGINAL_MEDIA_OUTBOX = process.env.TELCLAUDE_MEDIA_OUTBOX_DIR;

describe("media-detection", () => {
	let tempDir: string;
	let audioPath: string;
	let imagePath: string;
	let voicePath: string;
	let documentPath: string;
	let mediaRoot: string;
	// Real paths after symlink resolution (e.g., /var -> /private/var on macOS)
	let realAudioPath: string;
	let realImagePath: string;
	let realVoicePath: string;
	let realDocumentPath: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-media-"));
		mediaRoot = path.join(tempDir, ".telclaude-media");
		process.env.TELCLAUDE_MEDIA_OUTBOX_DIR = mediaRoot;
		vi.resetModules();
		({ extractGeneratedMediaPaths, inferMediaType, __resetPatternCache } = await import(
			"../../src/telegram/media-detection.js"
		));
		// Reset cached pattern to pick up new env var
		__resetPatternCache();

		const ttsDir = path.join(mediaRoot, "tts");
		const genDir = path.join(mediaRoot, "generated");
		const voiceDir = path.join(mediaRoot, "voice");
		const documentsDir = path.join(mediaRoot, "documents");
		fs.mkdirSync(ttsDir, { recursive: true });
		fs.mkdirSync(genDir, { recursive: true });
		fs.mkdirSync(voiceDir, { recursive: true });
		fs.mkdirSync(documentsDir, { recursive: true });
		audioPath = path.join(ttsDir, "sample.aac");
		imagePath = path.join(genDir, "image.png");
		voicePath = path.join(voiceDir, "sample.ogg");
		// Document with timestamp-hash suffix (as relay generates)
		documentPath = path.join(documentsDir, "visit_summary-1769063570514-28c3d9c9.pdf");
		fs.writeFileSync(audioPath, "fake audio data");
		fs.writeFileSync(imagePath, "fake image data");
		fs.writeFileSync(voicePath, "fake voice data");
		fs.writeFileSync(documentPath, "fake pdf data");
		// Get the real paths (resolves symlinks like /var -> /private/var on macOS)
		realAudioPath = fs.realpathSync(audioPath);
		realImagePath = fs.realpathSync(imagePath);
		realVoicePath = fs.realpathSync(voicePath);
		realDocumentPath = fs.realpathSync(documentPath);
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_MEDIA_OUTBOX === undefined) {
			delete process.env.TELCLAUDE_MEDIA_OUTBOX_DIR;
		} else {
			process.env.TELCLAUDE_MEDIA_OUTBOX_DIR = ORIGINAL_MEDIA_OUTBOX;
		}
	});

	describe("inferMediaType", () => {
		it("infers AAC audio files", () => {
			expect(inferMediaType(audioPath)).toBe("audio");
		});

		it("infers PNG image files", () => {
			expect(inferMediaType(imagePath)).toBe("photo");
		});

		it("infers voice messages for OGG files in voice directory", () => {
			expect(inferMediaType(voicePath)).toBe("voice");
		});

		it("does not treat non-voice extensions in voice directory as voice", () => {
			const wavPath = path.join(path.dirname(voicePath), "sample.wav");
			fs.writeFileSync(wavPath, "fake wav data");
			expect(inferMediaType(wavPath)).toBe("audio");
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
			const cwd = tempDir;
			const relativeDir = path.join(cwd, ".telclaude-media", "tts");
			const relativeFile = path.join(relativeDir, "relative.mp3");
			fs.writeFileSync(relativeFile, "fake audio");
			const realRelativeFile = fs.realpathSync(relativeFile);

			const text = "Generated audio at .telclaude-media/tts/relative.mp3 for you.";
			const results = extractGeneratedMediaPaths(text, cwd);
			expect(results).toEqual([{ path: realRelativeFile, type: "audio" }]);
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

		it("detects voice message paths", () => {
			const text = `Voice message: ${voicePath}`;
			const results = extractGeneratedMediaPaths(text);
			expect(results).toEqual([{ path: realVoicePath, type: "voice" }]);
		});

		it("deduplicates repeated paths", () => {
			const text = `${audioPath} ... ${audioPath}`;
			const results = extractGeneratedMediaPaths(text);
			expect(results).toHaveLength(1);
		});

		it("rejects symlinks for security", () => {
			const symlinkPath = path.join(mediaRoot, "tts", "symlink.mp3");
			fs.symlinkSync("/etc/passwd", symlinkPath);

			const text = `Audio at ${symlinkPath}`;
			const results = extractGeneratedMediaPaths(text);
			expect(results).toEqual([]);
		});

		it("rejects non-existent files", () => {
			const fakePath = path.join(mediaRoot, "tts", "nonexistent.mp3");
			const text = `Audio at ${fakePath}`;
			const results = extractGeneratedMediaPaths(text);
			expect(results).toEqual([]);
		});

		it("detects document paths with timestamp-hash suffix", () => {
			// This is the exact format the relay generates for attachments
			const text = `Here's your document: ${documentPath}`;
			const results = extractGeneratedMediaPaths(text);
			expect(results).toEqual([{ path: realDocumentPath, type: "document" }]);
		});

		it("detects document paths as plain text (no formatting)", () => {
			// Path must be plain text - no backticks, quotes, or code formatting
			const text = `Sending your visit summary: ${documentPath}`;
			const results = extractGeneratedMediaPaths(text);
			expect(results).toEqual([{ path: realDocumentPath, type: "document" }]);
		});

		it("rejects non-existent document paths (wrong filename)", () => {
			// If Claude invents a simplified filename, it won't match
			const wrongPath = path.join(mediaRoot, "documents", "visit_summary.pdf");
			const text = `Here's your document: ${wrongPath}`;
			const results = extractGeneratedMediaPaths(text);
			expect(results).toEqual([]);
		});
	});

	describe("inferMediaType for documents", () => {
		it("infers document type for PDFs in documents directory", () => {
			expect(inferMediaType(documentPath)).toBe("document");
		});

		it("documents directory takes priority over extension", () => {
			// Even if it's a .png in documents dir, it should be a document
			const pngInDocs = path.join(mediaRoot, "documents", "scan-123456.png");
			fs.writeFileSync(pngInDocs, "fake png");
			expect(inferMediaType(pngInDocs)).toBe("document");
		});
	});
});
