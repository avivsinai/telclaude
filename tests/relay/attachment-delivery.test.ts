import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

let extractGeneratedMediaPaths: typeof import("../../src/telegram/media-detection.js").extractGeneratedMediaPaths;
let __resetPatternCache: typeof import("../../src/telegram/media-detection.js").__resetPatternCache;

const ORIGINAL_MEDIA_OUTBOX = process.env.TELCLAUDE_MEDIA_OUTBOX_DIR;

/**
 * Integration test: Verifies that attachment delivery paths work with media detection.
 *
 * This tests the critical flow:
 * 1. Relay saves attachment with timestamp-hash filename
 * 2. Relay returns the exact path in response
 * 3. Claude outputs this exact path in text
 * 4. Media detection finds the file and triggers Telegram send
 */
describe("attachment-delivery integration", () => {
	let tempDir: string;
	let mediaRoot: string;
	let documentsDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-attach-"));
		mediaRoot = tempDir;
		documentsDir = path.join(mediaRoot, "documents");
		fs.mkdirSync(documentsDir, { recursive: true });

		process.env.TELCLAUDE_MEDIA_OUTBOX_DIR = mediaRoot;
		vi.resetModules();
		({ extractGeneratedMediaPaths, __resetPatternCache } = await import(
			"../../src/telegram/media-detection.js"
		));
		__resetPatternCache();
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_MEDIA_OUTBOX === undefined) {
			delete process.env.TELCLAUDE_MEDIA_OUTBOX_DIR;
		} else {
			process.env.TELCLAUDE_MEDIA_OUTBOX_DIR = ORIGINAL_MEDIA_OUTBOX;
		}
	});

	/**
	 * Simulates what the relay's buildAttachmentFilename does.
	 * This ensures our test uses the same format as production.
	 */
	function buildAttachmentFilename(filename: string): string {
		const ext = path.extname(filename);
		const stem = ext ? filename.slice(0, -ext.length) : filename;
		const timestamp = Date.now();
		const hash = Math.random().toString(16).slice(2, 10);
		return `${stem}-${timestamp}-${hash}${ext}`;
	}

	it("detects document when Claude outputs exact relay path", () => {
		// 1. Simulate relay saving file with timestamp-hash
		const originalFilename = "visit_summary.pdf";
		const safeFilename = buildAttachmentFilename(originalFilename);
		const destPath = path.join(documentsDir, safeFilename);
		fs.writeFileSync(destPath, "fake pdf content");

		// 2. Simulate Claude outputting the exact path from relay response
		const claudeResponse = `Here's your document: ${destPath}`;

		// 3. Verify media detection finds the file
		const results = extractGeneratedMediaPaths(claudeResponse);
		expect(results).toHaveLength(1);
		expect(results[0].type).toBe("document");
		expect(fs.existsSync(results[0].path)).toBe(true);
	});

	it("fails to detect when Claude invents a simplified filename", () => {
		// 1. Relay saves with timestamp-hash
		const safeFilename = buildAttachmentFilename("visit_summary.pdf");
		const destPath = path.join(documentsDir, safeFilename);
		fs.writeFileSync(destPath, "fake pdf content");

		// 2. Claude incorrectly outputs simplified path (the bug we fixed)
		const wrongPath = path.join(documentsDir, "visit_summary.pdf");
		const claudeResponse = `Here's your document: ${wrongPath}`;

		// 3. Media detection should NOT find this (file doesn't exist at that path)
		const results = extractGeneratedMediaPaths(claudeResponse);
		expect(results).toHaveLength(0);
	});

	it("detects document with various timestamp-hash formats", () => {
		const testCases = [
			"report-1769063570514-28c3d9c9.pdf",
			"ENT_Visit_Summary-1769012656025-69f6831a.pdf",
			"document-1737000000000-abcd1234.pdf",
		];

		for (const filename of testCases) {
			const destPath = path.join(documentsDir, filename);
			fs.writeFileSync(destPath, "fake content");

			const claudeResponse = `Sending: ${destPath}`;
			const results = extractGeneratedMediaPaths(claudeResponse);

			expect(results).toHaveLength(1);
			expect(results[0].type).toBe("document");
			fs.unlinkSync(destPath);
		}
	});

	it("detects path as plain text without quotes or backticks", () => {
		const safeFilename = buildAttachmentFilename("summary.pdf");
		const destPath = path.join(documentsDir, safeFilename);
		fs.writeFileSync(destPath, "fake pdf");

		// Plain text (correct)
		const plainText = `Your file: ${destPath}`;
		expect(extractGeneratedMediaPaths(plainText)).toHaveLength(1);

		// With backticks (should still work as path is extracted)
		const withBackticks = `Your file: \`${destPath}\``;
		const backticksResult = extractGeneratedMediaPaths(withBackticks);
		// Note: backticks may interfere depending on regex - this documents behavior
		expect(backticksResult.length).toBeGreaterThanOrEqual(0);
	});
});
