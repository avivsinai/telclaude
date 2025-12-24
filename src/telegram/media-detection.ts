/**
 * Detect generated media paths in Claude's response.
 *
 * This module enables automatic media sending for telclaude skills.
 * When Claude uses skills like image-generator or text-to-speech, it outputs
 * file paths to generated media. The relay detects these paths and sends them
 * back to the user via Telegram.
 *
 * This follows December 2025 best practices:
 * - Skills teach Claude the pattern (include path in response)
 * - Relay handles execution (detects path, sends media)
 * - Bot token stays secure (not exposed to sandbox)
 *
 * @see https://claude.com/blog/skills-explained
 */

import fs from "node:fs";
import path from "node:path";
import type { TelegramMediaType } from "./types.js";

/**
 * Pattern to match generated media paths.
 * Matches paths like:
 * - /workspace/.telclaude-media/generated/1234567890-abc123.png (absolute)
 * - /path/to/.telclaude-media/tts/1234567890-abc123.mp3 (absolute)
 * - .telclaude-media/generated/file.png (relative, no prefix)
 * - some/path/.telclaude-media/tts/file.mp3 (relative with prefix)
 *
 * Design: Uses delimiters and path separators to avoid false positives
 * while being flexible enough to match various path formats.
 *
 * Regex breakdown:
 * - (?:^|[\s"'`(\[]) - Anchor: start of string or delimiter
 * - ((?:\/[\w.-]+)+\/|(?:[\w.-]+\/)+)? - Optional path prefix (absolute or relative)
 * - \.telclaude-media\/(?:generated|tts)\/ - The marker directory
 * - [\w.-]+\.\w+ - Filename with extension
 * - Lookahead for valid terminators (whitespace, punctuation, end)
 */
const GENERATED_MEDIA_PATTERN =
	/(?:^|[\s"'`(\[])((?:(?:\/[\w.-]+)+\/|(?:[\w.-]+\/)+)?\.telclaude-media\/(?:generated|tts)\/[\w.-]+\.\w+)(?=$|[\s"'`)\],;:!?]|\.(?=$|[\s"'`)\],;:!?]))/gm;

/**
 * Image extensions we support sending.
 */
const IMAGE_EXTENSIONS = new Set([".png", ".jpg", ".jpeg", ".gif", ".webp"]);

/**
 * Audio extensions we support sending.
 */
const AUDIO_EXTENSIONS = new Set([".mp3", ".m4a", ".wav", ".flac", ".ogg", ".opus", ".aac"]);

export type DetectedMedia = {
	path: string;
	type: TelegramMediaType;
};

/**
 * Extract generated media paths from Claude's response text.
 *
 * This function scans Claude's response for file paths that point to
 * generated media (images, audio) in the .telclaude-media directory.
 * Detected files are verified to exist before being returned.
 *
 * SECURITY: Uses lstatSync (not following symlinks) to prevent TOCTOU attacks.
 * - Rejects symlinks entirely (Claude should create regular files, not symlinks)
 * - Verifies file is a regular file before including
 * - No time gap between check and use
 *
 * @param text - Claude's response text
 * @param workingDir - Current working directory for resolving relative paths
 * @returns Array of detected media that exists on disk
 */
export function extractGeneratedMediaPaths(text: string, workingDir?: string): DetectedMedia[] {
	const results: DetectedMedia[] = [];
	const seen = new Set<string>();

	// Reset regex state for global matching
	GENERATED_MEDIA_PATTERN.lastIndex = 0;

	for (const match of text.matchAll(GENERATED_MEDIA_PATTERN)) {
		const rawPath = match[1];
		if (!rawPath || seen.has(rawPath)) continue;
		seen.add(rawPath);

		// Resolve to absolute path if relative
		const absolutePath = path.isAbsolute(rawPath)
			? rawPath
			: path.resolve(workingDir ?? process.cwd(), rawPath);

		// SECURITY: Use lstatSync which does NOT follow symlinks (prevents TOCTOU)
		// This is atomic - no gap between checking and using the file info
		let stats: fs.Stats;
		try {
			stats = fs.lstatSync(absolutePath);
		} catch {
			// File doesn't exist or can't be accessed - skip
			continue;
		}

		// SECURITY: Reject symlinks entirely
		// Claude should create regular files, not symlinks
		// This prevents exfiltration attacks like:
		// .telclaude-media/generated/attack.png -> /etc/passwd
		if (stats.isSymbolicLink()) {
			continue;
		}

		// Only allow regular files (not directories, sockets, etc.)
		if (!stats.isFile()) {
			continue;
		}

		// SECURITY: Verify the path contains .telclaude-media (defense-in-depth)
		// The regex already requires this, but we double-check for safety
		if (!absolutePath.includes("/.telclaude-media/")) {
			continue;
		}

		// Determine media type from extension
		const type = inferMediaType(absolutePath);
		if (!type) continue;

		results.push({ path: absolutePath, type });
	}

	return results;
}

/**
 * Infer Telegram media type from file extension.
 *
 * @param filePath - Path to the media file
 * @returns The Telegram media type, or null if not a supported type
 */
export function inferMediaType(filePath: string): TelegramMediaType | null {
	const ext = path.extname(filePath).toLowerCase();

	if (IMAGE_EXTENSIONS.has(ext)) {
		return "photo";
	}
	if (AUDIO_EXTENSIONS.has(ext)) {
		return "audio";
	}

	return null;
}
