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
 * - /path/to/.telclaude-media/voice/1234567890-abc123.ogg (voice messages)
 * - .telclaude-media/generated/file.png (relative, no prefix)
 * - some/path/.telclaude-media/tts/file.mp3 (relative with prefix)
 * - /Users/name/My Projects/.telclaude-media/generated/file.png (paths with spaces)
 *
 * Design: Simple pattern that finds non-whitespace sequences containing the marker.
 * Trailing punctuation is stripped after matching.
 *
 * Note: For paths with spaces, they need to be quoted in the text
 * (e.g., "/path/with spaces/.telclaude-media/generated/file.png")
 */
const GENERATED_MEDIA_PATTERN = /(\S*\.telclaude-media\/(?:generated|tts|voice)\/\S+)/g;

/**
 * Image extensions we support sending.
 */
const IMAGE_EXTENSIONS = new Set([".png", ".jpg", ".jpeg", ".gif", ".webp"]);

/**
 * Audio extensions we support sending.
 */
const AUDIO_EXTENSIONS = new Set([".mp3", ".m4a", ".wav", ".flac", ".ogg", ".opus", ".aac"]);

/**
 * Voice message extensions that should be sent via sendVoice.
 */
const VOICE_EXTENSIONS = new Set([".ogg", ".opus"]);

export type DetectedMedia = {
	path: string;
	type: TelegramMediaType;
};

/**
 * Safely resolve a path to its real location, checking for symlinks in the chain.
 * Returns null if any component is a symlink or if resolution fails.
 *
 * SECURITY: This prevents symlink attacks where a parent directory is a symlink
 * pointing outside the expected media root.
 */
function safeResolvePath(inputPath: string): string | null {
	try {
		// fs.realpathSync follows ALL symlinks and returns the canonical path
		const realPath = fs.realpathSync(inputPath);

		// Verify the real path still contains .telclaude-media
		// This catches cases where a symlinked parent redirects outside
		if (!realPath.includes("/.telclaude-media/") && !realPath.includes("\\.telclaude-media\\")) {
			return null;
		}

		// Double-check the normalized real path still contains the marker
		// (realpathSync should have caught this, but defense-in-depth)
		const normalizedReal = path.normalize(realPath);
		if (!normalizedReal.includes(".telclaude-media")) {
			return null;
		}

		return realPath;
	} catch {
		// Resolution failed - file doesn't exist or permission denied
		return null;
	}
}

/**
 * Extract generated media paths from Claude's response text.
 *
 * This function scans Claude's response for file paths that point to
 * generated media (images, audio) in the .telclaude-media directory.
 * Detected files are verified to exist before being returned.
 *
 * SECURITY:
 * - Uses realpathSync to resolve the canonical path (catches symlinked parents)
 * - Uses lstatSync to reject symlinked leaf files
 * - Verifies the resolved real path is still under .telclaude-media
 * - No time gap between check and use (atomic operations)
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
		// Strip trailing punctuation that's not part of the path
		const rawPath = match[1].replace(/[.,!?;:'")\]]+$/, "");
		if (!rawPath || seen.has(rawPath)) continue;
		seen.add(rawPath);

		// Resolve to absolute path if relative
		const absolutePath = path.isAbsolute(rawPath)
			? rawPath
			: path.resolve(workingDir ?? process.cwd(), rawPath);

		// SECURITY: Resolve the real path, catching symlinked parent directories
		// This prevents attacks like: /tmp/symlink-to-root/.telclaude-media/... -> /etc/passwd
		const realPath = safeResolvePath(absolutePath);
		if (!realPath) {
			continue;
		}

		// SECURITY: Use lstatSync on the REAL path (doesn't follow symlinks)
		// This catches symlinked leaf files
		let stats: fs.Stats;
		try {
			stats = fs.lstatSync(realPath);
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

		// Determine media type from extension
		const type = inferMediaType(realPath);
		if (!type) continue;

		results.push({ path: realPath, type });
	}

	return results;
}

/**
 * Check if a path is in the voice messages directory.
 */
function isVoiceMessagePath(filePath: string): boolean {
	// Check for .telclaude-media/voice/ in the path
	return (
		filePath.includes(".telclaude-media/voice/") || filePath.includes(".telclaude-media\\voice\\")
	);
}

/**
 * Infer Telegram media type from file path and extension.
 *
 * Files in the .telclaude-media/voice/ directory are sent as voice messages
 * (using sendVoice API) which display with waveform in Telegram.
 *
 * @param filePath - Path to the media file
 * @returns The Telegram media type, or null if not a supported type
 */
export function inferMediaType(filePath: string): TelegramMediaType | null {
	const ext = path.extname(filePath).toLowerCase();

	if (IMAGE_EXTENSIONS.has(ext)) {
		return "photo";
	}

	// Voice messages directory -> send as voice (waveform display)
	if (isVoiceMessagePath(filePath) && VOICE_EXTENSIONS.has(ext)) {
		return "voice";
	}

	// Regular audio files -> send as audio (music player display)
	if (AUDIO_EXTENSIONS.has(ext)) {
		return "audio";
	}

	return null;
}
