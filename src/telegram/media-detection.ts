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
import { getMediaOutboxDirSync } from "../media/store.js";
import type { TelegramMediaType } from "./types.js";

/**
 * Pattern to match generated media paths.
 * Matches paths like:
 * - /media/outbox/generated/1234567890-abc123.png (absolute)
 * - /media/outbox/tts/1234567890-abc123.mp3 (absolute)
 * - /media/outbox/voice/1234567890-abc123.ogg (voice messages)
 * - /media/outbox/documents/form17.pdf (document attachments from external providers)
 * - /workspace/.telclaude-media/generated/file.png (legacy default)
 * - /Users/name/My Projects/.telclaude-media/generated/file.png (paths with spaces)
 *
 * Design: Simple pattern that finds non-whitespace sequences containing the marker.
 * Trailing punctuation is stripped after matching.
 *
 * Note: For paths with spaces, they need to be quoted in the text
 * (e.g., "/path/with spaces/.telclaude-media/generated/file.png")
 */

function escapeRegex(input: string): string {
	return input.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Lazy-initialized pattern to allow env vars to be set before first use (for testing)
let _cachedPattern: RegExp | null = null;
let _cachedMediaOutboxRoot: string | null = null;
let _cachedLegacyMediaRoot: string | null = null;

function getMediaRoots(): { outbox: string; legacy: string } {
	return {
		outbox: getMediaOutboxDirSync(),
		legacy: path.join(process.cwd(), ".telclaude-media"),
	};
}

function getGeneratedMediaPattern(): RegExp {
	const roots = getMediaRoots();

	// Invalidate cache if roots changed (happens when env var changes in tests)
	if (
		_cachedPattern &&
		_cachedMediaOutboxRoot === roots.outbox &&
		_cachedLegacyMediaRoot === roots.legacy
	) {
		return _cachedPattern;
	}

	const mediaRootsPattern = [
		escapeRegex(roots.outbox.replace(/\\/g, "/")),
		escapeRegex(roots.legacy.replace(/\\/g, "/")),
		"\\.telclaude-media",
	]
		.filter(Boolean)
		.join("|");

	_cachedPattern = new RegExp(
		`(\\S*(?:${mediaRootsPattern})/(?:generated|tts|voice|documents)/\\S+)`,
		"g",
	);
	_cachedMediaOutboxRoot = roots.outbox;
	_cachedLegacyMediaRoot = roots.legacy;

	return _cachedPattern;
}

/**
 * Reset the cached pattern. For testing only.
 * @internal
 */
export function __resetPatternCache(): void {
	_cachedPattern = null;
	_cachedMediaOutboxRoot = null;
	_cachedLegacyMediaRoot = null;
}

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
 * Check if a path is under one of the allowed media roots.
 *
 * SECURITY: This prevents symlink attacks where a parent directory is a symlink
 * pointing outside the expected media root.
 *
 * Handles macOS symlinks like /var -> /private/var by resolving both the
 * input path and the allowed roots to their real paths.
 */
function isUnderAllowedRoot(inputPath: string): boolean {
	// Resolve the input path to its real location
	let normalizedReal: string;
	try {
		normalizedReal = fs.realpathSync(inputPath);
	} catch {
		normalizedReal = path.resolve(inputPath);
	}

	const mediaRoots = getMediaRoots();
	// Also resolve the roots to their real paths (handles macOS /var -> /private/var symlink)
	const roots = [mediaRoots.outbox, mediaRoots.legacy].map((root) => {
		try {
			return fs.realpathSync(root);
		} catch {
			return path.resolve(root);
		}
	});
	return roots.some(
		(root) => normalizedReal === root || normalizedReal.startsWith(root + path.sep),
	);
}

function safeResolvePath(inputPath: string): string | null {
	try {
		// fs.realpathSync follows ALL symlinks and returns the canonical path
		const realPath = fs.realpathSync(inputPath);

		// Verify the real path still resolves under the allowed media roots
		if (!isUnderAllowedRoot(realPath)) {
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

	// Get pattern dynamically (allows env vars to be set before first use)
	const pattern = getGeneratedMediaPattern();

	for (const match of text.matchAll(pattern)) {
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
	const normalized = filePath.replace(/\\/g, "/");
	return normalized.includes("/voice/") && isUnderAllowedRoot(filePath);
}

/**
 * Check if a response is essentially just a media path with minimal extra text.
 * Used to determine if we should send only media (no text message).
 *
 * Returns true if the response is primarily just the media path,
 * possibly with some whitespace or minimal surrounding text.
 *
 * @param response - The full response text
 * @param mediaPath - The detected media path
 * @returns True if the response is "media-only" (path with minimal text)
 */
export function isMediaOnlyResponse(response: string, mediaPath: string): boolean {
	// Remove the media path and see what's left
	const withoutPath = response.replace(mediaPath, "").trim();

	// If nothing left, or only whitespace/newlines, it's media-only
	if (!withoutPath) {
		return true;
	}

	// If what's left is very short (< 20 chars) and doesn't contain
	// substantive content, consider it media-only.
	// This catches cases like "Here's the audio:" being accidentally left in.
	// But we want to preserve meaningful context if Claude added any.
	if (withoutPath.length < 20) {
		// Check if it's just punctuation, whitespace, or very short phrases
		const stripped = withoutPath.replace(/[.,!?:;\s\n\r]+/g, "");
		return stripped.length < 10;
	}

	return false;
}

/**
 * Check if a path is in the documents directory.
 */
function isDocumentsPath(filePath: string): boolean {
	const normalized = filePath.replace(/\\/g, "/");
	return normalized.includes("/documents/") && isUnderAllowedRoot(filePath);
}

/**
 * Infer Telegram media type from file path and extension.
 *
 * Files in the .telclaude-media/voice/ directory are sent as voice messages
 * (using sendVoice API) which display with waveform in Telegram.
 *
 * Files in the .telclaude-media/documents/ directory are sent as documents
 * (using sendDocument API) for file attachments from external providers.
 * Documents directory takes priority over extension-based detection to preserve
 * files as-is (no compression like photos).
 *
 * @param filePath - Path to the media file
 * @returns The Telegram media type, or null if not a supported type
 */
export function inferMediaType(filePath: string): TelegramMediaType | null {
	const ext = path.extname(filePath).toLowerCase();

	// Documents directory takes priority - always send as document to preserve file
	// (external provider attachments should not be compressed like photos)
	if (isDocumentsPath(filePath)) {
		return "document";
	}

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
