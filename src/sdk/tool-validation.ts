/**
 * Shared tool validation helpers for SDK security enforcement.
 *
 * These functions are used by BOTH enforcement layers:
 * - PreToolUse hooks (PRIMARY — runs unconditionally)
 * - canUseTool callback (FALLBACK — runs only when permission prompt would appear)
 *
 * Extracting them here eliminates the duplicated path-checking logic that
 * previously lived in two places inside client.ts.
 */

import fs from "node:fs";
import { getChildLogger } from "../logging.js";
import { isSensitivePath } from "../security/permissions.js";

const logger = getChildLogger({ module: "tool-validation" });

// ═══════════════════════════════════════════════════════════════════════════════
// Path Resolution
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Resolve symlinks to get the real path.
 * Returns the original path if the file doesn't exist or resolution fails.
 */
export function resolveRealPath(inputPath: string): string {
	try {
		return fs.realpathSync(inputPath);
	} catch {
		return inputPath;
	}
}

/**
 * Check if a path (after symlink resolution) is sensitive.
 * Defends against symlink attacks where an attacker creates a symlink
 * to bypass path checks.
 */
export function checkPathWithSymlinks(inputPath: string): boolean {
	if (isSensitivePath(inputPath)) return true;
	const realPath = resolveRealPath(inputPath);
	if (realPath !== inputPath && isSensitivePath(realPath)) {
		logger.warn({ inputPath, realPath }, "symlink to sensitive path detected");
		return true;
	}
	return false;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Path-Bearing Field Scanning
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Fields that contain paths and should be scanned for sensitive paths.
 * Excludes content fields like Write.content, Edit.old_string/new_string,
 * WebSearch.query, etc. to avoid false positives on legitimate content.
 */
const PATH_BEARING_FIELDS = new Set([
	"file_path", // Read, Write, Edit
	"path", // Glob, Grep
	"pattern", // Glob (can contain path prefixes)
	"command", // Bash
	"notebook_path", // NotebookEdit
]);

/**
 * Extract the path prefix from a glob pattern for symlink resolution.
 * E.g., "src/foo/*.ts" resolves "src/foo", "*.txt" returns "".
 * Returns the first path segment(s) before any wildcard characters.
 */
export function extractPathPrefix(pattern: string): string {
	const segments = pattern.split("/");
	const pathSegments: string[] = [];
	for (const segment of segments) {
		if (segment.includes("*") || segment.includes("?") || segment.includes("[")) {
			break;
		}
		pathSegments.push(segment);
	}
	return pathSegments.join("/");
}

/**
 * Scan ONLY path-bearing fields in an input payload for sensitive paths.
 * This avoids false positives on content fields (Write.content, Edit.new_string, etc.).
 */
export function inputContainsSensitivePath(payload: unknown): boolean {
	if (payload == null || typeof payload !== "object") {
		return false;
	}

	const obj = payload as Record<string, unknown>;

	for (const [key, value] of Object.entries(obj)) {
		if (PATH_BEARING_FIELDS.has(key) && typeof value === "string") {
			if (isSensitivePath(value)) {
				return true;
			}
		}
	}

	return false;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Unified Tool Path Validation
// ═══════════════════════════════════════════════════════════════════════════════

export type ToolPathValidationResult = {
	denied: boolean;
	reason: string;
};

const ALLOWED: ToolPathValidationResult = { denied: false, reason: "" };

function deny(reason: string): ToolPathValidationResult {
	return { denied: true, reason };
}

/**
 * Validate tool input for sensitive path access.
 *
 * Handles per-tool path checking with symlink resolution:
 * - Read/Write/Edit: check file_path + symlinks
 * - Glob: check path, pattern prefix, and full pattern
 * - Grep: check path with wildcard prefix extraction
 * - Bash: check command for sensitive paths
 * - Generic: scan all path-bearing fields
 *
 * Used by BOTH PreToolUse hooks (PRIMARY) and canUseTool (FALLBACK).
 */
export function validateToolPath(
	toolName: string,
	toolInput: Record<string, unknown>,
): ToolPathValidationResult {
	// Read, Write, Edit: check file_path with symlink resolution
	if (
		(toolName === "Read" || toolName === "Write" || toolName === "Edit") &&
		typeof toolInput.file_path === "string"
	) {
		if (checkPathWithSymlinks(toolInput.file_path)) {
			return deny(
				toolName === "Read"
					? "Access to this file is not permitted for security reasons."
					: toolName === "Write"
						? "Writing to this location is not permitted for security reasons."
						: "Editing this file is not permitted for security reasons.",
			);
		}
	}

	// Glob: check path, pattern prefix, and full pattern
	if (toolName === "Glob" && typeof toolInput.pattern === "string") {
		const searchPath =
			typeof toolInput.path === "string" ? toolInput.path : extractPathPrefix(toolInput.pattern);
		if (searchPath && checkPathWithSymlinks(searchPath)) {
			return deny("Searching this location is not permitted for security reasons.");
		}
		if (isSensitivePath(toolInput.pattern)) {
			return deny("Searching this location is not permitted for security reasons.");
		}
	}

	// Grep: check path with wildcard prefix extraction
	if (toolName === "Grep") {
		const searchPath = typeof toolInput.path === "string" ? toolInput.path : "";
		if (searchPath) {
			const pathPrefix = extractPathPrefix(searchPath);
			const realPath = pathPrefix ? resolveRealPath(pathPrefix) : "";
			if (
				(realPath && isSensitivePath(realPath)) ||
				isSensitivePath(searchPath) ||
				(pathPrefix && isSensitivePath(pathPrefix))
			) {
				return deny("Searching this location is not permitted for security reasons.");
			}
		}
	}

	// Bash: check command for sensitive path references
	if (toolName === "Bash" && typeof toolInput.command === "string") {
		if (isSensitivePath(toolInput.command)) {
			return deny("Access to sensitive paths via shell is not permitted.");
		}
	}

	// Generic guard: scan all path-bearing fields
	// Exclude WebSearch — uses `query` (not paths), server-side requests
	if (toolName !== "WebSearch" && inputContainsSensitivePath(toolInput)) {
		return deny("Input contains reference to sensitive paths.");
	}

	return ALLOWED;
}

// ═══════════════════════════════════════════════════════════════════════════════
// URL Port Resolution
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Get the effective port number from a URL, defaulting to protocol standard ports.
 * Replaces the 4 inline port-resolution snippets that were scattered through client.ts.
 */
export function getUrlPortNumber(url: URL): number {
	if (url.port) return Number.parseInt(url.port, 10);
	return url.protocol === "https:" ? 443 : 80;
}
