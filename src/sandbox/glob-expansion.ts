/**
 * Glob pattern expansion for Linux sandbox.
 *
 * The @anthropic-ai/sandbox-runtime library silently drops glob patterns on Linux
 * (bubblewrap doesn't support them). This module expands glob patterns to literal
 * paths before passing them to the sandbox, ensuring protections work on Linux.
 *
 * IMPORTANT: Relative glob patterns (like "*.env", "*.pem") are expanded from
 * MULTIPLE base directories to ensure coverage beyond just cwd:
 * - The project cwd (workspace)
 * - The user's home directory
 * This prevents sensitive files in ~ from being readable/writable when cwd is elsewhere.
 *
 * Security note: This is a point-in-time expansion. Files created after expansion
 * won't be protected. For dynamic protection, consider the output filter layer.
 */

import os from "node:os";
import path from "node:path";
import fg from "fast-glob";
import { getChildLogger } from "../logging.js";

const logger = getChildLogger({ module: "sandbox-glob" });

/**
 * Check if a path pattern contains glob characters.
 * Matches the logic in @anthropic-ai/sandbox-runtime.
 */
export function containsGlobChars(pattern: string): boolean {
	return (
		pattern.includes("*") || pattern.includes("?") || pattern.includes("[") || pattern.includes("]")
	);
}

/**
 * Check if running on Linux.
 */
export function isLinux(): boolean {
	return os.platform() === "linux";
}

/**
 * Check if a pattern is relative (doesn't start with / or ~).
 * Relative patterns need to be expanded from multiple base directories.
 */
function isRelativePattern(pattern: string): boolean {
	return !pattern.startsWith("/") && !pattern.startsWith("~");
}

/**
 * Expand a glob pattern from a single base directory.
 * Internal helper - use expandGlobSync for the full multi-directory expansion.
 */
function expandGlobFromBase(pattern: string, baseCwd: string): string[] {
	try {
		const matches = fg.sync(pattern, {
			cwd: baseCwd,
			absolute: true,
			dot: true, // Include dotfiles
			onlyFiles: false, // Include directories too
			followSymbolicLinks: false, // Don't follow symlinks for security
			suppressErrors: true, // Don't throw on permission errors
		});
		return matches;
	} catch (err) {
		logger.warn({ pattern, cwd: baseCwd, error: String(err) }, "failed to expand glob pattern");
		return [];
	}
}

/**
 * Expand a glob pattern to literal paths.
 *
 * IMPORTANT: For relative glob patterns (not starting with / or ~), expansion
 * runs from MULTIPLE base directories to ensure sensitive files outside cwd
 * are also protected:
 * - The project cwd
 * - The user's home directory (~)
 *
 * @param pattern - Glob pattern (e.g., ".env", "*.pem")
 * @param cwd - Base directory for expansion (defaults to process.cwd())
 * @returns Array of absolute paths matching the pattern
 */
export function expandGlobSync(pattern: string, cwd?: string): string[] {
	const baseCwd = cwd ?? process.cwd();
	const homedir = os.homedir();

	// Handle ~ expansion - these are already absolute
	let normalizedPattern = pattern;
	if (pattern.startsWith("~/")) {
		normalizedPattern = path.join(homedir, pattern.slice(2));
	} else if (pattern === "~") {
		normalizedPattern = homedir;
	}

	// If pattern doesn't contain globs, return as-is
	if (!containsGlobChars(normalizedPattern)) {
		return [normalizedPattern];
	}

	// For relative glob patterns, expand from MULTIPLE base directories
	// This ensures sensitive files in ~ are blocked even when cwd is elsewhere
	if (isRelativePattern(pattern)) {
		const allMatches = new Set<string>();

		// Expand from cwd (project directory)
		for (const match of expandGlobFromBase(normalizedPattern, baseCwd)) {
			allMatches.add(match);
		}

		// Expand from home directory (catches ~/.env, ~/secrets.json, etc.)
		// Skip only if we're already expanding from home (Set de-dupes paths, but avoid double walking)
		if (baseCwd !== homedir) {
			for (const match of expandGlobFromBase(normalizedPattern, homedir)) {
				allMatches.add(match);
			}
		}

		const matches = Array.from(allMatches);
		logger.debug(
			{ pattern, cwd: baseCwd, homedir, matches: matches.length },
			"expanded relative glob from multiple directories",
		);
		return matches;
	}

	// For absolute patterns (starting with / or ~), expand from a single base
	const matches = expandGlobFromBase(normalizedPattern, baseCwd);
	logger.debug({ pattern, cwd: baseCwd, matches: matches.length }, "expanded glob pattern");
	return matches;
}

/**
 * Expand all glob patterns in a path list for Linux.
 * On non-Linux platforms, returns the original list unchanged.
 *
 * @param paths - Array of path patterns (may include globs)
 * @param cwd - Base directory for expansion
 * @returns Expanded paths (globs replaced with literal matches)
 */
export function expandGlobsForLinux(paths: string[], cwd?: string): string[] {
	if (!isLinux()) {
		return paths;
	}

	const result: string[] = [];
	let expandedCount = 0;

	for (const pattern of paths) {
		if (containsGlobChars(pattern)) {
			const expanded = expandGlobSync(pattern, cwd);
			if (expanded.length > 0) {
				result.push(...expanded);
				expandedCount += expanded.length;
			} else {
				// No matches - drop it (bubblewrap doesn't support globs anyway).
				logger.debug({ pattern }, "no matches for glob pattern, dropping");
			}
		} else {
			result.push(pattern);
		}
	}

	if (expandedCount > 0) {
		logger.info(
			{ totalPaths: paths.length, expandedMatches: expandedCount },
			"expanded glob patterns for Linux sandbox",
		);
	}

	return result;
}

/**
 * Get patterns that contain globs (will be dropped on Linux).
 * Useful for warning users about the limitation.
 */
export function getGlobPatterns(paths: string[]): string[] {
	return paths.filter(containsGlobChars);
}

/**
 * Analyze sandbox config for Linux glob issues.
 * Returns information about patterns that will be silently dropped.
 */
export function analyzeGlobPatterns(config: {
	denyRead?: string[];
	denyWrite?: string[];
}): {
	denyReadGlobs: string[];
	denyWriteGlobs: string[];
	hasIssues: boolean;
} {
	const denyReadGlobs = getGlobPatterns(config.denyRead ?? []);
	const denyWriteGlobs = getGlobPatterns(config.denyWrite ?? []);

	return {
		denyReadGlobs,
		denyWriteGlobs,
		hasIssues: isLinux() && (denyReadGlobs.length > 0 || denyWriteGlobs.length > 0),
	};
}
