import { execSync } from "node:child_process";
import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);

const DEFAULT_VERSION = "0.0.0";
const DEFAULT_REVISION = "unknown";

function resolveVersion(): string {
	try {
		const pkg = require("../package.json") as { version?: string };
		return pkg.version ?? DEFAULT_VERSION;
	} catch {
		return DEFAULT_VERSION;
	}
}

function resolveRevision(): string {
	// 1. Environment variables (explicit override)
	const candidates = [
		process.env.TELCLAUDE_REVISION,
		process.env.GIT_COMMIT,
		process.env.GITHUB_SHA,
		process.env.CI_COMMIT_SHA,
		process.env.CI_COMMIT_SHORT_SHA,
	];

	for (const candidate of candidates) {
		if (candidate?.trim()) {
			return candidate.trim();
		}
	}

	// Anchored to the source directory, not process.cwd()
	const sourceDir = path.dirname(fileURLToPath(import.meta.url));

	// 2. Live git (native mode — always fresh; fails in Docker where .git is absent)
	try {
		const rev = execSync("git rev-parse HEAD", {
			cwd: sourceDir,
			encoding: "utf-8",
			stdio: ["ignore", "pipe", "ignore"],
			timeout: 2000,
		})
			.trim()
			.slice(0, 7);
		if (rev) {
			return rev;
		}
	} catch {
		// not in a git repo or git not available — fall through to .revision file
	}

	// 3. .revision file (Docker fallback — baked by prebuild from host, or copied into image)
	const revisionPaths = [
		"/app/.revision",
		path.resolve(sourceDir, "../.revision"),
	];
	for (const revPath of revisionPaths) {
		try {
			const rev = fs.readFileSync(revPath, "utf-8").trim();
			if (rev && rev !== "unknown") {
				return rev;
			}
		} catch {
			// file doesn't exist — try next
		}
	}

	return DEFAULT_REVISION;
}

const METADATA = {
	version: resolveVersion(),
	revision: resolveRevision(),
};

export type RuntimeSnapshot = {
	version: string;
	revision: string;
	startedAt: string;
	uptimeMs: number;
	uptimeSeconds: number;
};

export function getServiceVersion(): string {
	return METADATA.version;
}

export function getServiceRevision(): string {
	return METADATA.revision;
}

export function buildRuntimeSnapshot(
	startedAtMs: number,
	now: number = Date.now(),
): RuntimeSnapshot {
	const uptimeMs = now - startedAtMs;
	return {
		version: METADATA.version,
		revision: METADATA.revision,
		startedAt: new Date(startedAtMs).toISOString(),
		uptimeMs,
		uptimeSeconds: Math.floor(uptimeMs / 1000),
	};
}
