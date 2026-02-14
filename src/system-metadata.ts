import { createRequire } from "node:module";

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
