import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

export const MIN_SANDBOX_RUNTIME_VERSION = "0.0.16"; // CVE-2025-66479 fixed in 0.0.16+

let cachedVersion: string | null | undefined;

function parseSemver(version: string): [number, number, number] {
	const [major = "0", minor = "0", patchWithMeta = "0"] = version.split(".", 3);
	const patch = patchWithMeta.split("-")[0]; // drop pre-release metadata
	return [
		Number.parseInt(major, 10) || 0,
		Number.parseInt(minor, 10) || 0,
		Number.parseInt(patch, 10) || 0,
	];
}

function compareVersions(a: string, b: string): number {
	const pa = parseSemver(a);
	const pb = parseSemver(b);
	for (let i = 0; i < 3; i++) {
		if (pa[i] > pb[i]) return 1;
		if (pa[i] < pb[i]) return -1;
	}
	return 0;
}

export function getSandboxRuntimeVersion(): string | null {
	if (cachedVersion !== undefined) {
		return cachedVersion;
	}

	try {
		// package.json is safe to read; sandbox-runtime is a dependency
		const pkg = require("@anthropic-ai/sandbox-runtime/package.json") as { version?: string };
		cachedVersion = typeof pkg.version === "string" ? pkg.version : null;
	} catch {
		cachedVersion = null;
	}

	return cachedVersion;
}

export function isSandboxRuntimeAtLeast(minVersion: string = MIN_SANDBOX_RUNTIME_VERSION): boolean {
	const current = getSandboxRuntimeVersion();
	if (!current) return false;
	return compareVersions(current, minVersion) >= 0;
}
