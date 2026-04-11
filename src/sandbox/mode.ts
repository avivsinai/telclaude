/**
 * Runtime environment detection.
 *
 * Telclaude's supported runtime is Docker-only. We still expose mode detection
 * helpers because diagnostics and unit tests need to distinguish Docker from
 * non-Docker environments, but service/runtime entrypoints must fail closed
 * outside Docker.
 */

import fs from "node:fs";
import { getChildLogger } from "../logging.js";

const logger = getChildLogger({ module: "sandbox-mode" });

export type SandboxMode = "docker" | "native";

export function getDockerRuntimeRequirementMessage(context = "Telclaude runtime"): string {
	return `${context} requires Docker. Native/non-Docker deployment is retired and unsupported. Run it inside the Docker Compose stack.`;
}

/**
 * Detect if running inside Docker container.
 */
export function isDockerEnvironment(): boolean {
	// Explicit env var takes precedence
	if (process.env.TELCLAUDE_DOCKER === "1") {
		return true;
	}

	// Check for Docker-specific files
	try {
		// /.dockerenv exists in Docker containers
		if (fs.existsSync("/.dockerenv")) {
			return true;
		}

		// Check cgroup for docker/container indicators
		const cgroup = fs.readFileSync("/proc/1/cgroup", "utf-8");
		if (cgroup.includes("docker") || cgroup.includes("containerd") || cgroup.includes("kubepods")) {
			return true;
		}
	} catch {
		// Not on Linux or file doesn't exist - not in Docker
	}

	return false;
}

/**
 * Get the current sandbox mode.
 */
export function getSandboxMode(): SandboxMode {
	if (isDockerEnvironment()) {
		logger.debug("detected Docker environment");
		return "docker";
	}

	logger.debug("detected non-Docker environment");
	return "native";
}

export function assertDockerRuntime(context = "Telclaude runtime"): void {
	if (isDockerEnvironment()) {
		return;
	}
	throw new Error(getDockerRuntimeRequirementMessage(context));
}

/**
 * Check if SDK sandbox should be enabled for current environment.
 */
export function shouldEnableSdkSandbox(): boolean {
	return getSandboxMode() === "native";
}
