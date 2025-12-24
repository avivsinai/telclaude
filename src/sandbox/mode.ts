/**
 * Sandbox mode detection.
 *
 * Determines whether to use Docker-provided isolation or SDK's native sandbox.
 *
 * Architecture:
 * - Docker mode: SDK sandbox DISABLED. Docker container provides isolation.
 * - Native mode: SDK sandbox ENABLED. bubblewrap (Linux) or Seatbelt (macOS).
 *
 * This follows Anthropic's recommended pattern: use ONE isolation boundary,
 * not layered sandboxes which cause complexity and compatibility issues.
 */

import fs from "node:fs";
import { getChildLogger } from "../logging.js";

const logger = getChildLogger({ module: "sandbox-mode" });

export type SandboxMode = "docker" | "native";

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
		logger.debug("detected Docker environment - SDK sandbox will be disabled");
		return "docker";
	}

	logger.debug("detected native environment - SDK sandbox will be enabled");
	return "native";
}

/**
 * Check if SDK sandbox should be enabled for current environment.
 */
export function shouldEnableSdkSandbox(): boolean {
	return getSandboxMode() === "native";
}
