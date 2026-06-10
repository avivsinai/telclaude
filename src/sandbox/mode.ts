/**
 * Sandbox mode detection.
 *
 * Determines whether the relay process is running inside Docker or on the host.
 *
 * Architecture:
 * - Docker mode: the relay container provides process-level isolation.
 * - Native mode: the relay process is host-local; LLM/persona execution still
 *   routes through the contained Hermes runtime.
 *
 * This is posture detection only; runtime execution is always Hermes-wrapped.
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
		logger.debug("detected Docker environment");
		return "docker";
	}

	logger.debug("detected native environment");
	return "native";
}
