import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { auditSandboxPosture } from "../../src/sandbox/validate-config.js";

const TEMP_DIRS: string[] = [];

function createFixture(params: {
	composeContent: string;
	envContent?: string;
}): {
	rootDir: string;
	composePath: string;
	envPath: string;
} {
	const rootDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-sandbox-audit-"));
	TEMP_DIRS.push(rootDir);

	const dockerDir = path.join(rootDir, "docker");
	fs.mkdirSync(dockerDir, { recursive: true });

	const composePath = path.join(dockerDir, "docker-compose.yml");
	fs.writeFileSync(composePath, params.composeContent, "utf8");

	const envPath = path.join(dockerDir, ".env");
	fs.writeFileSync(envPath, params.envContent ?? "", "utf8");

	return { rootDir, composePath, envPath };
}

describe("auditSandboxPosture", () => {
	afterEach(() => {
		for (const dir of TEMP_DIRS.splice(0, TEMP_DIRS.length)) {
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	it("flags dangerous compose settings and docker socket mounts", () => {
		const fixture = createFixture({
			composeContent: `
services:
  telclaude-agent:
    network_mode: host
    privileged: true
    security_opt:
      - seccomp:unconfined
      - apparmor:unconfined
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:rw
`,
		});

		const findings = auditSandboxPosture({
			composePath: fixture.composePath,
			envPath: fixture.envPath,
		});

		expect(findings.some((f) => f.message.includes("network_mode=host"))).toBe(true);
		expect(findings.some((f) => f.message.includes("privileged=true"))).toBe(true);
		expect(findings.some((f) => f.message.includes("seccomp:unconfined"))).toBe(true);
		expect(findings.some((f) => f.message.includes("apparmor:unconfined"))).toBe(true);
		expect(findings.some((f) => f.message.includes("Docker socket"))).toBe(true);
		expect(findings.every((f) => f.severity === "critical")).toBe(true);
	});

	it("detects symlink bind-mount escape to blocked host paths", () => {
		const fixture = createFixture({
			composeContent: `
services:
  telclaude-agent:
    volumes:
      - ./escape-link:/workspace:ro
`,
		});
		const escapeLink = path.join(path.dirname(fixture.composePath), "escape-link");
		fs.symlinkSync("/etc", escapeLink);

		const findings = auditSandboxPosture({
			composePath: fixture.composePath,
			envPath: fixture.envPath,
		});

		expect(findings.some((f) => f.message.includes("symlink"))).toBe(true);
		expect(findings.some((f) => f.message.includes("/etc"))).toBe(true);
	});

	it("flags permissive network mode and sensitive env exposure for agent services", () => {
		const fixture = createFixture({
			composeContent: `
services:
  telclaude-agent:
    environment:
      - TELEGRAM_BOT_TOKEN=\${TELEGRAM_BOT_TOKEN:-}
`,
			envContent: `
TELCLAUDE_NETWORK_MODE=permissive
`,
		});

		const findings = auditSandboxPosture({
			composePath: fixture.composePath,
			envPath: fixture.envPath,
		});

		expect(findings.some((f) => f.message.includes("TELEGRAM_BOT_TOKEN"))).toBe(true);
		expect(findings.some((f) => f.message.includes("TELCLAUDE_NETWORK_MODE=permissive"))).toBe(
			true,
		);
		expect(findings.every((f) => f.severity === "warning")).toBe(true);
	});

	it("returns no findings for clean compose/env posture", () => {
		const fixture = createFixture({
			composeContent: `
services:
  telclaude-agent:
    security_opt:
      - no-new-privileges:true
    volumes:
      - ./telclaude.json:/data/telclaude.json:ro
`,
			envContent: `
TELCLAUDE_LOG_LEVEL=info
`,
		});

		const findings = auditSandboxPosture({
			composePath: fixture.composePath,
			envPath: fixture.envPath,
		});

		expect(findings).toEqual([]);
	});
});
