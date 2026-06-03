import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { auditSandboxPosture } from "../../src/sandbox/validate-config.js";

const TEMP_DIRS: string[] = [];

function createFixture(params: { composeContent: string; envContent?: string }): {
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

	it("keeps the Hermes compose overlay raw-provider-secretless and contained", () => {
		const composePath = path.resolve(process.cwd(), "docker/docker-compose.hermes.yml");
		const compose = fs.readFileSync(composePath, "utf8");
		const telclaude = serviceBlock(compose, "telclaude");
		const hermes = serviceBlock(compose, "tc-hermes-contained");
		const telclaudeEnv = envMap(listValues(telclaude, "environment"));
		const hermesEnv = envMap(listValues(hermes, "environment"));
		const requiredApiKey =
			"${TELCLAUDE_HERMES_API_SERVER_KEY:?generate an ephemeral key for this compose up}";

		expect(telclaude).toContain("tc-hermes-contained:");
		expect(telclaude).toContain("condition: service_healthy");
		expect(telclaude).toContain("hermes-relay-net:");
		expect(telclaude).toContain("ipv4_address: ${TELCLAUDE_HERMES_RELAY_IP:-192.0.2.10}");
		expect(listValues(telclaude, "tmpfs")).toEqual([
			"/tmp:size=512M,mode=1777",
			"/home/node:size=256M,uid=1000,gid=1000,mode=0755",
			"/run/telclaude:size=1M,uid=1000,gid=1000,mode=0700,noexec",
		]);
		expect(hermes).toContain("hermes-relay-net:");
		expect(hermes).toContain("ipv4_address: ${TELCLAUDE_HERMES_CONTAINED_IP:-192.0.2.11}");
		expect(compose).toContain("name: telclaude-hermes-relay");
		expect(compose).toContain("internal: true");
		expect(compose).toContain("subnet: ${TELCLAUDE_HERMES_RELAY_SUBNET:-192.0.2.0/24}");

		expect(telclaudeEnv.TELCLAUDE_HERMES_API_KEY).toBe(requiredApiKey);
		expect(telclaudeEnv.TELCLAUDE_HERMES_LIVE_MCP_ALLOWED_PEERS).toBe(
			"${TELCLAUDE_HERMES_LIVE_MCP_ALLOWED_PEERS:-192.0.2.11}",
		);
		expect(telclaudeEnv.TELCLAUDE_HERMES_LIVE_MCP_ADMIN_ENABLED).toBe(
			"${TELCLAUDE_HERMES_LIVE_MCP_ADMIN_ENABLED:-0}",
		);
		expect(telclaudeEnv.TELCLAUDE_HERMES_LIVE_MCP_ADMIN_SOCKET).toBe(
			"${TELCLAUDE_HERMES_LIVE_MCP_ADMIN_SOCKET:-/run/telclaude/hermes-live-mcp-admin.sock}",
		);
		expect(telclaudeEnv.OPERATOR_RPC_AGENT_PUBLIC_KEY).toBe(
			"${OPERATOR_RPC_AGENT_PUBLIC_KEY:?set from pnpm dev keygen operator}",
		);
		expect(telclaudeEnv.OPERATOR_RPC_RELAY_PRIVATE_KEY).toBe(
			"${OPERATOR_RPC_RELAY_PRIVATE_KEY:?set from pnpm dev keygen operator}",
		);
		expect(telclaudeEnv.TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN).toBe(
			"${TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN:?set relay-scoped OpenAI Codex proxy token}",
		);
		expect(hermesEnv).toEqual({
			API_SERVER_ENABLED: "true",
			API_SERVER_HOST: "0.0.0.0",
			API_SERVER_PORT: "8642",
			API_SERVER_KEY: requiredApiKey,
			HERMES_HOME: "/home/hermes/.hermes",
			HOME: "/home/hermes",
			HERMES_INFERENCE_PROVIDER: "openai-codex",
			HERMES_INFERENCE_MODEL: "${TELCLAUDE_HERMES_INFERENCE_MODEL:-gpt-5.5}",
			HERMES_CODEX_BASE_URL: "http://telclaude:8790/v1/openai-codex-proxy",
			TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN:
				"${TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN:?set relay-scoped OpenAI Codex proxy token}",
			TELCLAUDE_INTERNAL_HOSTS: "telclaude",
			TELCLAUDE_HERMES_SKILL_ALLOWLIST: "/tmp/telclaude-hermes-contained-skills.allowlist",
			TELCLAUDE_HERMES_SOURCE_SKILLS_DIR: "/opt/hermes/skills",
			NO_COLOR: "1",
		});

		expect(hermes).toContain("image: ${TELCLAUDE_HERMES_IMAGE:-nousresearch/hermes-agent@sha256:");
		expect(hermes).toContain(
			'entrypoint: ["/bin/sh", "/tmp/telclaude-hermes-contained-entrypoint.sh"]',
		);
		expect(hermes).toContain('command: ["gateway", "run"]');
		expect(hermes).not.toMatch(/image:.*:latest\b/);
		expect(hermes).toContain('user: "10000:10000"');
		expect(listValues(hermes, "cap_drop")).toEqual(["ALL"]);
		expect(hermes).not.toMatch(/^\s+cap_add:/m);
		expect(hermes).not.toMatch(/^\s+privileged:\s*true\b/m);
		expect(listValues(hermes, "security_opt")).toEqual(["no-new-privileges:true"]);
		expect(hermes).not.toContain("seccomp:unconfined");
		expect(hermes).not.toContain("apparmor:unconfined");
		expect(hermes).toContain("read_only: true");
		expect(listValues(hermes, "volumes")).toEqual([
			"./hermes-contained-entrypoint.sh:/tmp/telclaude-hermes-contained-entrypoint.sh:ro",
			"./hermes-contained-skills.allowlist:/tmp/telclaude-hermes-contained-skills.allowlist:ro",
		]);
		expect(hermes).not.toMatch(/^\s+env_file:/m);
		expect(listValues(hermes, "extra_hosts")).toEqual([
			'"api.anthropic.com:192.0.2.1"',
			'"api.openai.com:192.0.2.1"',
			'"auth.openai.com:192.0.2.1"',
			'"chatgpt.com:192.0.2.1"',
			'"generativelanguage.googleapis.com:192.0.2.1"',
			'"openrouter.ai:192.0.2.1"',
			'"api.x.ai:192.0.2.1"',
		]);
		expect(listValues(hermes, "tmpfs")).toEqual([
			"/tmp:size=128M,mode=1777,noexec",
			"/run:size=16M,uid=10000,gid=10000,mode=0755,noexec",
			"/home/hermes:size=512M,uid=10000,gid=10000,mode=0700,noexec",
		]);
		expect(hermes).toContain("http://127.0.0.1:8642/health");

		const forbiddenEnvKeys = [
			"ANTHROPIC_API_KEY",
			"OPENAI_API_KEY",
			"GITHUB_TOKEN",
			"GH_TOKEN",
			"CLAUDE_CODE_OAUTH_TOKEN",
			"TELEGRAM_BOT_TOKEN",
			"SECRETS_ENCRYPTION_KEY",
			"TOTP_ENCRYPTION_KEY",
			"VAULT_ENCRYPTION_KEY",
		];
		for (const key of [...Object.keys(telclaudeEnv), ...Object.keys(hermesEnv)]) {
			if (
				key === "TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN" &&
				hermesEnv[key] ===
					"${TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN:?set relay-scoped OpenAI Codex proxy token}"
			) {
				continue;
			}
			expect(forbiddenEnvKeys).not.toContain(key);
		}
		for (const interpolation of compose.matchAll(/\$\{([^}:]+)(?::[^}]*)?\}/g)) {
			const variableName = interpolation[1] ?? "";
			if (/(KEY|SECRET|TOKEN|OAUTH|VAULT|PROVIDER)/.test(variableName)) {
				expect([
					"TELCLAUDE_HERMES_API_SERVER_KEY",
					"OPERATOR_RPC_AGENT_PUBLIC_KEY",
					"OPERATOR_RPC_RELAY_PRIVATE_KEY",
					"TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN",
				]).toContain(variableName);
			}
		}
	});

	it("keeps the standalone Hermes CLI proof runner off host-gateway smoke paths", () => {
		const scriptPath = path.resolve(process.cwd(), "scripts/hermes-contained-cli-probe.sh");
		const script = fs.readFileSync(scriptPath, "utf8");

		expect(script).toContain("network inspect \"$NETWORK_NAME\" --format '{{json .}}'");
		expect(script).toContain('network.get("Internal") is not True');
		expect(script).toContain("requires relay container 'telclaude' on the network");
		expect(script).toContain("unexpected pre-existing containers");
		expect(script).toContain("x-telclaude-model-relay-observed-peer-address");
		expect(script).toContain('"containerIpAddress": container_ip');
		expect(script).toContain('"provenanceSource": "docker-inspect-container-dns-and-relay-peer"');
		expect(script).not.toContain('network create "$NETWORK_NAME"');
		expect(script).not.toContain("telclaude:host-gateway");
		expect(script).not.toContain("--network host");
	});
});

function serviceBlock(compose: string, serviceName: string): string {
	const lines = compose.split(/\r?\n/);
	const start = lines.findIndex((line) => line === `  ${serviceName}:`);
	if (start < 0) throw new Error(`Missing service ${serviceName}`);
	let end = lines.length;
	for (let index = start + 1; index < lines.length; index += 1) {
		if (/^ {2}[A-Za-z0-9_-]+:\s*$/.test(lines[index] ?? "")) {
			end = index;
			break;
		}
		if (/^[A-Za-z0-9_-]+:\s*$/.test(lines[index] ?? "")) {
			end = index;
			break;
		}
	}
	return lines.slice(start, end).join("\n");
}

function listValues(block: string, key: string): string[] {
	const lines = block.split(/\r?\n/);
	const keyIndex = lines.findIndex((line) => {
		const trimmed = line.trim();
		return trimmed === `${key}:` || trimmed.startsWith(`${key}: `);
	});
	if (keyIndex < 0) return [];
	const values: string[] = [];
	for (let index = keyIndex + 1; index < lines.length; index += 1) {
		const line = lines[index] ?? "";
		if (/^\s{4}[A-Za-z0-9_-]+:/.test(line)) break;
		const match = line.match(/^\s*-\s+(.*)$/);
		if (match?.[1]) values.push(match[1]);
	}
	return values;
}

function envMap(entries: string[]): Record<string, string> {
	return Object.fromEntries(
		entries.map((entry) => {
			const separator = entry.indexOf("=");
			if (separator < 1) throw new Error(`Invalid environment entry: ${entry}`);
			return [entry.slice(0, separator), entry.slice(separator + 1)];
		}),
	);
}
