import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import {
	DEFAULT_HERMES_CONTAINED_IP,
	DEFAULT_HERMES_RELAY_IP,
} from "../../src/hermes/runtime-network.js";
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
  tc-hermes-contained:
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
  tc-hermes-contained:
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

	it("flags permissive network mode and sensitive env exposure for runtime services", () => {
		const fixture = createFixture({
			composeContent: `
services:
  tc-hermes-contained:
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
  tc-hermes-contained:
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
		const socialHermes = serviceBlock(compose, "tc-hermes-social");
		const telclaudeEnv = envMap(listValues(telclaude, "environment"));
		const hermesEnv = envMap(listValues(hermes, "environment"));
		const socialHermesEnv = envMap(listValues(socialHermes, "environment"));
		const requiredApiKey =
			"${TELCLAUDE_HERMES_API_SERVER_KEY:?generate an ephemeral key for this compose up}";
		const requiredSocialApiKey =
			"${TELCLAUDE_HERMES_SOCIAL_API_SERVER_KEY:?generate an ephemeral social key for this compose up}";

		expect(telclaude).toContain("tc-hermes-contained:");
		expect(telclaude).toContain("tc-hermes-social:");
		expect(telclaude).toContain("condition: service_started");
		expect(telclaude).not.toContain("condition: service_healthy");
		expect(telclaude).toContain("hermes-private-net:");
		expect(telclaude).toContain("ipv4_address: ${TELCLAUDE_HERMES_RELAY_IP:-172.30.92.10}");
		expect(DEFAULT_HERMES_RELAY_IP).toBe("172.30.92.10");
		expect(telclaude).toContain("hermes-social-net:");
		expect(telclaude).toContain("ipv4_address: ${TELCLAUDE_HERMES_SOCIAL_RELAY_IP:-172.30.93.10}");
		expect(listValues(telclaude, "tmpfs")).toEqual([
			"/tmp:size=512M,mode=1777",
			"/home/node:size=256M,uid=1000,gid=1000,mode=0755",
			"/run/telclaude:size=1M,uid=1000,gid=1000,mode=0700,noexec",
		]);
		expect(hermes).toContain("hermes-private-net:");
		expect(hermes).toContain("ipv4_address: ${TELCLAUDE_HERMES_CONTAINED_IP:-172.30.92.11}");
		expect(DEFAULT_HERMES_CONTAINED_IP).toBe("172.30.92.11");
		expect(socialHermes).toContain("hermes-social-net:");
		expect(socialHermes).toContain("ipv4_address: ${TELCLAUDE_HERMES_SOCIAL_IP:-172.30.93.11}");
		expect(compose).toContain("name: telclaude-hermes-private");
		expect(compose).toContain("name: telclaude-hermes-social");
		expect(compose).toContain("internal: true");
		expect(compose).toContain("subnet: ${TELCLAUDE_HERMES_RELAY_SUBNET:-172.30.92.0/24}");
		expect(compose).toContain("subnet: ${TELCLAUDE_HERMES_SOCIAL_RELAY_SUBNET:-172.30.93.0/24}");

		expect(telclaudeEnv.TELCLAUDE_HERMES_API_KEY).toBe(requiredApiKey);
		expect(telclaudeEnv.TELCLAUDE_HERMES_API_BASE_URL).toBe("http://tc-hermes-contained:8642");
		expect(telclaudeEnv.TELCLAUDE_HERMES_SOCIAL_API_KEY).toBe(requiredSocialApiKey);
		expect(telclaudeEnv.TELCLAUDE_HERMES_SOCIAL_API_BASE_URL).toBe("http://tc-hermes-social:8642");
		expect(telclaudeEnv.TELCLAUDE_HERMES_LIVE_MCP_NETWORK).toBe("telclaude-hermes-private");
		expect(telclaudeEnv.TELCLAUDE_HERMES_LIVE_MCP_ADDITIONAL_BINDS).toBe(
			"${TELCLAUDE_HERMES_LIVE_MCP_ADDITIONAL_BINDS:-${TELCLAUDE_HERMES_SOCIAL_RELAY_IP:-172.30.93.10}@telclaude-hermes-social}",
		);
		expect(telclaudeEnv.TELCLAUDE_HERMES_LIVE_MCP_ALLOWED_PEERS).toBe(
			"${TELCLAUDE_HERMES_LIVE_MCP_ALLOWED_PEERS:-172.30.92.11,172.30.93.11}",
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
		expect(telclaudeEnv.TELCLAUDE_HERMES_MCP_RELAY_TOKEN).toBe(
			"${TELCLAUDE_HERMES_MCP_RELAY_TOKEN:?set relay-scoped Hermes MCP transport token}",
		);
		expect(telclaudeEnv.TELCLAUDE_HERMES_SKILL_CATALOG_DIR).toBe(
			"/opt/data/telclaude-hermes-skill-catalog",
		);
		expect(telclaudeEnv.TELCLAUDE_HERMES_SOCIAL_SKILL_CATALOG_DIR).toBe(
			"/opt/data/telclaude-hermes-social-skill-catalog",
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
			TELCLAUDE_HERMES_MCP_RELAY_TOKEN:
				"${TELCLAUDE_HERMES_MCP_RELAY_TOKEN:?set relay-scoped Hermes MCP transport token}",
			TELCLAUDE_HERMES_MCP_STARTUP_WAIT_SECONDS: `\${TELCLAUDE_HERMES_MCP_STARTUP_WAIT_SECONDS:-300}`,
			TELCLAUDE_HERMES_MCP_URL: "http://telclaude:8793/mcp",
			TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN:
				"${TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN:?set relay-scoped OpenAI Codex proxy token}",
			TELCLAUDE_INTERNAL_HOSTS: "telclaude",
			TELCLAUDE_FIREWALL_SKIP_ADDITIONAL_DOMAINS: "1",
			TELCLAUDE_HERMES_SKILL_ALLOWLIST: "/tmp/telclaude-hermes-contained-skills.allowlist",
			TELCLAUDE_HERMES_SOURCE_SKILLS_DIR: "/opt/hermes/skills",
			TELCLAUDE_HERMES_SKILL_CATALOG_MOUNT: "/opt/data/telclaude-hermes-skill-catalog",
			NO_COLOR: "1",
		});
		expect(socialHermesEnv).toEqual({
			API_SERVER_ENABLED: "true",
			API_SERVER_HOST: "0.0.0.0",
			API_SERVER_PORT: "8642",
			API_SERVER_KEY: requiredSocialApiKey,
			HERMES_HOME: "/home/hermes/.hermes-social",
			HOME: "/home/hermes",
			HERMES_INFERENCE_PROVIDER: "openai-codex",
			HERMES_INFERENCE_MODEL: "${TELCLAUDE_HERMES_SOCIAL_INFERENCE_MODEL:-gpt-5.5}",
			HERMES_CODEX_BASE_URL: "http://telclaude:8790/v1/openai-codex-proxy",
			TELCLAUDE_HERMES_MCP_RELAY_TOKEN:
				"${TELCLAUDE_HERMES_MCP_RELAY_TOKEN:?set relay-scoped Hermes MCP transport token}",
			TELCLAUDE_HERMES_MCP_STARTUP_WAIT_SECONDS: `\${TELCLAUDE_HERMES_MCP_STARTUP_WAIT_SECONDS:-300}`,
			TELCLAUDE_HERMES_MCP_URL: "http://telclaude:8793/mcp",
			TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN:
				"${TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN:?set relay-scoped OpenAI Codex proxy token}",
			TELCLAUDE_INTERNAL_HOSTS: "telclaude",
			TELCLAUDE_FIREWALL_SKIP_ADDITIONAL_DOMAINS: "1",
			TELCLAUDE_HERMES_SKILL_ALLOWLIST: "/tmp/telclaude-hermes-social-skills.allowlist",
			TELCLAUDE_HERMES_SOURCE_SKILLS_DIR: "/opt/hermes/skills",
			TELCLAUDE_HERMES_SKILL_CATALOG_MOUNT: "/opt/data/telclaude-hermes-social-skill-catalog",
			NO_COLOR: "1",
		});
		expect(listValues(hermes, "volumes")).toEqual([
			"./hermes-contained-entrypoint.sh:/tmp/telclaude-hermes-contained-entrypoint.sh:ro",
			"./hermes-contained-skills.allowlist:/tmp/telclaude-hermes-contained-skills.allowlist:ro",
			"..:/opt/data/telclaude-runner:ro",
			"telclaude-hermes-skill-catalog:/opt/data/telclaude-hermes-skill-catalog:ro",
		]);
		expect(listValues(socialHermes, "volumes")).toEqual([
			"./hermes-contained-entrypoint.sh:/tmp/telclaude-hermes-contained-entrypoint.sh:ro",
			"./hermes-social-skills.allowlist:/tmp/telclaude-hermes-social-skills.allowlist:ro",
			"..:/opt/data/telclaude-runner:ro",
			"telclaude-hermes-social-skill-catalog:/opt/data/telclaude-hermes-social-skill-catalog:ro",
		]);
		expect(listValues(telclaude, "volumes")).toEqual([
			"telclaude-hermes-skill-catalog:/opt/data/telclaude-hermes-skill-catalog:rw",
			"telclaude-hermes-social-skill-catalog:/opt/data/telclaude-hermes-social-skill-catalog:rw",
		]);
		expect(hermes).not.toContain("telclaude-hermes-social-skill-catalog");
		expect(socialHermes).not.toContain("telclaude-hermes-skill-catalog:");
		expect(compose).toContain("telclaude-hermes-skill-catalog:");
		expect(compose).toContain("telclaude-hermes-social-skill-catalog:");
		expect(
			fs.readFileSync(path.resolve(process.cwd(), "docker/hermes-social-skills.allowlist"), "utf8"),
		).toContain("social-media/xurl");
		expect(
			fs.readFileSync(path.resolve(process.cwd(), "docker/hermes-social-skills.allowlist"), "utf8"),
		).not.toContain("github/github-auth");

		for (const block of [hermes, socialHermes]) {
			expect(block).toContain("image: ${TELCLAUDE_HERMES_IMAGE:-nousresearch/hermes-agent@sha256:");
			expect(block).toContain(
				'entrypoint: ["/bin/sh", "/tmp/telclaude-hermes-contained-entrypoint.sh"]',
			);
			expect(block).toContain('command: ["gateway", "run"]');
			expect(block).not.toMatch(/image:.*:latest\b/);
			expect(block).toContain('user: "10000:10000"');
			expect(listValues(block, "cap_drop")).toEqual(["ALL"]);
			expect(block).not.toMatch(/^\s+cap_add:/m);
			expect(block).not.toMatch(/^\s+privileged:\s*true\b/m);
			expect(listValues(block, "security_opt")).toEqual(["no-new-privileges:true"]);
			expect(block).not.toContain("seccomp:unconfined");
			expect(block).not.toContain("apparmor:unconfined");
			expect(block).toContain("read_only: true");
			expect(block).not.toMatch(/^\s+env_file:/m);
			expect(listValues(block, "extra_hosts")).toEqual([
				'"api.anthropic.com:192.0.2.1"',
				'"api.openai.com:192.0.2.1"',
				'"auth.openai.com:192.0.2.1"',
				'"chatgpt.com:192.0.2.1"',
				'"generativelanguage.googleapis.com:192.0.2.1"',
				'"openrouter.ai:192.0.2.1"',
				'"api.x.ai:192.0.2.1"',
			]);
			const tmpfs = listValues(block, "tmpfs");
			expect(tmpfs).toEqual(
				expect.arrayContaining([
					"/tmp:size=128M,mode=1777,noexec",
					"/run:size=16M,uid=10000,gid=10000,mode=0755,noexec",
					"/home/hermes:size=512M,uid=10000,gid=10000,mode=0700,noexec",
				]),
			);
			expect(tmpfs).toContain(
				block === hermes
					? "/home/hermes/.hermes:size=128M,uid=10000,gid=10000,mode=0700,noexec"
					: "/home/hermes/.hermes-social:size=128M,uid=10000,gid=10000,mode=0700,noexec",
			);
			expect(tmpfs).toContain(
				block === hermes
					? "/home/hermes/.hermes/skills:size=1M,uid=0,gid=10000,mode=0550,noexec"
					: "/home/hermes/.hermes-social/skills:size=1M,uid=0,gid=10000,mode=0550,noexec",
			);
			expect(block).toContain("start_period: 360s");
			expect(block).toContain("http://127.0.0.1:8642/health");
		}

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
		for (const key of [
			...Object.keys(telclaudeEnv),
			...Object.keys(hermesEnv),
			...Object.keys(socialHermesEnv),
		]) {
			if (
				key === "TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN" &&
				(hermesEnv[key] ===
					"${TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN:?set relay-scoped OpenAI Codex proxy token}" ||
					socialHermesEnv[key] ===
						"${TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN:?set relay-scoped OpenAI Codex proxy token}")
			) {
				continue;
			}
			if (
				key === "TELCLAUDE_HERMES_MCP_RELAY_TOKEN" &&
				(hermesEnv[key] ===
					"${TELCLAUDE_HERMES_MCP_RELAY_TOKEN:?set relay-scoped Hermes MCP transport token}" ||
					socialHermesEnv[key] ===
						"${TELCLAUDE_HERMES_MCP_RELAY_TOKEN:?set relay-scoped Hermes MCP transport token}")
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
					"TELCLAUDE_HERMES_SOCIAL_API_SERVER_KEY",
					"TELCLAUDE_HERMES_MCP_RELAY_TOKEN",
					"TELCLAUDE_HERMES_PROVIDER_WRITE_APPROVER_ACTOR_ID",
					"OPERATOR_RPC_AGENT_PUBLIC_KEY",
					"OPERATOR_RPC_RELAY_PRIVATE_KEY",
					"TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN",
				]).toContain(variableName);
			}
		}
	});

	it("keeps the William deploy env writer pinned to the live-MCP RFC1918 tuple", () => {
		const workflow = fs.readFileSync(
			path.resolve(process.cwd(), ".github/workflows/ci.yml"),
			"utf8",
		);
		const step = workflowStep(workflow, "Persist William Hermes deploy keys");
		expect(step).toContain("hermes_private_subnet='172.30.92.0/24'");
		expect(step).toContain("hermes_social_subnet='172.30.93.0/24'");
		expect(step).toContain('hermes_private_prefix="${hermes_private_subnet%.*}"');
		expect(step).toContain('hermes_social_prefix="${hermes_social_subnet%.*}"');
		expect(step).toContain('hermes_relay_ip="${hermes_private_prefix}.10"');
		expect(step).toContain('hermes_social_relay_ip="${hermes_social_prefix}.10"');
		expect(step).toContain('hermes_contained_ip="${hermes_private_prefix}.11"');
		expect(step).toContain('hermes_social_ip="${hermes_social_prefix}.11"');
		expect(step).toContain(
			'hermes_live_mcp_additional_binds="${hermes_social_relay_ip}@telclaude-hermes-social"',
		);
		expect(step).toContain(
			'hermes_live_mcp_allowed_peers="${hermes_contained_ip},${hermes_social_ip}"',
		);
		const required = [
			["TELCLAUDE_HERMES_RELAY_SUBNET", "hermes_private_subnet"],
			["TELCLAUDE_HERMES_SOCIAL_RELAY_SUBNET", "hermes_social_subnet"],
			["TELCLAUDE_HERMES_RELAY_IP", "hermes_relay_ip"],
			["TELCLAUDE_HERMES_SOCIAL_RELAY_IP", "hermes_social_relay_ip"],
			["TELCLAUDE_HERMES_CONTAINED_IP", "hermes_contained_ip"],
			["TELCLAUDE_HERMES_SOCIAL_IP", "hermes_social_ip"],
			["TELCLAUDE_HERMES_LIVE_MCP_ENABLED", "hermes_live_mcp_enabled"],
			["TELCLAUDE_HERMES_LIVE_MCP_ADMIN_ENABLED", "hermes_live_mcp_admin_enabled"],
			["TELCLAUDE_HERMES_LIVE_MCP_HOST", "hermes_relay_ip"],
			["TELCLAUDE_HERMES_LIVE_MCP_ADDITIONAL_BINDS", "hermes_live_mcp_additional_binds"],
			["TELCLAUDE_HERMES_LIVE_MCP_ALLOWED_PEERS", "hermes_live_mcp_allowed_peers"],
			["TELCLAUDE_HERMES_SERVED_MCP_OFF_DOMAIN_PEER_IP", "hermes_social_ip"],
		] as const;
		const shellPattern = step.match(/shell_key_pattern='([^']+)'/)?.[1] ?? "";
		const composePattern = step.match(/compose_key_pattern='([^']+)'/)?.[1] ?? "";

		for (const [key, variable] of required) {
			const suffix = key.replace("TELCLAUDE_HERMES_", "");
			expect(shellPattern).toContain(suffix);
			expect(composePattern).toContain(suffix);
			expect(step).toContain(`printf 'export ${key}=%s\\n' "$${variable}"`);
			expect(step).toContain(`printf '${key}=%s\\n' "$${variable}"`);
		}
		for (const [key, variable] of [
			["TELCLAUDE_WHATSAPP_BRIDGE_SECRET", "whatsapp_bridge_secret"],
			["TELCLAUDE_WHATSAPP_INBOUND_SECRET", "whatsapp_inbound_secret"],
		] as const) {
			expect(step).toContain(`${variable}="$(read_deploy_env ${key} || true)"`);
			expect(step).toContain(`[ -n "$${variable}" ] || ${variable}="$(openssl rand -hex 32)"`);
			expect(step).toContain(`printf 'export ${key}=%q\\n' "$${variable}"`);
			expect(step).toContain(`printf '${key}=%s\\n' "$${variable}"`);
		}
		expect(shellPattern).toContain("TELCLAUDE_WHATSAPP_(BRIDGE_SECRET|INBOUND_SECRET)");
		expect(composePattern).toContain("TELCLAUDE_WHATSAPP_(BRIDGE_SECRET|INBOUND_SECRET)");
		expect(step).not.toContain("LIVE_MCP_ENABLED=0");
		expect(step).not.toContain("192.0.2.10");
		expect(step).not.toContain("192.0.3.10");
		expect(step).not.toContain("172.30.92.10");
		expect(step).not.toContain("172.30.93.10");
		expect(step).not.toContain("172.30.92.11");
		expect(step).not.toContain("172.30.93.11");
	});

	it("starts the William WhatsApp bridge profile and health-gates the sidecar", () => {
		const workflow = fs.readFileSync(
			path.resolve(process.cwd(), ".github/workflows/ci.yml"),
			"utf8",
		);
		const hookStep = workflowStep(workflow, "Install William post-deploy health gate");
		const deployStep = workflowStep(workflow, "Build and deploy");

		expect(hookStep).toContain("compose_profiles=(--profile whatsapp)");
		expect(hookStep).toContain("telclaude-whatsapp-bridge");
		expect(hookStep).toContain('docker compose "${compose_files[@]}" "${compose_profiles[@]}" ps');
		expect(deployStep).toContain("compose_profiles=(--profile whatsapp)");
		expect(deployStep).toContain("telclaude-whatsapp-bridge");
		expect(deployStep).toContain(
			'docker compose "${compose_files[@]}" "${compose_profiles[@]}" down --remove-orphans',
		);
		expect(deployStep).toContain(
			'docker compose "${compose_files[@]}" "${compose_profiles[@]}" up -d --remove-orphans --wait --wait-timeout 480',
		);
	});

	it("runs official Hermes verify-live runtime gates from the William deploy context", () => {
		const workflow = fs.readFileSync(
			path.resolve(process.cwd(), ".github/workflows/ci.yml"),
			"utf8",
		);
		const setupStep = workflowStep(workflow, "Setup Node.js for deploy verification");
		const installStep = workflowStep(workflow, "Install deploy verification dependencies");
		const buildStep = workflowStep(workflow, "Build and deploy");
		const verifyStep = workflowStep(workflow, "Verify live Hermes runtime gates");

		expect(setupStep).toContain("actions/setup-node@48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e");
		expect(setupStep).toContain("node-version: 22");
		expect(installStep).toContain("corepack enable");
		expect(installStep).toContain(
			'package_manager="$(node -p "require(\'./package.json\').packageManager")"',
		);
		expect(installStep).toContain('corepack prepare "$package_manager" --activate');
		expect(installStep).toContain("pnpm install --frozen-lockfile");
		expect(verifyStep).toContain(
			"pnpm --silent dev hermes verify-live --json --skip-mcp --skip-turn --timeout-ms 120000",
		);
		expect(verifyStep).toContain("verify_live_runtime_status=");
		expect(verifyStep).toContain("telclaude.hermes.verify-live.v1");
		expect(verifyStep).toContain("findVerifyLiveReport");
		expect(verifyStep).toContain("verify-live report JSON with expected schemaVersion was not found");
		expect(verifyStep).toContain("verify-live runtime output");
		expect(verifyStep).not.toContain("--skip-runtime-toolset");
		expect(verifyStep).not.toContain("--skip-runtime-skill-manage");
		expect(workflow.indexOf(buildStep)).toBeLessThan(workflow.indexOf(verifyStep));
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
	const start = lines.indexOf(`  ${serviceName}:`);
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

function workflowStep(workflow: string, name: string): string {
	const marker = `      - name: ${name}`;
	const start = workflow.indexOf(marker);
	expect(start).toBeGreaterThanOrEqual(0);
	const rest = workflow.slice(start);
	const next = rest.indexOf("\n      - name: ", 1);
	return next === -1 ? rest : rest.slice(0, next);
}
