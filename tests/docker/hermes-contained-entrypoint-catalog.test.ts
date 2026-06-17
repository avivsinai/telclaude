import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { verifyOpenAiCodexPeerBoundProxyToken } from "../../src/relay/openai-codex-proxy.js";

const repoRoot = path.resolve(import.meta.dirname, "../..");
const entrypointPath = path.join(repoRoot, "docker/hermes-contained-entrypoint.sh");
const relayProxyUrl = "http://telclaude:8790/v1/openai-codex-proxy";
const mcpRelayUrl = "http://telclaude:8793/mcp";

let tempRoot = "";

afterEach(() => {
	if (tempRoot && fs.existsSync(tempRoot)) {
		makeTreeWritable(tempRoot);
		fs.rmSync(tempRoot, { recursive: true, force: true });
	}
});

function makeTreeWritable(root: string): void {
	for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
		const fullPath = path.join(root, entry.name);
		if (entry.isDirectory()) makeTreeWritable(fullPath);
		if (!entry.isSymbolicLink()) fs.chmodSync(fullPath, entry.isDirectory() ? 0o700 : 0o600);
	}
	fs.chmodSync(root, 0o700);
}

function makeMount(): string {
	tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-entrypoint-catalog-"));
	const mount = path.join(tempRoot, "catalog");
	fs.mkdirSync(path.join(mount, "skills"), { recursive: true });
	return mount;
}

function writeSkill(mount: string, name: string): string {
	const dir = path.join(mount, "skills", name);
	fs.mkdirSync(dir, { recursive: true });
	fs.writeFileSync(
		path.join(dir, "SKILL.md"),
		`---\nname: ${name}\ndescription: Helps with ${name}\n---\n`,
	);
	return dir;
}

function runValidateCatalogOnly(mount: string): string {
	return execFileSync("sh", [entrypointPath, "validate-catalog-only"], {
		cwd: repoRoot,
		env: { ...process.env, TELCLAUDE_HERMES_SKILL_CATALOG_MOUNT: mount },
		stdio: "pipe",
		encoding: "utf8",
	});
}

function expectValidationDeath(mount: string, message: string): void {
	let stderr = "";
	try {
		runValidateCatalogOnly(mount);
	} catch (err) {
		stderr = String((err as { stderr?: unknown }).stderr ?? "");
	}
	expect(stderr).toContain(message);
}

describe("hermes-contained-entrypoint.sh validate-catalog-only", () => {
	it("reports disabled when the mount is absent", () => {
		tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-entrypoint-catalog-"));
		const output = runValidateCatalogOnly(path.join(tempRoot, "does-not-exist"));
		expect(output).toContain("catalog disabled");
	});

	it("reports enabled for a valid catalog mount", () => {
		const mount = makeMount();
		writeSkill(mount, "daily-brief");
		const output = runValidateCatalogOnly(mount);
		expect(output).toContain(`catalog enabled at ${path.join(mount, "skills")}`);
	});

	it("dies on a scripts/ directory inside a skill", () => {
		const mount = makeMount();
		const dir = writeSkill(mount, "scripted");
		fs.mkdirSync(path.join(dir, "scripts"));
		fs.writeFileSync(path.join(dir, "scripts", "x.py"), "print()\n");
		expectValidationDeath(mount, "contains a scripts/ directory: scripted");
	});

	it("dies on a symlink inside a skill", () => {
		const mount = makeMount();
		const dir = writeSkill(mount, "linked");
		fs.symlinkSync("/etc/hosts", path.join(dir, "hosts"));
		expectValidationDeath(mount, "contains a symlink: linked");
	});

	it("dies on an executable file inside a skill", () => {
		const mount = makeMount();
		const dir = writeSkill(mount, "execy");
		const tool = path.join(dir, "tool.md");
		fs.writeFileSync(tool, "text\n");
		fs.chmodSync(tool, 0o755);
		expectValidationDeath(mount, "contains an executable file: execy");
	});

	it("dies on dot-named and whitespace-named entries", () => {
		const mount = makeMount();
		writeSkill(mount, "good-skill");
		fs.mkdirSync(path.join(mount, "skills", ".sneaky"));
		expectValidationDeath(mount, "invalid catalog skill name: .sneaky");

		fs.rmSync(path.join(mount, "skills", ".sneaky"), { recursive: true, force: true });
		fs.mkdirSync(path.join(mount, "skills", "bad name"));
		expectValidationDeath(mount, "invalid catalog skill name: bad name");
	});

	it("dies on a skill without SKILL.md", () => {
		const mount = makeMount();
		fs.mkdirSync(path.join(mount, "skills", "hollow"));
		expectValidationDeath(mount, "catalog skill missing SKILL.md: hollow");
	});
});

describe("hermes-contained-entrypoint.sh catalog config merge", () => {
	it("keeps one skills: block and appends external_dirs conditionally", () => {
		const script = fs.readFileSync(entrypointPath, "utf8");

		// Exactly one skills: block in the generated config heredoc.
		expect(script.match(/^skills:$/gm)).toHaveLength(1);
		// creation_nudge_interval stays in the block; external_dirs joins it via the
		// conditional expansion rather than a second skills: key. The curated
		// bundled allowlist is always external; the relay catalog appends when mounted.
		expect(script).toContain(`  creation_nudge_interval: 0\${SKILLS_EXTERNAL_DIRS_BLOCK}`);
		expect(script).toContain('SKILLS_EXTERNAL_DIRS_BLOCK="');
		expect(script).toContain("  external_dirs:");
		expect(script).toContain(`    - \\"\${CURATED_SKILLS_DIR}\\"`);
		expect(script).toContain(`    - \\"\${CATALOG_SKILLS_DIR}\\"`);
		// Default mount path and validation wiring.
		expect(script).toContain(
			`SKILL_CATALOG_MOUNT=\${TELCLAUDE_HERMES_SKILL_CATALOG_MOUNT:-/opt/data/telclaude-hermes-skill-catalog}`,
		);
		expect(script).toContain("validate_catalog_skill_entry");
		// The catalog block is computed before the config heredoc is written.
		expect(script.indexOf('SKILLS_EXTERNAL_DIRS_BLOCK="')).toBeLessThan(
			script.indexOf(`cat > "\${HERMES_HOME}/config.yaml"`),
		);
	});
});

describe("hermes-contained-entrypoint.sh generated runtime profile custody", () => {
	it("does not write startup relay secrets into generated HERMES_HOME files", () => {
		tempRoot = fs.mkdtempSync("/tmp/hermes-entrypoint-profile-");
		const sourceSkills = path.join(tempRoot, "source-skills");
		const skillDir = path.join(sourceSkills, "productivity", "memory-search");
		const allowlistPath = path.join(tempRoot, "allowlist");
		const hermesHome = path.join(tempRoot, "home");
		const curatedSkills = path.join(tempRoot, "curated");
		const fakeBin = path.join(tempRoot, "bin");
		const codexRootToken = "relay-root-codex-token-sentinel-123456";
		const mcpTransportToken = "mcp-transport-token-sentinel-abcdef123456";
		const peerAddress = "172.30.92.11";

		fs.mkdirSync(skillDir, { recursive: true });
		fs.writeFileSync(path.join(skillDir, "SKILL.md"), "---\nname: memory-search\n---\n");
		fs.writeFileSync(allowlistPath, "productivity/memory-search\n");
		fs.mkdirSync(fakeBin, { recursive: true });
		fs.writeFileSync(
			path.join(fakeBin, "hostname"),
			[
				"#!/bin/sh",
				'if [ "$1" = "-i" ]; then',
				`  printf '%s\\n' '${peerAddress}'`,
				"  exit 0",
				"fi",
				'exec /bin/hostname "$@"',
				"",
			].join("\n"),
		);
		fs.chmodSync(path.join(fakeBin, "hostname"), 0o755);

		const output = execFileSync("sh", [entrypointPath, "provision-profile-only"], {
			cwd: repoRoot,
			env: {
				...process.env,
				PATH: `${fakeBin}:${process.env.PATH ?? ""}`,
				HERMES_HOME: hermesHome,
				HERMES_INFERENCE_PROVIDER: "openai-codex",
				HERMES_INFERENCE_MODEL: "gpt-5.5",
				HERMES_CODEX_BASE_URL: relayProxyUrl,
				TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN: codexRootToken,
				TELCLAUDE_HERMES_MCP_URL: mcpRelayUrl,
				TELCLAUDE_HERMES_MCP_RELAY_TOKEN: mcpTransportToken,
				TELCLAUDE_HERMES_SKILL_ALLOWLIST: allowlistPath,
				TELCLAUDE_HERMES_SOURCE_SKILLS_DIR: sourceSkills,
				TELCLAUDE_HERMES_CURATED_BUNDLED_SKILLS: curatedSkills,
				TELCLAUDE_HERMES_SKILL_CATALOG_MOUNT: path.join(tempRoot, "absent-catalog"),
				TELCLAUDE_HERMES_ENTRYPOINT_TEST_ALLOW_TMP_HOME: "1",
			},
			stdio: "pipe",
			encoding: "utf8",
		});

		expect(output).toContain(`profile provisioned at ${hermesHome}`);
		const config = fs.readFileSync(path.join(hermesHome, "config.yaml"), "utf8");
		const manifest = JSON.parse(
			fs.readFileSync(path.join(hermesHome, "secret-manifest.json"), "utf8"),
		) as Record<string, unknown>;
		const auth = JSON.parse(fs.readFileSync(path.join(hermesHome, "auth.json"), "utf8")) as {
			credential_pool: { "openai-codex": Array<{ access_token?: string }> };
		};
		const generatedProfile = [config, JSON.stringify(manifest), JSON.stringify(auth)].join("\n");

		expect(generatedProfile).not.toContain(codexRootToken);
		expect(generatedProfile).not.toContain(mcpTransportToken);
		expect(config).toContain(`Authorization: "Bearer \${TELCLAUDE_HERMES_MCP_RELAY_TOKEN}"`);
		expect(config).not.toMatch(/Authorization: "Bearer [A-Za-z0-9._~+/@:=,-]{12,}"/);
		expect(config).toContain(
			[
				"platform_toolsets:",
				"  api_server:",
				"    - todo",
				"    - skills",
				"    - telclaudeRelay",
			].join("\n"),
		);
		const disabledToolsetsBlock = config.slice(
			config.indexOf("agent:"),
			config.indexOf("mcp_servers:"),
		);
		expect(disabledToolsetsBlock).not.toContain("    - skills\n");
		expect(config).toContain(
			[
				"agent:",
				"  disabled_toolsets:",
				"    - terminal",
				"    - process",
				"    - code_execution",
				"    - file",
				"    - vision",
				"    - browser",
				"    - cronjob",
				"    - delegation",
				"    - memory",
				"    - session_search",
				"    - skill_manage",
				"    - image_gen",
				"    - web",
				"    - x_search",
				"    - tts",
				"    - video",
				"    - video_gen",
				"    - moa",
				"    - messaging",
				"    - send_message",
				"    - context_engine",
				"    - clarify",
				"    - homeassistant",
				"    - spotify",
				"    - discord",
				"    - discord_admin",
				"    - yuanbao",
				"    - computer_use",
				"    - feishu_doc",
				"    - feishu_drive",
			].join("\n"),
		);
		expect(config).toContain(
			[
				"skills:",
				"  creation_nudge_interval: 0",
				"  external_dirs:",
				`    - "${curatedSkills}"`,
			].join("\n"),
		);
		expect(fs.existsSync(path.join(hermesHome, ".no-bundled-skills"))).toBe(true);
		expect(fs.existsSync(path.join(hermesHome, "skills", "productivity", "memory-search"))).toBe(
			false,
		);
		expect(
			fs.existsSync(path.join(curatedSkills, "productivity", "memory-search", "SKILL.md")),
		).toBe(true);
		expect(() =>
			fs.mkdirSync(path.join(hermesHome, "skills", "telclaude-write-deny-canary")),
		).toThrow();
		for (const readOnlyPath of [
			path.join(hermesHome, "skills"),
			path.join(hermesHome, ".no-bundled-skills"),
			curatedSkills,
			path.join(curatedSkills, "productivity", "memory-search"),
		]) {
			expect(fs.statSync(readOnlyPath).mode & 0o222).toBe(0);
		}
		expect(manifest).toMatchObject({
			rawCredentialPolicy: "relay-owned-only",
			mcpTransportTokenBinding: "runtime-env-reference",
			mcpTransportTokenLocation: "process-env:not-HERMES_HOME",
			remainingRuntimeTokenCustody: "openai-codex-auth-store-peer-bound-compat",
		});

		const accessToken = auth.credential_pool["openai-codex"][0]?.access_token;
		expect(accessToken).toMatch(/^tc-openai-codex-relay-v1\./);
		expect(
			verifyOpenAiCodexPeerBoundProxyToken(accessToken, {
				secret: codexRootToken,
				peerAddress,
			}),
		).toMatchObject({ ok: true, tokenScope: "run" });
		expect(
			verifyOpenAiCodexPeerBoundProxyToken(accessToken, {
				secret: codexRootToken,
				peerAddress: "172.30.92.99",
			}),
		).toMatchObject({ ok: false, reason: "peer address mismatch" });
	});
});
