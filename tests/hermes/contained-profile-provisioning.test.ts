import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const repoRoot = path.resolve(import.meta.dirname, "../..");
const allowlistPath = path.join(repoRoot, "docker/hermes-contained-skills.allowlist");
const socialAllowlistPath = path.join(repoRoot, "docker/hermes-social-skills.allowlist");
const entrypointPath = path.join(repoRoot, "docker/hermes-contained-entrypoint.sh");
const composePath = path.join(repoRoot, "docker/docker-compose.hermes.yml");

describe("Hermes contained profile provisioning", () => {
	it("uses a deterministic curated skill allowlist", () => {
		const entries = readAllowlist(allowlistPath);
		const uniqueEntries = new Set(entries);

		expect(entries.length).toBeGreaterThan(50);
		expect(uniqueEntries.size).toBe(entries.length);
		for (const entry of entries) {
			expect(entry).not.toMatch(/^\/|(^|\/)\.\.($|\/)|\/\//);
			expect(entry).not.toMatch(/\s/);
		}
		expect(entries).not.toContain("mlops/evaluation/lm-evaluation-harness");
		expect(entries).not.toContain("red-teaming/godmode");
	});

	it("uses a narrower deterministic social skill allowlist", () => {
		const privateEntries = readAllowlist(allowlistPath);
		const socialEntries = readAllowlist(socialAllowlistPath);
		const uniqueEntries = new Set(socialEntries);

		expect(socialEntries.length).toBeGreaterThan(10);
		expect(socialEntries.length).toBeLessThan(privateEntries.length);
		expect(uniqueEntries.size).toBe(socialEntries.length);
		expect(socialEntries).toContain("social-media/xurl");
		expect(socialEntries).toContain("creative/humanizer");
		expect(socialEntries).not.toContain("github/github-auth");
		expect(socialEntries).not.toContain("productivity/google-workspace");
		expect(socialEntries).not.toContain("software-development/plan");
		for (const entry of socialEntries) {
			expect(entry).not.toMatch(/^\/|(^|\/)\.\.($|\/)|\/\//);
			expect(entry).not.toMatch(/\s/);
		}
	});

	it("serves curated skills as read-only external dirs and denies managed skill creation", () => {
		const script = fs.readFileSync(entrypointPath, "utf8");

		expect(script).toContain("prepare_managed_skills_dir()");
		expect(script).toContain('rm -rf "$CURATED_SKILLS_DIR"');
		expect(script).not.toContain('rm -rf "$CURATED_SKILLS_DIR" "$DEST_SKILLS_DIR"');
		expect(script).toContain('cp -R "');
		expect(script).not.toContain('/." "$DEST_SKILLS_DIR"');
		expect(script).toContain('touch "${HERMES_HOME}/.no-bundled-skills"');
		expect(script).toContain('SKILLS_EXTERNAL_DIRS_BLOCK="');
		expect(script).toContain('    - \\"${CURATED_SKILLS_DIR}\\"');
		expect(script).toContain('find "$CURATED_SKILLS_DIR" -type d -exec chmod 0550 {} +');
		expect(script).toContain('find "$CURATED_SKILLS_DIR" -type f -exec chmod 0440 {} +');
		expect(script).toContain('chmod 0550 "$DEST_SKILLS_DIR"');
		expect(script).toContain(
			'[ ! -w "$DEST_SKILLS_DIR" ] || die "managed skills directory remains writable: $DEST_SKILLS_DIR"',
		);
		expect(script).toContain(
			'chmod 0440 "${HERMES_HOME}/telclaude-contained-skills.allowlist" "${HERMES_HOME}/.no-bundled-skills"',
		);
		expect(script).not.toContain('export HERMES_BUNDLED_SKILLS="$CURATED_SKILLS_DIR"');
		expect(script).toContain("exec setpriv");
		expect(script).toContain('--reuid="$HERMES_RUNTIME_UID"');
		expect(script).toContain('--regid="$HERMES_RUNTIME_GID"');
		expect(script).toContain("--clear-groups");
		expect(script).toContain("--bounding-set=-all");
		expect(script).toContain("--inh-caps=-all");
		expect(script).toContain("--ambient-caps=-all");
		expect(script).toContain('exec /opt/hermes/hermes "$@"');
	});

	it("writes model-relay custody proof into the runtime Hermes profile", () => {
		const script = fs.readFileSync(entrypointPath, "utf8");

		expect(script).not.toContain("PROFILE_PROOF_DIR");
		expect(script).not.toContain(".hermes-profile-proof");
		expect(script).toContain(`cat > "\${HERMES_HOME}/config.yaml" <<EOF`);
		expect(script).toContain("  provider: openai-codex");
		expect(script).toContain("  api_mode: codex_responses");
		expect(script).toContain("  openai_runtime: auto");
		expect(script).toContain("skills:");
		expect(script).toContain("  creation_nudge_interval: 0");
		expect(script).toContain('Authorization: "Bearer \\${TELCLAUDE_HERMES_MCP_RELAY_TOKEN}"');
		expect(script).not.toContain('Authorization: "Bearer ${TELCLAUDE_MCP_RELAY_TOKEN}"');
		expect(script).toContain(`cat > "\${HERMES_HOME}/secret-manifest.json" <<'EOF'`);
		expect(script).toContain('"rawCredentialPolicy": "relay-owned-only"');
		expect(script).toContain('"relayTokenBinding": "run-peer-bound"');
		expect(script).toContain('"mcpTransportTokenLocation": "process-env:not-HERMES_HOME"');
		expect(script).toContain(`mv "$tmp_auth" "\${HERMES_HOME}/auth.json"`);
		expect(script).toContain(`chown "0:$HERMES_RUNTIME_GID" "$HERMES_HOME"`);
		expect(script).toContain(`chmod 1770 "$HERMES_HOME"`);
		expect(script).toContain(`chown "0:$HERMES_RUNTIME_GID"`);
		expect(script).toContain("chmod 0440");
		expect(script).toContain(
			`chmod 600 "\${HERMES_HOME}/config.yaml" "\${HERMES_HOME}/secret-manifest.json" "\${HERMES_HOME}/auth.json"`,
		);
	});

	it("waits for the relay MCP listener before launching upstream Hermes", () => {
		const script = fs.readFileSync(entrypointPath, "utf8");

		expect(script).toContain("wait_for_telclaude_mcp_relay()");
		expect(script).toContain("socket.create_connection((host, port), timeout=2)");
		expect(script).toContain("continuing");
		expect(script).toContain(
			`wait_for_telclaude_mcp_relay telclaude 8793 "\${TELCLAUDE_HERMES_MCP_STARTUP_WAIT_SECONDS:-300}"`,
		);
		expect(script.indexOf("wait_for_telclaude_mcp_relay telclaude 8793")).toBeLessThan(
			script.indexOf('exec /opt/hermes/hermes "$@"'),
		);
	});

	it("wires the curated provisioning script into the no-fork Hermes compose overlay", () => {
		const compose = fs.readFileSync(composePath, "utf8");

		expect(compose).toContain(
			'entrypoint: ["/bin/sh", "/tmp/telclaude-hermes-contained-entrypoint.sh"]',
		);
		expect(compose).toContain(
			"./hermes-contained-entrypoint.sh:/tmp/telclaude-hermes-contained-entrypoint.sh:ro",
		);
		expect(compose).toContain(
			"./hermes-contained-skills.allowlist:/tmp/telclaude-hermes-contained-skills.allowlist:ro",
		);
		expect(compose).toContain(
			"./hermes-social-skills.allowlist:/tmp/telclaude-hermes-social-skills.allowlist:ro",
		);
		expect(compose).toContain("..:/opt/data/telclaude-runner:ro");
		expect(compose).toContain('user: "10000:10000"');
		expect(compose).toContain("cap_drop:");
		expect(compose).toContain("      - ALL");
		expect(compose).not.toContain("cap_add:");
		expect(compose).toContain(
			"/home/hermes/.hermes/skills:size=1M,uid=0,gid=10000,mode=0550,noexec",
		);
		expect(compose).toContain(
			"/home/hermes/.hermes-social/skills:size=1M,uid=0,gid=10000,mode=0550,noexec",
		);
		expect(compose).toMatch(
			/TELCLAUDE_HERMES_LIVE_MCP_HOST=\$\{TELCLAUDE_HERMES_RELAY_IP:-172\.30\.92\.10\}/,
		);
		expect(compose).toContain("TELCLAUDE_HERMES_LIVE_MCP_NETWORK=telclaude-hermes-private");
		expect(compose).toContain("telclaude-hermes-social");
	});
});

function readAllowlist(filePath: string): string[] {
	return fs
		.readFileSync(filePath, "utf8")
		.split(/\r?\n/)
		.map((line) => line.trim())
		.filter((line) => line.length > 0 && !line.startsWith("#"));
}
