import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const repoRoot = path.resolve(import.meta.dirname, "../..");
const allowlistPath = path.join(repoRoot, "docker/hermes-contained-skills.allowlist");
const entrypointPath = path.join(repoRoot, "docker/hermes-contained-entrypoint.sh");
const composePath = path.join(repoRoot, "docker/docker-compose.hermes.yml");

describe("Hermes contained profile provisioning", () => {
	it("uses a deterministic curated skill allowlist", () => {
		const entries = readAllowlist();
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

	it("resets HERMES_HOME skills and points Hermes bundled sync at the curated tree", () => {
		const script = fs.readFileSync(entrypointPath, "utf8");

		expect(script).toContain('rm -rf "$CURATED_SKILLS_DIR" "$DEST_SKILLS_DIR"');
		expect(script).toContain('cp -R "');
		expect(script).toContain('/." "$DEST_SKILLS_DIR"');
		expect(script).toContain('export HERMES_BUNDLED_SKILLS="$CURATED_SKILLS_DIR"');
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
		expect(script).toContain(`cat > "\${HERMES_HOME}/secret-manifest.json" <<'EOF'`);
		expect(script).toContain('"rawCredentialPolicy": "relay-owned-only"');
		expect(script).toContain('"relayTokenBinding": "run-peer-bound"');
		expect(script).toContain(`mv "$tmp_auth" "\${HERMES_HOME}/auth.json"`);
		expect(script).toContain(`chown "0:$HERMES_RUNTIME_GID" "$HERMES_HOME"`);
		expect(script).toContain(`chmod 1770 "$HERMES_HOME"`);
		expect(script).toContain(`chown "0:$HERMES_RUNTIME_GID"`);
		expect(script).toContain("chmod 0440");
		expect(script).toContain(
			`chmod 600 "\${HERMES_HOME}/config.yaml" "\${HERMES_HOME}/secret-manifest.json" "\${HERMES_HOME}/auth.json"`,
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
		expect(compose).toContain("..:/opt/data/telclaude-runner:ro");
		expect(compose).toContain('user: "10000:10000"');
		expect(compose).toContain("cap_drop:");
		expect(compose).toContain("      - ALL");
		expect(compose).not.toContain("cap_add:");
		expect(compose).toMatch(
			/TELCLAUDE_HERMES_LIVE_MCP_HOST=\$\{TELCLAUDE_HERMES_RELAY_IP:-192\.0\.2\.10\}/,
		);
	});
});

function readAllowlist(): string[] {
	return fs
		.readFileSync(allowlistPath, "utf8")
		.split(/\r?\n/)
		.map((line) => line.trim())
		.filter((line) => line.length > 0 && !line.startsWith("#"));
}
