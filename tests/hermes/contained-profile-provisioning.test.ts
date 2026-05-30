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
		expect(script).toContain('exec /opt/hermes/hermes "$@"');
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
		expect(compose).toMatch(
			/TELCLAUDE_HERMES_LIVE_MCP_HOST=\$\{TELCLAUDE_HERMES_RELAY_IP:-172\.29\.92\.10\}/,
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
