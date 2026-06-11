import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	buildRelaySkillsCatalogProbeInput,
	DEFAULT_HERMES_SKILL_CATALOG_MOUNT,
	DEFAULT_HERMES_SOCIAL_SKILL_CATALOG_MOUNT,
	evaluateSkillsAllowlistEvidence,
	runSkillsAllowlistProbe,
	SKILLS_ALLOWLIST_REQUIRED_PROPERTY_NAMES,
	SKILLS_CATALOG_OBSERVER_SCRIPT,
	SKILLS_CATALOG_REQUIRED_CHECK_NAMES,
	type SkillsAllowlistEvidence,
	type SkillsAllowlistPropertyName,
	type SkillsAllowlistRunner,
	type SkillsCatalogObservedEntry,
	type SkillsCatalogSection,
} from "../../src/hermes/skills-allowlist-probe.js";
import {
	catalogManifestDigestSha256,
	computeCatalogSkillSha256,
	HERMES_SKILL_CATALOG_MANIFEST_FILENAME,
	HERMES_SKILL_CATALOG_MANIFEST_VERSION,
	type RelaySkillCatalogState,
} from "../../src/hermes/skills-catalog.js";
import { generateKeyPair } from "../../src/internal-auth.js";

const PRETOOLUSE_PROPERTIES = new Set<SkillsAllowlistPropertyName>([
	"pretooluse_hook_registered",
	"allowlisted_skill_invocation_allowed",
	"nonallowlisted_skill_invocation_denied",
	"social_missing_allowlist_denied",
	"social_empty_allowlist_denied",
]);

const manifest = [{ name: "daily-brief", sha256: "a".repeat(64) }];
const manifestDigest = catalogManifestDigestSha256(manifest);
const configuredRelayCatalog: RelaySkillCatalogState = {
	configured: true,
	skillCount: manifest.length,
	manifestSha256: manifestDigest,
};
const configuredSocialRelayCatalog: RelaySkillCatalogState = {
	configured: true,
	skillCount: manifest.length,
	manifestSha256: manifestDigest,
};

// Pin the relay catalog root to a nonexistent path so the default (live)
// resolution is hermetic: a real catalog on the dev machine must not leak
// catalog gates into catalog-free expectations.
const savedCatalogDir = process.env.TELCLAUDE_HERMES_SKILL_CATALOG_DIR;
const savedSocialCatalogDir = process.env.TELCLAUDE_HERMES_SOCIAL_SKILL_CATALOG_DIR;
let tempRoot = "";
beforeEach(() => {
	tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-skills-catalog-"));
	process.env.TELCLAUDE_HERMES_SKILL_CATALOG_DIR = path.join(tempRoot, "absent-catalog");
	process.env.TELCLAUDE_HERMES_SOCIAL_SKILL_CATALOG_DIR = path.join(
		tempRoot,
		"absent-social-catalog",
	);
});
afterEach(() => {
	if (savedCatalogDir === undefined) delete process.env.TELCLAUDE_HERMES_SKILL_CATALOG_DIR;
	else process.env.TELCLAUDE_HERMES_SKILL_CATALOG_DIR = savedCatalogDir;
	if (savedSocialCatalogDir === undefined)
		delete process.env.TELCLAUDE_HERMES_SOCIAL_SKILL_CATALOG_DIR;
	else process.env.TELCLAUDE_HERMES_SOCIAL_SKILL_CATALOG_DIR = savedSocialCatalogDir;
	fs.rmSync(tempRoot, { recursive: true, force: true });
});

/** Create a real relay catalog root with a valid manifest and point the env at it. */
function configureLiveRelayCatalog(): string {
	const root = path.join(tempRoot, "live-catalog");
	fs.mkdirSync(root, { recursive: true });
	fs.writeFileSync(
		path.join(root, HERMES_SKILL_CATALOG_MANIFEST_FILENAME),
		`${JSON.stringify({
			schemaVersion: HERMES_SKILL_CATALOG_MANIFEST_VERSION,
			skills: manifest.map((entry) => ({
				...entry,
				origin: "test",
				installedAt: "2026-06-10T00:00:00.000Z",
			})),
		})}\n`,
	);
	process.env.TELCLAUDE_HERMES_SKILL_CATALOG_DIR = root;
	return root;
}

function configureLiveSocialRelayCatalog(): string {
	const root = path.join(tempRoot, "live-social-catalog");
	fs.mkdirSync(root, { recursive: true });
	fs.writeFileSync(
		path.join(root, HERMES_SKILL_CATALOG_MANIFEST_FILENAME),
		`${JSON.stringify({
			schemaVersion: HERMES_SKILL_CATALOG_MANIFEST_VERSION,
			skills: manifest.map((entry) => ({
				...entry,
				origin: "test-social",
				installedAt: "2026-06-10T00:00:00.000Z",
			})),
		})}\n`,
	);
	process.env.TELCLAUDE_HERMES_SOCIAL_SKILL_CATALOG_DIR = root;
	return root;
}

function validEvidence(): SkillsAllowlistEvidence {
	const properties = Object.fromEntries(
		SKILLS_ALLOWLIST_REQUIRED_PROPERTY_NAMES.map((name) => [name, true]),
	) as SkillsAllowlistEvidence["properties"];
	const checks = SKILLS_ALLOWLIST_REQUIRED_PROPERTY_NAMES.map((name) => ({
		name,
		status: "pass" as const,
		detail: `${name} proven`,
		...(name === "artifact_redacted" ? {} : { observationLayer: "docker_exec" as const }),
		...(PRETOOLUSE_PROPERTIES.has(name) ? { enforcementLayer: "pretooluse" as const } : {}),
	}));
	return {
		schemaVersion: "telclaude.hermes.skills-allowlist.v1",
		probeId: "skills.allowlist",
		status: "pass",
		ran: true,
		generatedAt: "2026-06-05T20:00:00.000Z",
		summary: "skills allowlist profile proven in contained runtime",
		origin: {
			kind: "contained-runtime",
			containerName: "tc-hermes-contained",
			topologyInternal: true,
			relayContainerPresent: true,
			authoritativeBoundary: "docker_internal_network",
			detail: "docker internal-network topology proof",
		},
		properties,
		checks,
	};
}

function passingCatalogSection(): SkillsCatalogSection {
	return {
		mountPath: "/opt/data/telclaude-hermes-skill-catalog",
		manifestSkillCount: manifest.length,
		manifestSha256: manifestDigest,
		checks: SKILLS_CATALOG_REQUIRED_CHECK_NAMES.map((name) => ({
			name,
			status: "pass" as const,
			detail: `${name} proven against the container-visible mount`,
			observationLayer: "docker_exec" as const,
		})),
	};
}

function passingSocialCatalogSection(): SkillsCatalogSection {
	return {
		...passingCatalogSection(),
		mountPath: DEFAULT_HERMES_SOCIAL_SKILL_CATALOG_MOUNT,
	};
}

describe("evaluateSkillsAllowlistEvidence catalog section", () => {
	it("evaluates catalog-free evidence exactly as before (no catalog gates)", () => {
		const report = evaluateSkillsAllowlistEvidence(validEvidence());
		expect(report.status).toBe("pass");
		expect(report.gates.filter((gate) => gate.name.startsWith("skills.catalog."))).toEqual([]);
	});

	it("passes when the catalog section is complete and all checks pass", () => {
		const report = evaluateSkillsAllowlistEvidence({
			...validEvidence(),
			catalog: passingCatalogSection(),
		});
		expect(report.status).toBe("pass");
		expect(
			report.gates
				.filter((gate) => gate.name.startsWith("skills.catalog.catalog_"))
				.map((g) => g.status),
		).toEqual(["pass", "pass", "pass", "pass"]);
	});

	it("fails when a catalog check fails", () => {
		const catalog = passingCatalogSection();
		catalog.checks[0] = {
			...catalog.checks[0],
			status: "fail",
			detail: "catalog_manifest_match violated by: rogue (not in relay manifest)",
		};
		const report = evaluateSkillsAllowlistEvidence({ ...validEvidence(), catalog });
		expect(report.status).toBe("fail");
		expect(
			report.gates.find((gate) => gate.name === "skills.catalog.catalog_manifest_match")?.status,
		).toBe("fail");
	});

	it("fails when a required catalog check is missing", () => {
		const catalog = passingCatalogSection();
		catalog.checks = catalog.checks.filter((check) => check.name !== "catalog_no_symlinks");
		const report = evaluateSkillsAllowlistEvidence({ ...validEvidence(), catalog });
		expect(report.status).toBe("fail");
		expect(
			report.gates.find((gate) => gate.name === "skills.catalog.catalog_no_symlinks")?.detail,
		).toContain("missing");
	});

	it("input_errors on a non-docker_exec catalog observation", () => {
		const catalog = passingCatalogSection() as unknown as Record<string, unknown>;
		(catalog.checks as Array<Record<string, unknown>>)[0].observationLayer = "host";
		const report = evaluateSkillsAllowlistEvidence({ ...validEvidence(), catalog });
		expect(report.status).toBe("input_error");
	});
});

describe("evaluateSkillsAllowlistEvidence catalog requirement (fail-closed)", () => {
	it("fails closed when the relay serves a catalog and the evidence carries no catalog section", () => {
		const report = evaluateSkillsAllowlistEvidence(validEvidence(), {
			relayCatalog: configuredRelayCatalog,
		});
		expect(report.status).toBe("fail");
		expect(report.productionEnable).toBe(false);
		const gate = report.gates.find((g) => g.name === "skills.catalog.required");
		expect(gate?.status).toBe("fail");
		expect(gate?.detail).toContain("no catalog section");
	});

	it("requires the catalog section under live relay-state resolution (no injected state)", () => {
		// The cutover-check path: foundation calls the evaluator with no relayCatalog
		// option, so the requirement must come from the live relay catalog root.
		configureLiveRelayCatalog();
		const report = evaluateSkillsAllowlistEvidence(validEvidence());
		expect(report.status).toBe("fail");
		expect(report.gates.find((g) => g.name === "skills.catalog.required")?.status).toBe("fail");
	});

	it("fails closed when catalog evidence was probed against a different relay manifest", () => {
		const report = evaluateSkillsAllowlistEvidence(
			{ ...validEvidence(), catalog: passingCatalogSection() },
			{
				relayCatalog: {
					configured: true,
					skillCount: 2,
					manifestSha256: crypto.createHash("sha256").update("other-manifest").digest("hex"),
				},
			},
		);
		expect(report.status).toBe("fail");
		const gate = report.gates.find((g) => g.name === "skills.catalog.required");
		expect(gate?.status).toBe("fail");
		expect(gate?.detail).toContain("manifestSha256");
	});

	it("fails closed when the relay catalog manifest is unreadable", () => {
		const report = evaluateSkillsAllowlistEvidence(
			{ ...validEvidence(), catalog: passingCatalogSection() },
			{ relayCatalog: { configured: true, error: "corrupt catalog manifest" } },
		);
		expect(report.status).toBe("fail");
		expect(report.gates.find((g) => g.name === "skills.catalog.required")?.detail).toContain(
			"unreadable",
		);
	});

	it("fails closed under live resolution when the on-disk manifest is corrupt", () => {
		const root = configureLiveRelayCatalog();
		fs.writeFileSync(path.join(root, HERMES_SKILL_CATALOG_MANIFEST_FILENAME), "not-json");
		const report = evaluateSkillsAllowlistEvidence({
			...validEvidence(),
			catalog: passingCatalogSection(),
		});
		expect(report.status).toBe("fail");
		expect(report.gates.find((g) => g.name === "skills.catalog.required")?.status).toBe("fail");
	});

	it("passes when catalog evidence is bound to the live relay manifest", () => {
		const report = evaluateSkillsAllowlistEvidence(
			{ ...validEvidence(), catalog: passingCatalogSection() },
			{ relayCatalog: configuredRelayCatalog },
		);
		expect(report.status).toBe("pass");
		expect(report.gates.find((g) => g.name === "skills.catalog.required")?.status).toBe("pass");
	});

	it("fails closed when the relay serves a social catalog and evidence carries no social section", () => {
		const report = evaluateSkillsAllowlistEvidence(
			{ ...validEvidence(), catalog: passingCatalogSection() },
			{
				relayCatalog: configuredRelayCatalog,
				socialRelayCatalog: configuredSocialRelayCatalog,
			},
		);
		expect(report.status).toBe("fail");
		expect(report.productionEnable).toBe(false);
		const gate = report.gates.find((g) => g.name === "skills.socialCatalog.required");
		expect(gate?.status).toBe("fail");
		expect(gate?.detail).toContain("no social catalog section");
	});

	it("passes when both private and social catalog evidence are bound to live manifests", () => {
		const report = evaluateSkillsAllowlistEvidence(
			{
				...validEvidence(),
				catalog: passingCatalogSection(),
				socialCatalog: passingSocialCatalogSection(),
			},
			{
				relayCatalog: configuredRelayCatalog,
				socialRelayCatalog: configuredSocialRelayCatalog,
			},
		);
		expect(report.status).toBe("pass");
		expect(report.gates.find((g) => g.name === "skills.catalog.required")?.status).toBe("pass");
		expect(report.gates.find((g) => g.name === "skills.socialCatalog.required")?.status).toBe(
			"pass",
		);
	});

	it("requires social catalog evidence under live social relay-state resolution", () => {
		configureLiveSocialRelayCatalog();
		const report = evaluateSkillsAllowlistEvidence(validEvidence());
		expect(report.status).toBe("fail");
		expect(report.gates.find((g) => g.name === "skills.socialCatalog.required")?.status).toBe(
			"fail",
		);
	});
});

describe("runSkillsAllowlistProbe catalog producer", () => {
	const savedRelayKeys = {
		private: process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY,
		public: process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY,
	};
	beforeEach(() => {
		const relayKeys = generateKeyPair();
		process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = relayKeys.privateKey;
		process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = relayKeys.publicKey;
	});
	afterEach(() => {
		if (savedRelayKeys.private === undefined) delete process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
		else process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = savedRelayKeys.private;
		if (savedRelayKeys.public === undefined) delete process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
		else process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = savedRelayKeys.public;
	});

	const containedTopology = async () => ({
		containerName: "tc-hermes-contained",
		topologyInternal: true,
		relayContainerPresent: true,
	});

	const dockerRunner: SkillsAllowlistRunner = async (scenario) => ({
		passed: true,
		observationLayer: "docker_exec",
		...(scenario.kind === "pretooluse" ? { enforcementLayer: "pretooluse" as const } : {}),
	});

	function observedEntry(
		overrides: Partial<SkillsCatalogObservedEntry> = {},
	): SkillsCatalogObservedEntry {
		return {
			name: "daily-brief",
			sha256: "a".repeat(64),
			hasScriptsDir: false,
			hasSymlink: false,
			hasExecutable: false,
			...overrides,
		};
	}

	it("produces a passing, attested catalog section when container state matches the manifest", async () => {
		const evidence = await runSkillsAllowlistProbe({
			allowRun: true,
			runner: dockerRunner,
			observeTopology: containedTopology,
			relayCatalog: configuredRelayCatalog,
			catalog: {
				mountPath: "/opt/data/telclaude-hermes-skill-catalog",
				manifest,
				observe: async () => [observedEntry()],
			},
		});

		expect(evidence.status).toBe("pass");
		expect(evidence.catalog?.manifestSkillCount).toBe(1);
		expect(evidence.catalog?.manifestSha256).toBe(manifestDigest);
		expect(evidence.catalog?.checks.every((check) => check.status === "pass")).toBe(true);
		expect(evidence.runnerAttestation).toBeDefined();

		const report = evaluateSkillsAllowlistEvidence(evidence, {
			allowStaleAttestations: true,
			relayCatalog: configuredRelayCatalog,
		});
		expect(report.status).toBe("pass");
		expect(report.productionEnable).toBe(true);
	});

	it("fails closed when the relay serves a catalog but no catalog observer is wired", async () => {
		// The exact failure shape of the review finding: a catalog-serving deployment
		// running the probe without catalog wiring must not produce passing evidence.
		const evidence = await runSkillsAllowlistProbe({
			allowRun: true,
			runner: dockerRunner,
			observeTopology: containedTopology,
			relayCatalog: configuredRelayCatalog,
		});

		expect(evidence.catalog).toBeUndefined();
		expect(evidence.status).toBe("fail");
		expect(evidence.summary).toContain("skills.catalog.required");

		const report = evaluateSkillsAllowlistEvidence(evidence, {
			allowStaleAttestations: true,
			relayCatalog: configuredRelayCatalog,
		});
		expect(report.status).toBe("fail");
		expect(report.productionEnable).toBe(false);
	});

	it("fails closed under live relay-state resolution when catalog wiring is missing", async () => {
		configureLiveRelayCatalog();
		const evidence = await runSkillsAllowlistProbe({
			allowRun: true,
			runner: dockerRunner,
			observeTopology: containedTopology,
		});
		expect(evidence.status).toBe("fail");
		expect(evidence.summary).toContain("skills.catalog.required");
	});

	it("fails the evidence when the container catalog drifts from the manifest", async () => {
		const evidence = await runSkillsAllowlistProbe({
			allowRun: true,
			runner: dockerRunner,
			observeTopology: containedTopology,
			relayCatalog: configuredRelayCatalog,
			catalog: {
				mountPath: "/opt/data/telclaude-hermes-skill-catalog",
				manifest,
				observe: async () => [
					observedEntry({ sha256: "b".repeat(64) }),
					observedEntry({ name: "rogue", hasExecutable: true }),
				],
			},
		});

		expect(evidence.status).toBe("fail");
		const byName = new Map(evidence.catalog?.checks.map((check) => [check.name, check]));
		expect(byName.get("catalog_manifest_match")?.status).toBe("fail");
		expect(byName.get("catalog_manifest_match")?.detail).toContain("content hash mismatch");
		expect(byName.get("catalog_manifest_match")?.detail).toContain("not in relay manifest");
		expect(byName.get("catalog_no_executables")?.status).toBe("fail");
		expect(byName.get("catalog_no_symlinks")?.status).toBe("pass");

		const report = evaluateSkillsAllowlistEvidence(evidence, {
			allowStaleAttestations: true,
			relayCatalog: configuredRelayCatalog,
		});
		expect(report.status).toBe("fail");
	});

	it("fails every catalog check when the observation itself fails", async () => {
		const evidence = await runSkillsAllowlistProbe({
			allowRun: true,
			runner: dockerRunner,
			observeTopology: containedTopology,
			relayCatalog: configuredRelayCatalog,
			catalog: {
				mountPath: "/opt/data/telclaude-hermes-skill-catalog",
				manifest,
				observe: async () => {
					throw new Error("docker exec failed");
				},
			},
		});
		expect(evidence.status).toBe("fail");
		expect(evidence.catalog?.checks.map((check) => check.status)).toEqual([
			"fail",
			"fail",
			"fail",
			"fail",
		]);
		expect(evidence.catalog?.checks[0]?.detail).toContain("catalog observation failed");
	});

	it("binds the catalog section into the attestation digest", async () => {
		const evidence = await runSkillsAllowlistProbe({
			allowRun: true,
			runner: dockerRunner,
			observeTopology: containedTopology,
			relayCatalog: configuredRelayCatalog,
			catalog: {
				mountPath: "/opt/data/telclaude-hermes-skill-catalog",
				manifest,
				observe: async () => [observedEntry()],
			},
		});

		const tampered: SkillsAllowlistEvidence = {
			...evidence,
			catalog: { ...(evidence.catalog as SkillsCatalogSection), mountPath: "/evil/mount" },
		};
		const report = evaluateSkillsAllowlistEvidence(tampered, {
			allowStaleAttestations: true,
			relayCatalog: configuredRelayCatalog,
		});
		expect(report.status).toBe("fail");
		expect(report.gates.find((gate) => gate.name === "skills.attestation")?.detail).toContain(
			"evidenceSha256 mismatch",
		);
	});

	it("binds the social catalog section into the attestation digest", async () => {
		const evidence = await runSkillsAllowlistProbe({
			allowRun: true,
			runner: dockerRunner,
			observeTopology: containedTopology,
			relayCatalog: configuredRelayCatalog,
			socialRelayCatalog: configuredSocialRelayCatalog,
			catalog: {
				mountPath: "/opt/data/telclaude-hermes-skill-catalog",
				manifest,
				observe: async () => [observedEntry()],
			},
			socialCatalog: {
				mountPath: DEFAULT_HERMES_SOCIAL_SKILL_CATALOG_MOUNT,
				manifest,
				observe: async () => [observedEntry()],
			},
		});

		const tampered: SkillsAllowlistEvidence = {
			...evidence,
			socialCatalog: {
				...(evidence.socialCatalog as SkillsCatalogSection),
				mountPath: "/evil/social-mount",
			},
		};
		const report = evaluateSkillsAllowlistEvidence(tampered, {
			allowStaleAttestations: true,
			relayCatalog: configuredRelayCatalog,
			socialRelayCatalog: configuredSocialRelayCatalog,
		});
		expect(report.status).toBe("fail");
		expect(report.gates.find((gate) => gate.name === "skills.attestation")?.detail).toContain(
			"evidenceSha256 mismatch",
		);
	});

	it("emits no catalog section when no catalog is configured", async () => {
		const evidence = await runSkillsAllowlistProbe({
			allowRun: true,
			runner: dockerRunner,
			observeTopology: containedTopology,
		});
		expect(evidence.catalog).toBeUndefined();
		expect(evidence.status).toBe("pass");
	});
});

describe("buildRelaySkillsCatalogProbeInput", () => {
	it("returns undefined when no relay catalog is configured", () => {
		expect(buildRelaySkillsCatalogProbeInput({ containerName: "tc-hermes-contained" })).toBe(
			undefined,
		);
	});

	it("builds the manifest and mount path from the live relay catalog", () => {
		const root = configureLiveRelayCatalog();
		const input = buildRelaySkillsCatalogProbeInput({
			containerName: "tc-hermes-contained",
			catalogRoot: root,
		});
		expect(input?.mountPath).toBe(DEFAULT_HERMES_SKILL_CATALOG_MOUNT);
		expect(input?.manifest).toEqual(manifest);
	});

	it("builds social manifest and mount path from the live social relay catalog", () => {
		const root = configureLiveSocialRelayCatalog();
		const input = buildRelaySkillsCatalogProbeInput({
			containerName: "tc-hermes-social",
			catalogKind: "social",
			catalogRoot: root,
		});
		expect(input?.mountPath).toBe(DEFAULT_HERMES_SOCIAL_SKILL_CATALOG_MOUNT);
		expect(input?.manifest).toEqual(manifest);
	});

	it("throws on an unreadable relay manifest instead of degrading to catalog-free", () => {
		const root = configureLiveRelayCatalog();
		fs.writeFileSync(path.join(root, HERMES_SKILL_CATALOG_MANIFEST_FILENAME), "not-json");
		expect(() =>
			buildRelaySkillsCatalogProbeInput({
				containerName: "tc-hermes-contained",
				catalogRoot: root,
			}),
		).toThrow(/unreadable/);
	});
});

describe("SKILLS_CATALOG_OBSERVER_SCRIPT", () => {
	function runObserverScript(mountPath: string): SkillsCatalogObservedEntry[] {
		const result = spawnSync(
			process.execPath,
			["--input-type=module", "-e", SKILLS_CATALOG_OBSERVER_SCRIPT, mountPath],
			{ encoding: "utf8" },
		);
		expect(result.status).toBe(0);
		return JSON.parse(result.stdout.trim()) as SkillsCatalogObservedEntry[];
	}

	it("hashes a clean skill identically to the relay-side hasher", () => {
		const mount = path.join(tempRoot, "mount");
		const skillDir = path.join(mount, "skills", "daily-brief");
		fs.mkdirSync(path.join(skillDir, "reference"), { recursive: true });
		fs.writeFileSync(
			path.join(skillDir, "SKILL.md"),
			"---\nname: daily-brief\ndescription: Test skill\n---\n\nBody.\n",
		);
		fs.writeFileSync(path.join(skillDir, "reference", "notes.md"), "extra notes\n");

		const observed = runObserverScript(mount);
		expect(observed).toEqual([
			{
				name: "daily-brief",
				sha256: computeCatalogSkillSha256(skillDir),
				hasScriptsDir: false,
				hasSymlink: false,
				hasExecutable: false,
			},
		]);
	});

	it("flags scripts directories, symlinks, and executables", () => {
		const mount = path.join(tempRoot, "mount");
		const skillDir = path.join(mount, "skills", "evil");
		fs.mkdirSync(path.join(skillDir, "scripts"), { recursive: true });
		fs.writeFileSync(path.join(skillDir, "SKILL.md"), "body\n");
		fs.writeFileSync(path.join(skillDir, "run.sh"), "#!/bin/sh\n", { mode: 0o755 });
		fs.symlinkSync("/etc/hosts", path.join(skillDir, "link"));

		const [observed] = runObserverScript(mount);
		expect(observed.name).toBe("evil");
		expect(observed.hasScriptsDir).toBe(true);
		expect(observed.hasSymlink).toBe(true);
		expect(observed.hasExecutable).toBe(true);
	});

	it("reports an empty mount as an empty catalog", () => {
		const mount = path.join(tempRoot, "empty-mount");
		fs.mkdirSync(path.join(mount, "skills"), { recursive: true });
		expect(runObserverScript(mount)).toEqual([]);
	});
});
