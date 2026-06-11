/**
 * Relay-owned Hermes skill catalog.
 *
 * The catalog is a relay-side directory tree (`<root>/skills/<name>/SKILL.md`)
 * that the contained Hermes runtime mounts read-only and scans via upstream
 * `skills.external_dirs`. The relay is the only writer: every install is
 * validated (path-safe name, no scripts/symlinks/executables, size caps,
 * secret + injection scan) and recorded in an atomic manifest so drift between
 * the manifest and the mounted tree is detectable.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { z } from "zod";
import { assessRisk } from "../security/external-content.js";
import { filterOutput } from "../security/output-filter.js";
import { CONFIG_DIR } from "../utils.js";

export const HERMES_SKILL_CATALOG_MANIFEST_VERSION = "telclaude.hermes.skill-catalog-manifest.v1";
export const HERMES_SKILL_CATALOG_MANIFEST_FILENAME = "catalog-manifest.json";

const CATALOG_SKILL_NAME_PATTERN = /^[a-z0-9][a-z0-9-]{0,62}$/;
const SHA256_HEX_PATTERN = /^[a-f0-9]{64}$/;
const MAX_CATALOG_SKILL_TOTAL_BYTES = 256 * 1024;
const MAX_CATALOG_SKILL_MD_BYTES = 64 * 1024;

const HermesSkillCatalogManifestEntrySchema = z
	.object({
		name: z.string().regex(CATALOG_SKILL_NAME_PATTERN),
		sha256: z.string().regex(SHA256_HEX_PATTERN),
		origin: z.string().min(1),
		installedAt: z.string().min(1),
	})
	.strict();

const HermesSkillCatalogManifestSchema = z
	.object({
		schemaVersion: z.literal(HERMES_SKILL_CATALOG_MANIFEST_VERSION),
		skills: z.array(HermesSkillCatalogManifestEntrySchema),
	})
	.strict();

export type HermesSkillCatalogManifestEntry = z.infer<typeof HermesSkillCatalogManifestEntrySchema>;
export type HermesSkillCatalogManifest = z.infer<typeof HermesSkillCatalogManifestSchema>;

export type CatalogSkillValidation =
	| { ok: true; name: string; description: string }
	| { ok: false; errors: string[] };

export type CatalogInstallResult = {
	name: string;
	sha256: string;
	origin: string;
	installedAt: string;
	targetDir: string;
	manifestPath: string;
};

export type CatalogVerifyStatus = "ok" | "drift" | "missing" | "invalid" | "unmanaged";

export type CatalogVerifyEntry = {
	name: string;
	status: CatalogVerifyStatus;
	detail?: string;
};

export type CatalogVerifyResult = {
	ok: boolean;
	skills: CatalogVerifyEntry[];
};

export type CatalogOptions = {
	/** Override the catalog root (tests / non-default deployments). */
	catalogRoot?: string;
	now?: Date;
};

/**
 * Catalog root: TELCLAUDE_HERMES_SKILL_CATALOG_DIR if set, else
 * `<telclaude config dir>/hermes-skill-catalog`.
 */
export function resolveHermesSkillCatalogRoot(): string {
	const fromEnv = process.env.TELCLAUDE_HERMES_SKILL_CATALOG_DIR?.trim();
	if (fromEnv) return path.resolve(fromEnv);
	return path.join(CONFIG_DIR, "hermes-skill-catalog");
}

function catalogRootFrom(options: CatalogOptions): string {
	return path.resolve(options.catalogRoot ?? resolveHermesSkillCatalogRoot());
}

function catalogSkillsDir(root: string): string {
	return path.join(root, "skills");
}

function manifestPathFor(root: string): string {
	return path.join(root, HERMES_SKILL_CATALOG_MANIFEST_FILENAME);
}

type WalkedFile = {
	rel: string;
	abs: string;
	size: number;
};

function walkSkillDir(dir: string, errors: string[]): WalkedFile[] {
	const files: WalkedFile[] = [];
	const visit = (current: string, relPrefix: string): void => {
		for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
			const abs = path.join(current, entry.name);
			const rel = relPrefix ? `${relPrefix}/${entry.name}` : entry.name;
			const stat = fs.lstatSync(abs);
			if (stat.isSymbolicLink()) {
				errors.push(`symlink not allowed: ${rel}`);
				continue;
			}
			if (stat.isDirectory()) {
				if (entry.name === "scripts") {
					errors.push(`scripts/ directory not allowed: ${rel}`);
					continue;
				}
				visit(abs, rel);
				continue;
			}
			if (!stat.isFile()) {
				errors.push(`unsupported file type: ${rel}`);
				continue;
			}
			if ((stat.mode & 0o111) !== 0) {
				errors.push(`executable file not allowed: ${rel}`);
				continue;
			}
			files.push({ rel, abs, size: stat.size });
		}
	};
	visit(dir, "");
	return files;
}

function parseSkillFrontmatter(markdown: string): { name?: string; description?: string } | null {
	const match = markdown.match(/^---\s*\n([\s\S]*?)\n---/);
	if (!match) return null;
	const fields: Record<string, string> = {};
	let currentKey: string | null = null;
	for (const rawLine of match[1].split("\n")) {
		const line = rawLine.replace(/\r$/, "");
		if (!line.trim()) continue;
		const keyMatch = line.match(/^(\w[\w.-]*)\s*:\s*(.*)$/);
		if (keyMatch) {
			currentKey = keyMatch[1];
			fields[currentKey] = keyMatch[2].trim();
			continue;
		}
		if (currentKey && /^\s+/.test(line)) {
			fields[currentKey] = `${fields[currentKey] ?? ""} ${line.trim()}`.trim();
		}
	}
	return { name: fields.name, description: fields.description };
}

/**
 * Validate a candidate skill directory against catalog policy. The directory
 * name is the skill name; the SKILL.md frontmatter name must match it exactly.
 */
export function validateCatalogSkillDir(dir: string): CatalogSkillValidation {
	const errors: string[] = [];
	const resolved = path.resolve(dir);

	let dirStat: fs.Stats;
	try {
		dirStat = fs.lstatSync(resolved);
	} catch {
		return { ok: false, errors: [`skill directory not found: ${resolved}`] };
	}
	if (dirStat.isSymbolicLink() || !dirStat.isDirectory()) {
		return { ok: false, errors: [`skill path is not a plain directory: ${resolved}`] };
	}

	const name = path.basename(resolved);
	if (!CATALOG_SKILL_NAME_PATTERN.test(name)) {
		errors.push(`invalid skill name "${name}" (must match ${CATALOG_SKILL_NAME_PATTERN})`);
	}

	const files = walkSkillDir(resolved, errors);
	const totalBytes = files.reduce((sum, file) => sum + file.size, 0);
	if (totalBytes > MAX_CATALOG_SKILL_TOTAL_BYTES) {
		errors.push(`skill exceeds ${MAX_CATALOG_SKILL_TOTAL_BYTES} bytes total (${totalBytes})`);
	}

	const skillMd = files.find((file) => file.rel === "SKILL.md");
	let description = "";
	if (!skillMd) {
		errors.push("SKILL.md is required");
	} else {
		if (skillMd.size > MAX_CATALOG_SKILL_MD_BYTES) {
			errors.push(`SKILL.md exceeds ${MAX_CATALOG_SKILL_MD_BYTES} bytes (${skillMd.size})`);
		}
		const markdown = fs.readFileSync(skillMd.abs, "utf8");
		const frontmatter = parseSkillFrontmatter(markdown);
		if (!frontmatter?.name?.trim()) {
			errors.push("SKILL.md frontmatter must include name");
		} else if (frontmatter.name.trim() !== name) {
			errors.push(
				`SKILL.md frontmatter name "${frontmatter.name.trim()}" must match directory name "${name}"`,
			);
		}
		if (!frontmatter?.description?.trim()) {
			errors.push("SKILL.md frontmatter must include description");
		} else {
			description = frontmatter.description.trim();
		}
		const risk = assessRisk(markdown);
		if (risk.level === "high" || risk.level === "critical") {
			errors.push(
				`SKILL.md injection risk is ${risk.level} (${risk.findings.length} finding(s)); refusing to catalog`,
			);
		}
	}

	for (const file of files) {
		const text = fs.readFileSync(file.abs, "utf8");
		const filtered = filterOutput(text);
		if (filtered.blocked) {
			errors.push(
				`file contains secret-looking value (${filtered.matches[0].pattern}): ${file.rel}`,
			);
		}
	}

	if (errors.length > 0) {
		return { ok: false, errors };
	}
	return { ok: true, name, description };
}

/**
 * Canonical content hash of a catalog skill directory: sha256 over the sorted
 * listing of `<posix relpath>\0<sha256(file bytes) hex>\n` for every regular file.
 */
export function computeCatalogSkillSha256(dir: string): string {
	const errors: string[] = [];
	const files = walkSkillDir(path.resolve(dir), errors).sort((a, b) =>
		a.rel < b.rel ? -1 : a.rel > b.rel ? 1 : 0,
	);
	if (errors.length > 0) {
		throw new Error(`cannot hash skill directory: ${errors.join("; ")}`);
	}
	const hash = crypto.createHash("sha256");
	for (const file of files) {
		hash.update(file.rel);
		hash.update("\0");
		hash.update(crypto.createHash("sha256").update(fs.readFileSync(file.abs)).digest("hex"));
		hash.update("\n");
	}
	return hash.digest("hex");
}

function copyTreeWithCatalogModes(src: string, dst: string): void {
	fs.mkdirSync(dst, { recursive: true });
	fs.chmodSync(dst, 0o755);
	for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
		const from = path.join(src, entry.name);
		const to = path.join(dst, entry.name);
		const stat = fs.lstatSync(from);
		if (stat.isDirectory()) {
			copyTreeWithCatalogModes(from, to);
		} else if (stat.isFile()) {
			fs.copyFileSync(from, to);
			fs.chmodSync(to, 0o644);
		} else {
			throw new Error(`unsupported entry while copying skill: ${entry.name}`);
		}
	}
}

function readManifest(root: string): HermesSkillCatalogManifest {
	const manifestPath = manifestPathFor(root);
	if (!fs.existsSync(manifestPath)) {
		return { schemaVersion: HERMES_SKILL_CATALOG_MANIFEST_VERSION, skills: [] };
	}
	const parsed = HermesSkillCatalogManifestSchema.safeParse(
		JSON.parse(fs.readFileSync(manifestPath, "utf8")),
	);
	if (!parsed.success) {
		throw new Error(`corrupt catalog manifest at ${manifestPath}: ${parsed.error.message}`);
	}
	return parsed.data;
}

function writeManifestAtomic(root: string, manifest: HermesSkillCatalogManifest): string {
	const manifestPath = manifestPathFor(root);
	fs.mkdirSync(root, { recursive: true });
	const tempPath = path.join(
		root,
		`.${HERMES_SKILL_CATALOG_MANIFEST_FILENAME}.${process.pid}.${crypto.randomUUID()}.tmp`,
	);
	try {
		fs.writeFileSync(tempPath, `${JSON.stringify(manifest, null, 2)}\n`, {
			encoding: "utf8",
			mode: 0o600,
			flag: "wx",
		});
		fs.renameSync(tempPath, manifestPath);
	} catch (err) {
		fs.rmSync(tempPath, { force: true });
		throw err;
	}
	return manifestPath;
}

/**
 * Validate and atomically install a skill directory into the catalog,
 * recording {name, sha256, origin, installedAt} in the manifest.
 */
export function installSkillFromDir(
	srcDir: string,
	options: CatalogOptions & { origin: string },
): CatalogInstallResult {
	const validation = validateCatalogSkillDir(srcDir);
	if (!validation.ok) {
		throw new Error(`skill validation failed: ${validation.errors.join("; ")}`);
	}

	const root = catalogRootFrom(options);
	const skillsDir = catalogSkillsDir(root);
	fs.mkdirSync(skillsDir, { recursive: true });
	fs.chmodSync(root, 0o755);
	fs.chmodSync(skillsDir, 0o755);

	const targetDir = path.join(skillsDir, validation.name);
	const stagingDir = path.join(skillsDir, `.tmp-install-${crypto.randomUUID()}`);
	const replacedDir = path.join(skillsDir, `.tmp-replaced-${crypto.randomUUID()}`);
	try {
		copyTreeWithCatalogModes(path.resolve(srcDir), stagingDir);
		const sha256 = computeCatalogSkillSha256(stagingDir);
		if (fs.existsSync(targetDir)) {
			fs.renameSync(targetDir, replacedDir);
		}
		fs.renameSync(stagingDir, targetDir);
		fs.rmSync(replacedDir, { recursive: true, force: true });

		const installedAt = (options.now ?? new Date()).toISOString();
		const manifest = readManifest(root);
		const entry: HermesSkillCatalogManifestEntry = {
			name: validation.name,
			sha256,
			origin: options.origin,
			installedAt,
		};
		manifest.skills = [
			...manifest.skills.filter((existing) => existing.name !== validation.name),
			entry,
		].sort((a, b) => (a.name < b.name ? -1 : 1));
		const manifestPath = writeManifestAtomic(root, manifest);

		return { ...entry, targetDir, manifestPath };
	} finally {
		fs.rmSync(stagingDir, { recursive: true, force: true });
	}
}

/** Remove a skill from the catalog tree and manifest. */
export function removeSkill(name: string, options: CatalogOptions = {}): boolean {
	if (!CATALOG_SKILL_NAME_PATTERN.test(name)) {
		throw new Error(`invalid skill name "${name}"`);
	}
	const root = catalogRootFrom(options);
	const targetDir = path.join(catalogSkillsDir(root), name);
	const hadDir = fs.existsSync(targetDir);
	if (hadDir) {
		fs.rmSync(targetDir, { recursive: true, force: true });
	}
	const manifest = readManifest(root);
	const remaining = manifest.skills.filter((entry) => entry.name !== name);
	const hadEntry = remaining.length !== manifest.skills.length;
	if (hadEntry) {
		writeManifestAtomic(root, { ...manifest, skills: remaining });
	}
	return hadDir || hadEntry;
}

/** Manifest entries, sorted by name. */
export function listCatalog(options: CatalogOptions = {}): HermesSkillCatalogManifestEntry[] {
	return readManifest(catalogRootFrom(options)).skills;
}

export type RelaySkillCatalogState =
	| { readonly configured: false }
	| { readonly configured: true; readonly skillCount: number; readonly manifestSha256: string }
	| { readonly configured: true; readonly error: string };

/**
 * Canonical digest of the served catalog manifest: sha256 over the name-sorted
 * JSON of `{name, sha256}` pairs. Skills-allowlist catalog evidence carries
 * this digest so the cutover evaluator can bind the evidence to the exact
 * relay manifest it was probed against — stale or substituted evidence fails.
 */
export function catalogManifestDigestSha256(
	entries: ReadonlyArray<Pick<HermesSkillCatalogManifestEntry, "name" | "sha256">>,
): string {
	const canonical = entries
		.map(({ name, sha256 }) => ({ name, sha256 }))
		.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
	return crypto.createHash("sha256").update(JSON.stringify(canonical)).digest("hex");
}

/**
 * Relay-side catalog state for proof gating. The catalog is configured iff the
 * resolved catalog root exists on disk (the relay creates it on first install;
 * in Docker the mounted volume directory always exists). Fail-closed: an
 * unreadable manifest reports an error state instead of "not configured".
 */
export function resolveRelaySkillCatalogState(
	options: CatalogOptions = {},
): RelaySkillCatalogState {
	const root = catalogRootFrom(options);
	if (!fs.existsSync(root)) return { configured: false };
	try {
		const entries = listCatalog(options);
		return {
			configured: true,
			skillCount: entries.length,
			manifestSha256: catalogManifestDigestSha256(entries),
		};
	} catch (error) {
		return { configured: true, error: error instanceof Error ? error.message : String(error) };
	}
}

/**
 * Verify the on-disk catalog tree against the manifest: per-skill ok/drift,
 * plus missing manifest entries, invalid trees, and unmanaged directories.
 */
export function verifyCatalogAgainstManifest(options: CatalogOptions = {}): CatalogVerifyResult {
	const root = catalogRootFrom(options);
	const skillsDir = catalogSkillsDir(root);
	const manifest = readManifest(root);
	const skills: CatalogVerifyEntry[] = [];

	for (const entry of manifest.skills) {
		const dir = path.join(skillsDir, entry.name);
		if (!fs.existsSync(dir)) {
			skills.push({ name: entry.name, status: "missing", detail: "directory absent from catalog" });
			continue;
		}
		const validation = validateCatalogSkillDir(dir);
		if (!validation.ok) {
			skills.push({ name: entry.name, status: "invalid", detail: validation.errors.join("; ") });
			continue;
		}
		const sha256 = computeCatalogSkillSha256(dir);
		if (sha256 !== entry.sha256) {
			skills.push({
				name: entry.name,
				status: "drift",
				detail: `content hash ${sha256} does not match manifest ${entry.sha256}`,
			});
			continue;
		}
		skills.push({ name: entry.name, status: "ok" });
	}

	const managed = new Set(manifest.skills.map((entry) => entry.name));
	let onDisk: fs.Dirent[] = [];
	try {
		onDisk = fs.readdirSync(skillsDir, { withFileTypes: true });
	} catch {
		onDisk = [];
	}
	for (const entry of onDisk) {
		if (entry.name.startsWith(".") || managed.has(entry.name)) continue;
		skills.push({ name: entry.name, status: "unmanaged", detail: "directory not in manifest" });
	}

	return { ok: skills.every((entry) => entry.status === "ok"), skills };
}
