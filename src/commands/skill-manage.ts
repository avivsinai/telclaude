/**
 * Managed skill writer for agent-authored skills.
 *
 * Slice B intentionally supports create only. It writes exclusively under
 * `.claude/skills/agent/...`, never the user-authored skill namespace.
 */

import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { Command } from "commander";
import type { PermissionTier } from "../config/config.js";
import { BLOCKED_METADATA_DOMAINS } from "../sandbox/config.js";
import { isNonOverridableBlock, isPrivateIP } from "../sandbox/network-proxy.js";
import { filterOutput } from "../security/output-filter.js";
import { TIER_TOOLS } from "../security/permissions.js";
import { type ScanResult, scanSkill } from "../security/skill-scanner.js";
import { CONFIG_DIR } from "../utils.js";
import { getAllSkillRoots, getSkillRoot, SkillRootUnavailableError } from "./skill-path.js";

const SKILL_NAME_PATTERN = /^[a-z0-9-]{1,63}$/;
const SERVICE_ID_PATTERN = /^[a-z0-9-]{1,63}$/;
const MAX_SKILL_MARKDOWN_BYTES = 64 * 1024;
const MAX_SNAPSHOTS_PER_PERSONA = 30;
const AUDIT_FILENAME = "skills-manage-audit.jsonl";

const SENSITIVE_ABSOLUTE_PATH_PREFIXES = [
	"/bin",
	"/boot",
	"/dev",
	"/etc",
	"/home",
	"/Library",
	"/lib",
	"/lib64",
	"/mnt",
	"/opt",
	"/private",
	"/proc",
	"/root",
	"/run",
	"/sbin",
	"/srv",
	"/sys",
	"/System",
	"/tmp",
	"/Users",
	"/usr",
	"/var",
];

const KNOWN_TOOLS = new Set([
	"Read",
	"Write",
	"Edit",
	"Glob",
	"Grep",
	"Bash",
	"WebFetch",
	"WebSearch",
	"NotebookEdit",
	"Skill",
	"Task",
]);

const INFRA_SECRET_NAMES = [
	"ANTHROPIC_API_KEY",
	"OPENAI_API_KEY",
	"TELEGRAM_BOT_TOKEN",
	"GITHUB_TOKEN",
	"GH_TOKEN",
	"AWS_SECRET_ACCESS_KEY",
	"AWS_SECRET",
];

type SkillManagePersona = { kind: "telegram" } | { kind: "social"; serviceId: string };

export type CreateManagedSkillOptions = {
	name: string;
	markdown: string;
	persona: SkillManagePersona;
	actorTier: PermissionTier;
	userId?: string;
	cwd?: string;
	skillRoot?: string;
	snapshotRoot?: string;
	auditPath?: string;
	now?: Date;
};

type ScanAuditSummary =
	| {
			blocked: boolean;
			counts: ScanResult["counts"];
			findings: Array<{ rule: string; severity: string; file: string; line?: number }>;
			skipped?: false;
	  }
	| { blocked: false; skipped: true; reason: string };

export type SkillManageAuditEntry = {
	ts: string;
	persona: string;
	service_id?: string;
	action: "create";
	skill_name: string;
	content_sha256: string;
	scanner_result: ScanAuditSummary;
	success: boolean;
	error?: string;
};

export type CreateManagedSkillResult =
	| {
			success: true;
			skillName: string;
			targetDir: string;
			skillMdPath: string;
			snapshotPath: string;
			auditPath: string;
	  }
	| {
			success: false;
			skillName: string;
			error: string;
			snapshotPath?: string;
			auditPath?: string;
			scanBlocked?: boolean;
	  };

type ParsedFrontmatter = {
	fields: Record<string, string>;
	allowedTools: string[];
};

function isPermissionTier(value: string): value is PermissionTier {
	return (
		value === "READ_ONLY" ||
		value === "WRITE_LOCAL" ||
		value === "FULL_ACCESS" ||
		value === "SOCIAL"
	);
}

function personaKey(persona: SkillManagePersona): string {
	return persona.kind === "telegram" ? "telegram" : `social-${persona.serviceId}`;
}

function sha256(content: string): string {
	return crypto.createHash("sha256").update(content).digest("hex");
}

function resolveInsideRoot(root: string, candidate: string, label: string): string {
	const resolvedRoot = path.resolve(root);
	const resolvedCandidate = path.resolve(candidate);
	const rootWithSep = resolvedRoot.endsWith(path.sep) ? resolvedRoot : `${resolvedRoot}${path.sep}`;
	if (resolvedCandidate !== resolvedRoot && !resolvedCandidate.startsWith(rootWithSep)) {
		throw new Error(`${label} must stay within the skill root.`);
	}
	return resolvedCandidate;
}

function resolveTargetDir(
	skillRoot: string,
	persona: SkillManagePersona,
	skillName: string,
): string {
	if (persona.kind === "telegram") {
		return resolveInsideRoot(
			skillRoot,
			path.join(skillRoot, "agent", "telegram", skillName),
			"target skill path",
		);
	}
	return resolveInsideRoot(
		skillRoot,
		path.join(skillRoot, "agent", "social", persona.serviceId, skillName),
		"target skill path",
	);
}

function parseFrontmatter(content: string): ParsedFrontmatter | null {
	const match = content.match(/^---\s*\n([\s\S]*?)\n---/);
	if (!match) return null;

	const fields: Record<string, string> = {};
	const allowedTools: string[] = [];
	let currentKey: string | null = null;
	let collectingAllowedTools = false;

	for (const rawLine of match[1].split("\n")) {
		const line = rawLine.replace(/\r$/, "");
		if (!line.trim()) continue;

		const keyMatch = line.match(/^(\w[\w.-]*)\s*:\s*(.*)$/);
		if (keyMatch) {
			currentKey = keyMatch[1];
			const value = keyMatch[2].trim();
			fields[currentKey] = value;
			collectingAllowedTools = currentKey === "allowed-tools" && value.length === 0;
			if (currentKey === "allowed-tools" && value.length > 0) {
				for (const tool of splitAllowedToolsValue(value)) {
					allowedTools.push(tool);
				}
			}
			continue;
		}

		if (collectingAllowedTools && /^\s*-\s+/.test(line)) {
			const tool = line
				.replace(/^\s*-\s+/, "")
				.trim()
				.replace(/^['"]|['"]$/g, "");
			if (tool) allowedTools.push(tool);
			continue;
		}

		if (currentKey && /^\s+/.test(line)) {
			fields[currentKey] = `${fields[currentKey] ?? ""} ${line.trim()}`.trim();
		}
	}

	return { fields, allowedTools };
}

function splitAllowedToolsValue(value: string): string[] {
	const trimmed = value.replace(/^\[|\]$/g, "").trim();
	if (!trimmed) return [];
	return trimmed
		.split(",")
		.map((tool) => tool.trim().replace(/^['"]|['"]$/g, ""))
		.filter(Boolean);
}

function validateFrontmatter(
	markdown: string,
	skillName: string,
	actorTier: PermissionTier,
): string | null {
	const parsed = parseFrontmatter(markdown);
	if (!parsed) {
		return "SKILL.md must include YAML frontmatter.";
	}

	const declaredName = parsed.fields.name?.trim();
	if (!declaredName) {
		return "Skill frontmatter must include name.";
	}
	if (declaredName !== skillName) {
		return `Skill frontmatter name "${declaredName}" must match "${skillName}".`;
	}
	if (!parsed.fields.description?.trim()) {
		return "Skill frontmatter must include description.";
	}

	const tierTools = actorTier === "FULL_ACCESS" ? KNOWN_TOOLS : new Set(TIER_TOOLS[actorTier]);
	for (const tool of parsed.allowedTools) {
		if (!KNOWN_TOOLS.has(tool)) {
			return `Skill frontmatter declares unknown tool "${tool}".`;
		}
		if (!tierTools.has(tool)) {
			return `Skill frontmatter declares "${tool}", which is beyond ${actorTier}.`;
		}
	}

	return null;
}

function findUrls(markdown: string): string[] {
	return [...markdown.matchAll(/\bhttps?:\/\/[^\s<>"'`)]+/g)].map((match) => match[0]);
}

function isBlockedMetadataHost(hostname: string): boolean {
	const host = hostname.toLowerCase();
	return BLOCKED_METADATA_DOMAINS.some((blocked) => blocked.toLowerCase() === host);
}

function validateUrls(markdown: string): string | null {
	for (const rawUrl of findUrls(markdown)) {
		let parsed: URL;
		try {
			parsed = new URL(rawUrl);
		} catch {
			continue;
		}
		const host = parsed.hostname.replace(/^\[|\]$/g, "");
		if (isBlockedMetadataHost(host) || isNonOverridableBlock(host) || isPrivateIP(host)) {
			return `Skill body references blocked private or metadata URL: ${rawUrl}`;
		}
	}
	return null;
}

function validateInfraSecrets(markdown: string): string | null {
	for (const name of INFRA_SECRET_NAMES) {
		if (new RegExp(`\\b${name}\\b`).test(markdown)) {
			return `Skill body references infrastructure secret ${name}.`;
		}
	}
	return null;
}

function validateInfraSecretValues(markdown: string): string | null {
	const result = filterOutput(markdown);
	if (!result.blocked) return null;
	const match = result.matches[0];
	return `Skill body contains secret-looking value (${match.pattern}).`;
}

function validateShellBlocks(markdown: string): string | null {
	const shellBlockPattern = /```(?:bash|sh|shell|zsh)\s*\n([\s\S]*?)```/gi;
	let match = shellBlockPattern.exec(markdown);
	while (match !== null) {
		const body = match[1];
		for (const rawLine of body.split("\n")) {
			const line = rawLine.trim();
			if (!line || line.startsWith("#")) continue;
			if (/[;&`]/.test(line) || /\|\|?/.test(line) || /\$\(/.test(line) || /[<>]\(/.test(line)) {
				return "Bash examples in managed skills must not contain shell chaining, pipes, command substitution, or process substitution.";
			}
			if (/\s[<>]{1,2}\s*\S/.test(line)) {
				return "Bash examples in managed skills must not contain shell redirection.";
			}
		}
		match = shellBlockPattern.exec(markdown);
	}
	return null;
}

function validateFileReadTargets(markdown: string): string | null {
	const absolutePathPattern = /(^|[\s('"`])\/[A-Za-z0-9._/-]+/g;
	let match = absolutePathPattern.exec(markdown);
	while (match !== null) {
		const candidate = match[0].trim().replace(/^['"`(]/, "");
		const allowed =
			candidate === "/workspace" ||
			candidate.startsWith("/workspace/") ||
			candidate === "/media/inbox" ||
			candidate.startsWith("/media/inbox/") ||
			candidate === "/media/outbox" ||
			candidate.startsWith("/media/outbox/");
		const sensitive = SENSITIVE_ABSOLUTE_PATH_PREFIXES.some(
			(prefix) => candidate === prefix || candidate.startsWith(`${prefix}/`),
		);
		if (!allowed && sensitive) {
			return `Skill body references path outside the workspace/media allowlist: ${candidate}`;
		}
		match = absolutePathPattern.exec(markdown);
	}
	return null;
}

function validateMarkdownStatic(
	markdown: string,
	skillName: string,
	actorTier: PermissionTier,
): string | null {
	const size = Buffer.byteLength(markdown, "utf8");
	if (size > MAX_SKILL_MARKDOWN_BYTES) {
		return `SKILL.md exceeds ${MAX_SKILL_MARKDOWN_BYTES} bytes.`;
	}

	return (
		validateFrontmatter(markdown, skillName, actorTier) ??
		validateUrls(markdown) ??
		validateInfraSecrets(markdown) ??
		validateInfraSecretValues(markdown) ??
		validateShellBlocks(markdown) ??
		validateFileReadTargets(markdown)
	);
}

function isDirLike(dir: string): boolean {
	try {
		return fs.statSync(dir).isDirectory();
	} catch {
		return false;
	}
}

type SkillNameCollision = {
	root: string;
	relativeDir: string;
};

function addCollisionIfSkill(
	collisions: SkillNameCollision[],
	root: string,
	relativeDir: string,
): void {
	const skillDir = path.join(root, relativeDir);
	if (fs.existsSync(path.join(skillDir, "SKILL.md"))) {
		collisions.push({ root, relativeDir });
	}
}

function findSkillNameCollisions(name: string, roots: readonly string[]): SkillNameCollision[] {
	const collisions: SkillNameCollision[] = [];
	const seen = new Set<string>();
	for (const root of roots) {
		const resolvedRoot = path.resolve(root);
		if (seen.has(resolvedRoot)) continue;
		seen.add(resolvedRoot);

		addCollisionIfSkill(collisions, resolvedRoot, name);
		addCollisionIfSkill(collisions, resolvedRoot, path.join("agent", "telegram", name));

		const socialRoot = path.join(resolvedRoot, "agent", "social");
		let serviceEntries: fs.Dirent[] = [];
		try {
			serviceEntries = fs.readdirSync(socialRoot, { withFileTypes: true });
		} catch {
			serviceEntries = [];
		}
		for (const entry of serviceEntries) {
			if (entry.name.startsWith(".") || entry.name === "archived") continue;
			const serviceDir = path.join(socialRoot, entry.name);
			if (!entry.isDirectory() && !(entry.isSymbolicLink() && isDirLike(serviceDir))) continue;
			addCollisionIfSkill(collisions, resolvedRoot, path.join("agent", "social", entry.name, name));
		}
	}
	return collisions;
}

function summarizeScan(scanResult: ScanResult): ScanAuditSummary {
	return {
		blocked: scanResult.blocked,
		counts: scanResult.counts,
		findings: scanResult.findings.map((finding) => ({
			rule: finding.rule,
			severity: finding.severity,
			file: finding.file,
			...(finding.line ? { line: finding.line } : {}),
		})),
	};
}

function defaultAuditPath(): string {
	return path.join(CONFIG_DIR, AUDIT_FILENAME);
}

function appendAudit(entry: SkillManageAuditEntry, auditPath?: string): string {
	const targetPath = auditPath ?? defaultAuditPath();
	fs.mkdirSync(path.dirname(targetPath), { recursive: true, mode: 0o700 });
	const existed = fs.existsSync(targetPath);
	fs.appendFileSync(targetPath, `${JSON.stringify(entry)}\n`, { encoding: "utf8", mode: 0o600 });
	if (!existed) {
		try {
			fs.chmodSync(targetPath, 0o600);
		} catch {
			// best-effort on filesystems that do not support chmod
		}
	}
	return targetPath;
}

export function createSkillSnapshot(options: {
	skillRoot: string;
	persona: SkillManagePersona;
	action: "create";
	snapshotRoot?: string;
	now?: Date;
}): string {
	const skillRoot = path.resolve(options.skillRoot);
	fs.mkdirSync(skillRoot, { recursive: true });

	const snapshotDir =
		options.snapshotRoot ?? path.join(CONFIG_DIR, "skills-snapshots", personaKey(options.persona));
	fs.mkdirSync(snapshotDir, { recursive: true, mode: 0o700 });

	const timestamp = (options.now ?? new Date()).toISOString().replace(/[:.]/g, "-");
	const snapshotPath = path.join(snapshotDir, `${timestamp}-${options.action}.tar.gz`);
	const tar = spawnSync("tar", ["-czf", snapshotPath, "-C", skillRoot, "."], {
		encoding: "utf8",
	});
	if (tar.status !== 0) {
		throw new Error(`Failed to create skill snapshot: ${tar.stderr || tar.stdout || "tar failed"}`);
	}

	const snapshots = fs
		.readdirSync(snapshotDir)
		.filter((entry) => entry.endsWith(".tar.gz"))
		.sort();
	for (const stale of snapshots.slice(
		0,
		Math.max(0, snapshots.length - MAX_SNAPSHOTS_PER_PERSONA),
	)) {
		fs.rmSync(path.join(snapshotDir, stale), { force: true });
	}

	return snapshotPath;
}

function skippedScan(reason: string): ScanAuditSummary {
	return { blocked: false, skipped: true, reason };
}

export function createManagedSkill(options: CreateManagedSkillOptions): CreateManagedSkillResult {
	const skillName = options.name.trim();
	const contentHash = sha256(options.markdown);
	const personaLabel = personaKey(options.persona);
	let scannerResult: ScanAuditSummary = skippedScan("not_started");
	let tempRoot: string | undefined;

	type SuccessPayload = Omit<
		Extract<CreateManagedSkillResult, { success: true }>,
		"success" | "skillName" | "auditPath"
	>;
	type FailurePayload = Omit<
		Extract<CreateManagedSkillResult, { success: false }>,
		"success" | "skillName" | "auditPath"
	>;

	function finish(
		success: true,
		result: SuccessPayload,
	): Extract<CreateManagedSkillResult, { success: true }>;
	function finish(
		success: false,
		result: FailurePayload,
	): Extract<CreateManagedSkillResult, { success: false }>;
	function finish(
		success: boolean,
		result: SuccessPayload | FailurePayload,
	): CreateManagedSkillResult {
		const auditPath = appendAudit(
			{
				ts: (options.now ?? new Date()).toISOString(),
				persona: personaLabel,
				...(options.persona.kind === "social" ? { service_id: options.persona.serviceId } : {}),
				action: "create",
				skill_name: skillName || options.name,
				content_sha256: contentHash,
				scanner_result: scannerResult,
				success,
				...(!success && "error" in result ? { error: result.error } : {}),
			},
			options.auditPath,
		);

		if (success) {
			return { success: true, skillName, auditPath, ...(result as SuccessPayload) };
		}
		return { success: false, skillName, auditPath, ...(result as FailurePayload) };
	}

	try {
		if (options.actorTier === "SOCIAL" || options.userId?.startsWith("social:")) {
			return finish(false, {
				error: "SOCIAL tier cannot use skill_manage.",
			});
		}
		if (options.actorTier === "READ_ONLY") {
			return finish(false, {
				error: "skill_manage create requires WRITE_LOCAL or FULL_ACCESS.",
			});
		}
		if (options.persona.kind === "social" && !SERVICE_ID_PATTERN.test(options.persona.serviceId)) {
			return finish(false, {
				error: `Invalid social service id "${options.persona.serviceId}". Must match ${SERVICE_ID_PATTERN}.`,
			});
		}
		if (!SKILL_NAME_PATTERN.test(skillName)) {
			return finish(false, {
				error: `Invalid skill name "${skillName}". Must match ${SKILL_NAME_PATTERN}.`,
			});
		}

		const validationError = validateMarkdownStatic(options.markdown, skillName, options.actorTier);
		if (validationError) {
			scannerResult = skippedScan("static_validation_failed");
			return finish(false, { error: validationError });
		}

		let skillRoot: string;
		try {
			skillRoot = path.resolve(options.skillRoot ?? getSkillRoot(options.cwd));
		} catch (err) {
			if (err instanceof SkillRootUnavailableError) {
				return finish(false, { error: err.message });
			}
			throw err;
		}

		const targetDir = resolveTargetDir(skillRoot, options.persona, skillName);
		const roots = [skillRoot, ...getAllSkillRoots(options.cwd)];
		const collisions = findSkillNameCollisions(skillName, roots);
		if (collisions.length > 0) {
			const collision = collisions[0];
			return finish(false, {
				error: `Skill name "${skillName}" already exists at ${path.join(collision.root, collision.relativeDir)}.`,
			});
		}
		if (fs.existsSync(targetDir)) {
			return finish(false, {
				error: `Target skill directory already exists at ${targetDir}.`,
			});
		}

		tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-skill-manage-"));
		const tempSkillDir = path.join(tempRoot, skillName);
		fs.mkdirSync(tempSkillDir, { recursive: true });
		fs.writeFileSync(path.join(tempSkillDir, "SKILL.md"), options.markdown, "utf8");

		const scanResult = scanSkill(tempSkillDir, {
			repoRoot: options.cwd ? path.resolve(options.cwd) : process.cwd(),
		});
		scannerResult = summarizeScan(scanResult);
		if (scanResult.blocked) {
			const summary = scanResult.findings
				.filter((finding) => finding.severity === "critical" || finding.severity === "high")
				.map((finding) => `${finding.severity.toUpperCase()}: ${finding.message}`)
				.join("; ");
			return finish(false, {
				error: `Skill "${skillName}" blocked by scanner: ${summary}`,
				scanBlocked: true,
			});
		}

		const snapshotPath = createSkillSnapshot({
			skillRoot,
			persona: options.persona,
			action: "create",
			snapshotRoot: options.snapshotRoot,
			now: options.now,
		});

		try {
			fs.mkdirSync(path.dirname(targetDir), { recursive: true });
			fs.mkdirSync(targetDir);
			fs.writeFileSync(path.join(targetDir, "SKILL.md"), options.markdown, "utf8");
		} catch (err) {
			fs.rmSync(targetDir, { recursive: true, force: true });
			return finish(false, {
				error: `Failed to write managed skill: ${String(err)}`,
				snapshotPath,
			});
		}

		return finish(true, {
			targetDir,
			skillMdPath: path.join(targetDir, "SKILL.md"),
			snapshotPath,
		});
	} catch (err) {
		return finish(false, { error: err instanceof Error ? err.message : String(err) });
	} finally {
		if (tempRoot) {
			fs.rmSync(tempRoot, { recursive: true, force: true });
		}
	}
}

async function readStdin(): Promise<string> {
	const chunks: Buffer[] = [];
	for await (const chunk of process.stdin) {
		chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
	}
	return Buffer.concat(chunks).toString("utf8");
}

async function readMarkdownInput(filePath?: string): Promise<string> {
	if (!filePath || filePath === "-") {
		return readStdin();
	}
	return fs.readFileSync(path.resolve(filePath), "utf8");
}

function parsePersonaOptions(opts: { persona?: string; serviceId?: string }): SkillManagePersona {
	const persona = opts.persona?.trim();
	if (persona === "telegram") return { kind: "telegram" };
	if (persona === "social") {
		const serviceId = opts.serviceId?.trim();
		if (!serviceId) {
			throw new Error("--service-id is required when --persona social.");
		}
		return { kind: "social", serviceId };
	}
	throw new Error('--persona must be either "telegram" or "social".');
}

function printResult(result: CreateManagedSkillResult, json: boolean): void {
	if (json) {
		console.log(JSON.stringify(result, null, 2));
		return;
	}
	if (result.success) {
		console.log(`Created managed skill "${result.skillName}".`);
		console.log(`  SKILL.md: ${result.skillMdPath}`);
		console.log(`  Snapshot: ${result.snapshotPath}`);
		return;
	}
	console.error(`Error: ${result.error}`);
}

export function registerSkillManageSubcommands(parent: Command): void {
	const group = parent
		.command("skill-manage")
		.description("Create agent-authored skills with scanner, snapshot, and audit guards");

	group
		.command("create")
		.description("Create an agent-authored managed skill")
		.requiredOption("--name <name>", "Skill name (^[a-z0-9-]{1,63}$)")
		.requiredOption("--persona <persona>", "Target persona: telegram or social")
		.option("--service-id <id>", "Social service id when --persona social")
		.requiredOption("--actor-tier <tier>", "Request permission tier")
		.option("--user-id <id>", "Actor user id (defaults to TELCLAUDE_REQUEST_USER_ID)")
		.option("--file <path>", "Read SKILL.md from file; omit or '-' for stdin", "-")
		.option("--json", "Emit JSON", false)
		.action(
			async (opts: {
				name: string;
				persona: string;
				serviceId?: string;
				actorTier: string;
				userId?: string;
				file?: string;
				json?: boolean;
			}) => {
				try {
					const actorTier = process.env.TELCLAUDE_REQUEST_TIER ?? opts.actorTier;
					if (!isPermissionTier(actorTier)) {
						throw new Error(`Invalid actor tier "${actorTier}".`);
					}
					const persona = parsePersonaOptions(opts);
					const markdown = await readMarkdownInput(opts.file);
					const result = createManagedSkill({
						name: opts.name,
						markdown,
						persona,
						actorTier,
						userId: process.env.TELCLAUDE_REQUEST_USER_ID ?? opts.userId,
					});
					printResult(result, Boolean(opts.json));
					if (!result.success) process.exitCode = 1;
				} catch (err) {
					const message = err instanceof Error ? err.message : String(err);
					if (opts.json) {
						console.log(JSON.stringify({ success: false, error: message }, null, 2));
					} else {
						console.error(`Error: ${message}`);
					}
					process.exitCode = 1;
				}
			},
		);
}
