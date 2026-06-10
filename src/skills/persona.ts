import fs from "node:fs";
import path from "node:path";
import { getAllSkillRoots } from "../commands/skill-path.js";
import { getChildLogger } from "../logging.js";

const logger = getChildLogger({ module: "skill-persona" });

const AGENT_DIR = "agent";
const TELEGRAM_DIR = "telegram";
const SOCIAL_DIR = "social";
const ARCHIVED_DIR = "archived";

export type SkillPersonaContext =
	| { kind: "telegram" }
	| { kind: "social"; serviceId: string; allowedAgentSkills?: readonly string[] };

export type SkillProvenance =
	| { kind: "user" }
	| { kind: "agent"; persona: "telegram" }
	| { kind: "agent"; persona: "social"; serviceId: string };

export type SkillInventoryEntry = {
	name: string;
	root: string;
	dir: string;
	relativeDir: string;
	provenance: SkillProvenance;
};

export type BlockedSkillEntry = SkillInventoryEntry & {
	reason: "persona_mismatch" | "service_mismatch" | "agent_skill_not_allowed" | "name_collision";
};

export type SkillLoadPlan = {
	context: SkillPersonaContext;
	userAuthored: SkillInventoryEntry[];
	agentAuthored: SkillInventoryEntry[];
	blocked: BlockedSkillEntry[];
	names: string[];
};

function isDirLike(dir: string): boolean {
	try {
		return fs.statSync(dir).isDirectory();
	} catch {
		return false;
	}
}

function readDirSafe(dir: string): fs.Dirent[] {
	try {
		return fs.readdirSync(dir, { withFileTypes: true });
	} catch {
		return [];
	}
}

function hasSkillMd(dir: string): boolean {
	return fs.existsSync(path.join(dir, "SKILL.md"));
}

function isVisibleDirEntry(root: string, entry: fs.Dirent): boolean {
	if (entry.name.startsWith(".")) return false;
	const fullPath = path.join(root, entry.name);
	return entry.isDirectory() || entry.isSymbolicLink() ? isDirLike(fullPath) : false;
}

function addIfSkill(
	out: SkillInventoryEntry[],
	root: string,
	dir: string,
	relativeDir: string,
	provenance: SkillProvenance,
): void {
	if (!hasSkillMd(dir)) return;
	const normalizedRelativeDir = relativeDir.split(path.sep).join("/");
	out.push({
		name: path.basename(dir),
		root,
		dir,
		relativeDir: normalizedRelativeDir,
		provenance,
	});
}

function realPathSafe(dir: string): string {
	try {
		return fs.realpathSync.native(dir);
	} catch {
		return dir;
	}
}

function collectUserSkills(
	root: string,
	out: SkillInventoryEntry[],
	relativeRoot = "",
	seen = new Set<string>(),
): void {
	const dirRoot = relativeRoot ? path.join(root, relativeRoot) : root;
	const realDirRoot = realPathSafe(dirRoot);
	if (seen.has(realDirRoot)) return;
	seen.add(realDirRoot);
	for (const entry of readDirSafe(dirRoot)) {
		if (!relativeRoot && entry.name === AGENT_DIR) continue;
		if (!isVisibleDirEntry(dirRoot, entry)) continue;
		const relativeDir = relativeRoot ? path.join(relativeRoot, entry.name) : entry.name;
		const dir = path.join(root, relativeDir);
		addIfSkill(out, root, dir, relativeDir, { kind: "user" });
		collectUserSkills(root, out, relativeDir, seen);
	}
}

function collectAgentTelegramSkills(root: string, out: SkillInventoryEntry[]): void {
	const telegramRoot = path.join(root, AGENT_DIR, TELEGRAM_DIR);
	for (const entry of readDirSafe(telegramRoot)) {
		if (entry.name === ARCHIVED_DIR || !isVisibleDirEntry(telegramRoot, entry)) continue;
		const relativeDir = path.join(AGENT_DIR, TELEGRAM_DIR, entry.name);
		addIfSkill(out, root, path.join(telegramRoot, entry.name), relativeDir, {
			kind: "agent",
			persona: "telegram",
		});
	}
}

function collectAgentSocialSkills(root: string, out: SkillInventoryEntry[]): void {
	const socialRoot = path.join(root, AGENT_DIR, SOCIAL_DIR);
	for (const serviceEntry of readDirSafe(socialRoot)) {
		if (!isVisibleDirEntry(socialRoot, serviceEntry)) continue;
		const serviceId = serviceEntry.name;
		const serviceRoot = path.join(socialRoot, serviceId);
		for (const skillEntry of readDirSafe(serviceRoot)) {
			if (skillEntry.name === ARCHIVED_DIR || !isVisibleDirEntry(serviceRoot, skillEntry)) {
				continue;
			}
			const relativeDir = path.join(AGENT_DIR, SOCIAL_DIR, serviceId, skillEntry.name);
			addIfSkill(out, root, path.join(serviceRoot, skillEntry.name), relativeDir, {
				kind: "agent",
				persona: "social",
				serviceId,
			});
		}
	}
}

export function listSkillInventory(cwd: string = process.cwd()): SkillInventoryEntry[] {
	const entries: SkillInventoryEntry[] = [];
	for (const root of getAllSkillRoots(cwd)) {
		collectUserSkills(root, entries);
		collectAgentTelegramSkills(root, entries);
		collectAgentSocialSkills(root, entries);
	}
	return entries;
}

function classifyBlockReason(
	entry: SkillInventoryEntry,
	context: SkillPersonaContext,
): BlockedSkillEntry["reason"] | null {
	if (entry.provenance.kind === "user") return null;
	if (entry.provenance.persona === "telegram") {
		return context.kind === "telegram" ? null : "persona_mismatch";
	}
	if (context.kind !== "social") return "persona_mismatch";
	if (entry.provenance.serviceId !== context.serviceId) return "service_mismatch";
	if (!new Set(context.allowedAgentSkills ?? []).has(entry.name)) {
		return "agent_skill_not_allowed";
	}
	return null;
}

function dedupeByName(entries: readonly SkillInventoryEntry[]): SkillInventoryEntry[] {
	const seen = new Set<string>();
	const deduped: SkillInventoryEntry[] = [];
	for (const entry of entries) {
		if (seen.has(entry.name)) continue;
		seen.add(entry.name);
		deduped.push(entry);
	}
	return deduped.sort((left, right) => left.name.localeCompare(right.name));
}

function skillProvenanceKey(provenance: SkillProvenance): string {
	if (provenance.kind === "user") return "user";
	if (provenance.persona === "telegram") return "agent:telegram";
	return `agent:social:${provenance.serviceId}`;
}

function skillIdentityKey(entry: SkillInventoryEntry): string {
	return `${skillProvenanceKey(entry.provenance)}\0${entry.relativeDir}`;
}

export function buildSkillLoadPlan(
	context: SkillPersonaContext,
	options?: { cwd?: string; requestedSkillNames?: readonly string[] | null },
): SkillLoadPlan {
	const requested = options?.requestedSkillNames ? new Set(options.requestedSkillNames) : null;
	const userAuthored: SkillInventoryEntry[] = [];
	const agentAuthored: SkillInventoryEntry[] = [];
	const blocked: BlockedSkillEntry[] = [];
	const inventory = listSkillInventory(options?.cwd);
	const inventoryByName = new Map<string, SkillInventoryEntry[]>();
	for (const entry of inventory) {
		const prior = inventoryByName.get(entry.name);
		if (prior) {
			prior.push(entry);
		} else {
			inventoryByName.set(entry.name, [entry]);
		}
	}
	const collidingNames = new Set(
		Array.from(inventoryByName.entries())
			.filter(([, entries]) => new Set(entries.map(skillIdentityKey)).size > 1)
			.map(([name]) => name),
	);

	for (const entry of inventory) {
		const reason = collidingNames.has(entry.name)
			? "name_collision"
			: classifyBlockReason(entry, context);
		if (reason) {
			const blockedEntry = { ...entry, reason };
			blocked.push(blockedEntry);
			if (requested?.has(entry.name) || requested?.has(entry.relativeDir)) {
				logger.warn(
					{
						skillName: entry.name,
						relativeDir: entry.relativeDir,
						reason,
						context,
					},
					"skill excluded from persona load plan",
				);
			}
			continue;
		}
		if (entry.provenance.kind === "user") {
			userAuthored.push(entry);
		} else {
			agentAuthored.push(entry);
		}
	}

	const loadable = dedupeByName([...userAuthored, ...agentAuthored]);
	const names = loadable.map((entry) => entry.name);
	return {
		context,
		userAuthored: dedupeByName(userAuthored),
		agentAuthored: dedupeByName(agentAuthored),
		blocked,
		names,
	};
}

export function resolveSkillPersonaContext(options: {
	tier: string;
	userId?: string;
	telemetrySource?: "telegram" | "social";
	telemetryServiceId?: string;
	allowedAgentSkills?: readonly string[];
}): SkillPersonaContext {
	if (options.telemetrySource === "social" || options.tier === "SOCIAL") {
		const serviceId =
			options.telemetryServiceId ?? /^social:([^:\s]+)/.exec(options.userId ?? "")?.[1];
		return {
			kind: "social",
			serviceId: serviceId ?? "social",
			allowedAgentSkills: options.allowedAgentSkills ?? [],
		};
	}
	return { kind: "telegram" };
}
