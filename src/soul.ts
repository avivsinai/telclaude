import fs from "node:fs";
import path from "node:path";

import { getChildLogger } from "./logging.js";
import { resolveInsideRoot } from "./path-safety.js";

const logger = getChildLogger({ module: "soul" });

let cachedProjectSoul: string | null = null;

export type SoulProfile = {
	id: string;
	label: string;
	soulPath?: string;
};

function escXmlAttr(value: string): string {
	return value
		.replace(/&/g, "&amp;")
		.replace(/"/g, "&quot;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;");
}

export function loadProjectSoul(): string {
	if (cachedProjectSoul !== null) return cachedProjectSoul;
	// Try app bundle first (Docker), then project root (native)
	for (const base of ["/app", process.cwd()]) {
		const p = path.join(base, "docs/soul.md");
		try {
			cachedProjectSoul = fs.readFileSync(p, "utf-8").trim();
			return cachedProjectSoul;
		} catch {
			/* continue */
		}
	}
	cachedProjectSoul = "";
	return cachedProjectSoul;
}

export const loadSoul = loadProjectSoul;

export function loadProfileSoul(
	profile: SoulProfile | null | undefined,
	options: { cwd?: string } = {},
): string {
	if (!profile?.soulPath) return "";
	try {
		const root = options.cwd ?? process.cwd();
		const soulPath = resolveInsideRoot(profile.soulPath, root, `profile ${profile.id} soulPath`);
		return fs.readFileSync(soulPath, "utf-8").trim();
	} catch (err) {
		logger.warn({ profileId: profile.id, error: String(err) }, "profile soul overlay unavailable");
		return "";
	}
}

export function buildSoulPromptAppend(
	profile: SoulProfile | null | undefined,
	options: { includeProjectSoul: boolean; cwd?: string } = { includeProjectSoul: true },
): string | undefined {
	const parts: string[] = [];
	if (options.includeProjectSoul) {
		const projectSoul = loadProjectSoul();
		if (projectSoul) parts.push(`<soul>\n${projectSoul}\n</soul>`);
	}
	const profileSoul = loadProfileSoul(profile, { cwd: options.cwd });
	if (profile && profileSoul) {
		parts.push(
			`<profile-soul id="${escXmlAttr(profile.id)}" label="${escXmlAttr(profile.label)}">\n${profileSoul}\n</profile-soul>`,
		);
	}
	return parts.length > 0 ? parts.join("\n\n") : undefined;
}
