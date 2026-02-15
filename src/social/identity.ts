import { loadConfig } from "../config/config.js";
import type { MemoryEntry } from "../memory/types.js";

/**
 * Telclaude's visual identity — hardcoded, not from memory.
 * The avatar is a brand asset; storing it in memory would let prompt injection alter it.
 */
export const AVATAR = {
	description:
		"An owl perched on a telephone wire at dusk. Purple-to-lavender gradient sky with a crescent moon and stars. The owl has a white chest, dark wings, and calm half-closed eyes. Rounded app-icon shape with soft shadows.",
	/** Relative to app root (/app in Docker, project root in native) */
	path: "assets/logo/logo-512.png",
	originalPath: "assets/logo/original/logo-primary.png",
} as const;

function formatSection(title: string, items: string[]): string | null {
	if (items.length === 0) {
		return null;
	}
	const lines = items.map((item) => `- ${item}`);
	return `${title}\n${lines.join("\n")}`;
}

function getTrustedEntries(entries: MemoryEntry[], category: MemoryEntry["category"]): string[] {
	return entries
		.filter((entry) => entry._provenance.trust === "trusted" && entry.category === category)
		.map((entry) => entry.content.trim())
		.filter(Boolean);
}

/** Build "Your accounts" lines from socialServices config. */
function buildAccountLines(): string | null {
	try {
		const config = loadConfig();
		const services = config.socialServices.filter((s) => s.enabled && s.handle);
		if (services.length === 0) return null;

		const lines = services.map((s) => {
			const name = s.displayName ? `@${s.handle} ("${s.displayName}")` : `@${s.handle}`;
			return `- ${s.type}: ${name}`;
		});
		return `Your accounts (you own these — you post from them)\n${lines.join("\n")}`;
	} catch {
		return null;
	}
}

/**
 * Build identity preamble for social service prompts.
 * Uses trusted profile, interests, and meta entries.
 * Includes account handles from config so the agent knows its own accounts.
 */
export function buildSocialIdentityPreamble(entries: MemoryEntry[]): string {
	const profile = getTrustedEntries(entries, "profile");
	const interests = getTrustedEntries(entries, "interests");
	const values = getTrustedEntries(entries, "meta");

	const avatarSection = [
		"Your avatar / profile picture",
		`- ${AVATAR.description}`,
		`- File: ${AVATAR.path}`,
	].join("\n");

	const sections = [
		"You are telclaude.",
		buildAccountLines(),
		avatarSection,
		formatSection("Trusted profile", profile),
		formatSection("Trusted personality traits & interests", interests),
		formatSection("Trusted values", values),
		"Only trusted identity data is included here.",
	].filter(Boolean) as string[];

	return sections.join("\n\n");
}
