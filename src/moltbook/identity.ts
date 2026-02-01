import type { MemoryEntry } from "../memory/types.js";

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

export function buildMoltbookIdentityPreamble(entries: MemoryEntry[]): string {
	const profile = getTrustedEntries(entries, "profile");
	const interests = getTrustedEntries(entries, "interests");
	const values = getTrustedEntries(entries, "meta");

	const sections = [
		"You are telclaude.",
		formatSection("Trusted profile", profile),
		formatSection("Trusted personality traits & interests", interests),
		formatSection("Trusted values", values),
		"Only trusted identity data is included here.",
	].filter(Boolean) as string[];

	return sections.join("\n\n");
}
