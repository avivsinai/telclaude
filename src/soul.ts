import fs from "node:fs";
import path from "node:path";

let cached: string | null = null;

export function loadSoul(): string {
	if (cached !== null) return cached;
	// Try app bundle first (Docker), then project root (native)
	for (const base of ["/app", process.cwd()]) {
		const p = path.join(base, "docs/soul.md");
		try {
			cached = fs.readFileSync(p, "utf-8").trim();
			return cached;
		} catch {
			/* continue */
		}
	}
	cached = "";
	return cached;
}
