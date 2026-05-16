import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

describe("soul prompt helpers", () => {
	let tempDir: string;
	const originalCwd = process.cwd();

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-soul-"));
		fs.mkdirSync(path.join(tempDir, "profiles"), { recursive: true });
		fs.writeFileSync(path.join(tempDir, "profiles", "engineer.md"), "Engineer overlay");
		vi.resetModules();
	});

	afterEach(() => {
		process.chdir(originalCwd);
		fs.rmSync(tempDir, { recursive: true, force: true });
	});

	it("loads and trims the project soul from cwd when /app is unavailable", async () => {
		fs.mkdirSync(path.join(tempDir, "docs"), { recursive: true });
		fs.writeFileSync(path.join(tempDir, "docs", "soul.md"), "\n  native soul content  \n");
		process.chdir(tempDir);

		const { loadSoul } = await import("../src/soul.js");

		expect(loadSoul()).toBe("native soul content");
	});

	it("returns an empty string when no project soul exists", async () => {
		process.chdir(tempDir);

		const { loadSoul } = await import("../src/soul.js");

		expect(loadSoul()).toBe("");
	});

	it("caches the project soul after the first read", async () => {
		fs.mkdirSync(path.join(tempDir, "docs"), { recursive: true });
		const soulPath = path.join(tempDir, "docs", "soul.md");
		fs.writeFileSync(soulPath, "first soul");
		process.chdir(tempDir);

		const { loadSoul } = await import("../src/soul.js");

		expect(loadSoul()).toBe("first soul");
		fs.writeFileSync(soulPath, "second soul");
		expect(loadSoul()).toBe("first soul");
	});

	it("loads profile soul overlays from inside the project root", async () => {
		const { buildSoulPromptAppend } = await import("../src/soul.js");

		const prompt = buildSoulPromptAppend(
			{ id: "engineer", label: "Engineer", soulPath: "profiles/engineer.md" },
			{ includeProjectSoul: false, cwd: tempDir },
		);

		expect(prompt).toContain('<profile-soul id="engineer" label="Engineer">');
		expect(prompt).toContain("Engineer overlay");
	});

	it("omits missing profile overlays without throwing", async () => {
		const { buildSoulPromptAppend } = await import("../src/soul.js");

		const prompt = buildSoulPromptAppend(
			{ id: "engineer", label: "Engineer", soulPath: "profiles/missing.md" },
			{ includeProjectSoul: false, cwd: tempDir },
		);

		expect(prompt).toBeUndefined();
	});
});
