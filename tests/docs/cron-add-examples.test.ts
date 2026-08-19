import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const repoRoot = path.resolve(import.meta.dirname, "../..");

const ACTION_FLAGS = ["private", "prompt", "social", "curator-scan"] as const;
const SCHEDULE_FLAGS = ["at", "every", "cron"] as const;
const ISO_AT = /^\d{4}-\d{2}-\d{2}T/;

function skillMarkdownPaths(): string[] {
	const roots = [".claude/skills", ".agents/skills"];
	const files: string[] = [];
	for (const root of roots) {
		const abs = path.join(repoRoot, root);
		if (!fs.existsSync(abs)) continue;
		for (const name of fs.readdirSync(abs)) {
			const skill = path.join(abs, name, "SKILL.md");
			if (fs.existsSync(skill)) files.push(skill);
		}
	}
	files.push(path.join(repoRoot, "docs/operator-playbook.md"));
	return files;
}

function extractCronAddBlocks(markdown: string): string[] {
	const commandStart = /pnpm(?:\s+dev)?\s+maintenance\s+cron\s+add(?:\s+(?:\\|--)|$)/;
	const parts = markdown.split(/(?=pnpm(?:\s+dev)?\s+maintenance\s+cron\s+add(?:\s+(?:\\|--)|$))/);
	return parts
		.filter((part) => commandStart.test(part))
		.map((part) => {
			const fence = part.search(/\n```/);
			return (fence === -1 ? part : part.slice(0, fence)).trim();
		});
}

function flagCount(block: string, name: string): number {
	const re = new RegExp(`--${name}(?:\\s|=|$)`, "g");
	return block.match(re)?.length ?? 0;
}

function atValues(block: string): string[] {
	const values: string[] = [];
	const re = /--at(?:\s+|=)(\S+)/g;
	let match = re.exec(block);
	while (match) {
		values.push(match[1] ?? "");
		match = re.exec(block);
	}
	return values;
}

describe("documented cron add examples", () => {
	it("use exactly one action and one schedule, and never a past --at ISO timestamp", () => {
		const files = skillMarkdownPaths();
		expect(files.length).toBeGreaterThan(3);

		for (const file of files) {
			const markdown = fs.readFileSync(file, "utf8");
			const rel = path.relative(repoRoot, file);
			for (const [index, block] of extractCronAddBlocks(markdown).entries()) {
				const actions = ACTION_FLAGS.reduce((sum, name) => sum + flagCount(block, name), 0);
				const schedules = SCHEDULE_FLAGS.reduce((sum, name) => sum + flagCount(block, name), 0);
				expect(actions, `${rel} cron add #${index + 1} actions`).toBe(1);
				expect(schedules, `${rel} cron add #${index + 1} schedules`).toBe(1);

				for (const value of atValues(block)) {
					if (!ISO_AT.test(value)) continue;
					const ms = Date.parse(value);
					expect(Number.isNaN(ms), `${rel} cron add #${index + 1} --at ${value}`).toBe(false);
					expect(
						ms,
						`${rel} cron add #${index + 1} --at ${value} must be in the future`,
					).toBeGreaterThan(Date.now());
				}
			}
		}
	});
});
