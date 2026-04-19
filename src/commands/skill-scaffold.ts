/**
 * Skill scaffold command.
 *
 * Creates a new draft skill under the canonical draft-skill root populated
 * from a template. The scaffold fills in frontmatter, creates the expected
 * subdirectories (scripts/, references/, assets/) and drops a PREVIEW.md
 * checklist the operator walks before promotion.
 *
 * Templates live under `assets/skill-templates/<template>/`. Three ship by
 * default: `basic`, `api-client`, `telegram-render`.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { Command } from "commander";
import { getChildLogger } from "../logging.js";
import { scanSkill } from "../security/skill-scanner.js";
import { getDraftSkillRoot, SkillRootUnavailableError } from "./skill-path.js";

const logger = getChildLogger({ module: "cmd-skill-scaffold" });

export const SKILL_TEMPLATES = ["basic", "api-client", "telegram-render"] as const;
export type SkillTemplate = (typeof SKILL_TEMPLATES)[number];

const SKILL_NAME_PATTERN = /^[a-z0-9][a-z0-9-]*$/;

export type ScaffoldOptions = {
	name: string;
	template?: SkillTemplate;
	description?: string;
	cwd?: string;
	/** Override the draft root used for tests. */
	draftRoot?: string;
	/** Override the template directory used for tests. */
	templatesRoot?: string;
};

export type ScaffoldResult = {
	success: boolean;
	draftDir?: string;
	skillMdPath?: string;
	previewPath?: string;
	error?: string;
};

const DEFAULT_TEMPLATE: SkillTemplate = "basic";
const DEFAULT_DESCRIPTION_SUFFIX =
	"Replace this description with one that describes WHEN to invoke the skill.";

function resolveTemplatesRoot(): string {
	// Templates ship inside the package at assets/skill-templates/.
	return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../assets/skill-templates");
}

function toTitle(name: string): string {
	return name
		.split("-")
		.filter(Boolean)
		.map((segment) => segment.charAt(0).toUpperCase() + segment.slice(1))
		.join(" ");
}

function renderTemplate(template: string, vars: Record<string, string>): string {
	return template.replace(/\{\{\s*(\w+)\s*\}\}/g, (_match, key: string) => {
		return Object.hasOwn(vars, key) ? vars[key] : "";
	});
}

function renderPreview(name: string, template: SkillTemplate): string {
	return [
		`# ${name} — draft preview`,
		"",
		`Scaffolded from the \`${template}\` template.`,
		"",
		"## Promotion checklist",
		"",
		`- [ ] Rewrite the \`description\` in SKILL.md so it describes WHEN to invoke the skill.`,
		`- [ ] Trim \`allowed-tools\` to the minimum set needed. Avoid Bash/Write/Edit/NotebookEdit unless required.`,
		`- [ ] Delete the boilerplate sections you do not need. Keep the prose tight.`,
		`- [ ] Add or remove bundled resources in \`scripts/\`, \`references/\`, \`assets/\` to match the skill.`,
		`- [ ] Run \`telclaude skills scan --path <this-draft-dir>\` and fix any findings.`,
		`- [ ] Run \`telclaude skills doctor\` and confirm this skill passes.`,
		`- [ ] When ready, promote via \`telclaude skills promote ${name}\` or \`/skills promote ${name}\`.`,
		"",
		"## Files in this draft",
		"",
		"- `SKILL.md` — frontmatter + instructions (REQUIRED).",
		"- `scripts/` — helper scripts invoked via `telclaude skill-path`.",
		"- `references/` — supporting docs consumed by the skill.",
		"- `assets/` — binary or large resources the skill references.",
		"",
		"This PREVIEW.md file is stripped away when you promote the skill.",
		"",
	].join("\n");
}

/**
 * Create a new draft skill under the canonical writable draft root.
 */
export function scaffoldSkill(options: ScaffoldOptions): ScaffoldResult {
	const name = options.name.trim();
	if (!SKILL_NAME_PATTERN.test(name)) {
		return {
			success: false,
			error: `Invalid skill name "${name}". Must match ${SKILL_NAME_PATTERN} (lowercase letters, digits, and hyphens).`,
		};
	}

	const template: SkillTemplate = options.template ?? DEFAULT_TEMPLATE;
	if (!SKILL_TEMPLATES.includes(template)) {
		return {
			success: false,
			error: `Unknown template "${template}". Choose one of: ${SKILL_TEMPLATES.join(", ")}.`,
		};
	}

	let draftRoot: string;
	try {
		draftRoot = options.draftRoot ?? getDraftSkillRoot(options.cwd);
	} catch (err) {
		if (err instanceof SkillRootUnavailableError) {
			return { success: false, error: err.message };
		}
		throw err;
	}

	const draftDir = path.join(draftRoot, name);
	const resolvedDraft = path.resolve(draftDir);
	if (!resolvedDraft.startsWith(`${path.resolve(draftRoot)}${path.sep}`)) {
		return { success: false, error: "Path traversal detected while resolving draft directory." };
	}

	if (fs.existsSync(draftDir)) {
		return {
			success: false,
			error: `Draft skill already exists at ${draftDir}. Delete it or choose a different name.`,
		};
	}

	const templatesRoot = options.templatesRoot ?? resolveTemplatesRoot();
	const templateDir = path.join(templatesRoot, template);
	const templateSkillMd = path.join(templateDir, "SKILL.md");
	if (!fs.existsSync(templateSkillMd)) {
		return {
			success: false,
			error: `Template "${template}" missing SKILL.md at ${templateSkillMd}. Reinstall telclaude or pass --template.`,
		};
	}

	const description =
		options.description?.trim() || `${toTitle(name)}. ${DEFAULT_DESCRIPTION_SUFFIX}`;

	let rendered: string;
	try {
		const raw = fs.readFileSync(templateSkillMd, "utf8");
		rendered = renderTemplate(raw, {
			name,
			description,
			title: toTitle(name),
		});
	} catch (err) {
		return { success: false, error: `Failed to read template: ${String(err)}` };
	}

	try {
		fs.mkdirSync(draftDir, { recursive: true });
		for (const sub of ["scripts", "references", "assets"]) {
			fs.mkdirSync(path.join(draftDir, sub), { recursive: true });
			// Drop a .gitkeep so empty dirs survive commits / copies.
			fs.writeFileSync(path.join(draftDir, sub, ".gitkeep"), "", "utf8");
		}

		const skillMdPath = path.join(draftDir, "SKILL.md");
		fs.writeFileSync(skillMdPath, rendered, "utf8");

		const previewPath = path.join(draftDir, "PREVIEW.md");
		fs.writeFileSync(previewPath, renderPreview(name, template), "utf8");

		logger.info({ name, template, draftDir }, "scaffolded new draft skill");
		return { success: true, draftDir, skillMdPath, previewPath };
	} catch (err) {
		// Roll back partial creation on failure.
		try {
			fs.rmSync(draftDir, { recursive: true, force: true });
		} catch {
			// best-effort
		}
		return { success: false, error: `Failed to write scaffold: ${String(err)}` };
	}
}

/**
 * Register the skill-scaffold command under `telclaude skills scaffold`.
 */
export function registerSkillsScaffoldSubcommand(parent: Command): void {
	parent
		.command("scaffold")
		.description("Create a new draft skill from a template")
		.argument("<name>", "Skill name (lowercase, hyphen-separated)")
		.option(
			"-t, --template <template>",
			`Template to use (${SKILL_TEMPLATES.join(", ")})`,
			DEFAULT_TEMPLATE,
		)
		.option("-d, --description <description>", "Description for the skill frontmatter")
		.option("--scan", "Run the skill scanner over the scaffold immediately after creation", false)
		.action(
			(name: string, options: { template?: string; description?: string; scan?: boolean }) => {
				const templateName = (options.template ?? DEFAULT_TEMPLATE) as SkillTemplate;
				const result = scaffoldSkill({
					name,
					template: templateName,
					description: options.description,
				});

				if (!result.success) {
					console.error(`Error: ${result.error}`);
					process.exitCode = 1;
					return;
				}

				console.log(`Scaffolded draft skill "${name}" (template: ${templateName}).`);
				console.log(`  SKILL.md:   ${result.skillMdPath}`);
				console.log(`  PREVIEW.md: ${result.previewPath}`);
				console.log("");
				console.log("Next steps:");
				console.log("  1. Edit SKILL.md (rewrite description, trim allowed-tools).");
				console.log(`  2. telclaude skills doctor`);
				console.log(`  3. telclaude skills promote ${name}`);

				if (options.scan && result.draftDir) {
					const scanResult = scanSkill(result.draftDir);
					if (scanResult.blocked) {
						console.error("");
						console.error("Scanner blocked the scaffold. Findings:");
						for (const finding of scanResult.findings) {
							console.error(
								`  ${finding.severity.toUpperCase()}: ${finding.message} (${finding.file}${finding.line ? `:${finding.line}` : ""})`,
							);
						}
						process.exitCode = 1;
					} else if (scanResult.findings.length > 0) {
						console.log("");
						console.log("Scanner findings (non-blocking):");
						for (const finding of scanResult.findings) {
							console.log(
								`  ${finding.severity.toUpperCase()}: ${finding.message} (${finding.file}${finding.line ? `:${finding.line}` : ""})`,
							);
						}
					} else {
						console.log("");
						console.log("Scanner: OK — no findings.");
					}
				}
			},
		);
}
