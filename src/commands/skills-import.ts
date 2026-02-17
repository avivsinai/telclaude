/**
 * OpenClaw skill importer command.
 *
 * Imports community skills from OpenClaw-format directories into telclaude.
 * OpenClaw skills are pure markdown (SKILL.md + frontmatter) — same family
 * as Claude skills. Most work in telclaude with a thin adapter.
 *
 * Steps:
 * 1. Read OpenClaw skill dirs (skills/, .agents/skills/, extensions/&lt;ext&gt;/skills)
 * 2. Convert frontmatter: keep name, description, allowed-tools; strip OpenClaw-specific
 * 3. Copy to .claude/skills/openclaw/<skill-name>/SKILL.md
 * 4. Run skill scanner before activation — block malicious patterns
 * 5. Refuse auto-install directives
 * 6. Report results
 */

import fs from "node:fs";
import path from "node:path";
import type { Command } from "commander";
import { scanSkill } from "../security/skill-scanner.js";

// ═══════════════════════════════════════════════════════════════════════════════
// OpenClaw Skill Discovery
// ═══════════════════════════════════════════════════════════════════════════════

/** Standard OpenClaw skill directory locations. */
const OPENCLAW_SKILL_DIRS = ["skills", ".agents/skills", "extensions"];

type DiscoveredSkill = {
	name: string;
	dir: string;
	skillMdPath: string;
};

/**
 * Discover OpenClaw-format skills in a source directory.
 */
function discoverSkills(sourceDir: string): DiscoveredSkill[] {
	const skills: DiscoveredSkill[] = [];

	for (const relDir of OPENCLAW_SKILL_DIRS) {
		const searchDir = path.join(sourceDir, relDir);
		if (!fs.existsSync(searchDir)) continue;

		if (relDir === "extensions") {
			// Extensions have nested skill dirs: extensions/*/skills/*
			const extEntries = safeReaddir(searchDir);
			for (const ext of extEntries) {
				if (!ext.isDirectory()) continue;
				const extSkillsDir = path.join(searchDir, ext.name, "skills");
				if (!fs.existsSync(extSkillsDir)) continue;
				skills.push(...discoverSkillsInDir(extSkillsDir));
			}
		} else {
			skills.push(...discoverSkillsInDir(searchDir));
		}
	}

	// Also check root-level SKILL.md (single-skill repos)
	const rootSkillMd = path.join(sourceDir, "SKILL.md");
	if (fs.existsSync(rootSkillMd)) {
		skills.push({
			name: path.basename(sourceDir),
			dir: sourceDir,
			skillMdPath: rootSkillMd,
		});
	}

	return skills;
}

function discoverSkillsInDir(dir: string): DiscoveredSkill[] {
	const skills: DiscoveredSkill[] = [];
	const entries = safeReaddir(dir);

	for (const entry of entries) {
		if (!entry.isDirectory()) continue;
		const skillDir = path.join(dir, entry.name);
		const skillMd = path.join(skillDir, "SKILL.md");
		if (fs.existsSync(skillMd)) {
			skills.push({
				name: entry.name,
				dir: skillDir,
				skillMdPath: skillMd,
			});
		}
	}

	return skills;
}

function safeReaddir(dir: string): fs.Dirent[] {
	try {
		return fs.readdirSync(dir, { withFileTypes: true });
	} catch {
		return [];
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Frontmatter Conversion
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * OpenClaw-specific frontmatter fields to strip during import.
 */
const OPENCLAW_STRIP_FIELDS = new Set([
	"metadata.openclaw",
	"install",
	"install-deps",
	"auto-install",
	"setup-script",
	"command-dispatch",
	"openclaw-version",
	"openclaw_version",
	"channel",
	"channels",
]);

/**
 * Auto-install directive patterns that must be refused.
 */
const AUTO_INSTALL_PATTERNS = [
	/\b(?:brew|apt|yum|pacman|dnf)\s+install\b/i,
	/\bnpm\s+(?:i|install)\s+-g\b/i,
	/\bpip\s+install\b/i,
	/\bgo\s+install\b/i,
	/\bcargo\s+install\b/i,
	/\buv\s+(?:tool\s+)?install\b/i,
	/\bnpx\s+/i,
];

type ConversionResult = {
	content: string;
	hasAutoInstall: boolean;
	autoInstallDeps: string[];
	strippedFields: string[];
};

/**
 * Convert OpenClaw SKILL.md frontmatter to telclaude format.
 */
function convertSkillMd(content: string): ConversionResult {
	const strippedFields: string[] = [];
	const autoInstallDeps: string[] = [];
	let hasAutoInstall = false;

	// Check for auto-install directives in content
	for (const pattern of AUTO_INSTALL_PATTERNS) {
		const match = content.match(pattern);
		if (match) {
			hasAutoInstall = true;
			autoInstallDeps.push(match[0]);
		}
	}

	// Process frontmatter
	const frontmatterMatch = content.match(/^(---\s*\n)([\s\S]*?)(\n---)/);
	if (!frontmatterMatch) {
		return { content, hasAutoInstall, autoInstallDeps, strippedFields };
	}

	const [, open, frontmatterBody, close] = frontmatterMatch;
	const lines = frontmatterBody.split("\n");
	const keptLines: string[] = [];
	let currentKey = "";
	let inNestedBlock = false;

	for (const line of lines) {
		// Detect top-level key
		const topKeyMatch = line.match(/^(\w[\w.-]*)\s*:/);
		if (topKeyMatch) {
			currentKey = topKeyMatch[1];
			inNestedBlock = false;
		}

		// Check if current key (or its dotted form with parent) should be stripped
		const shouldStrip =
			OPENCLAW_STRIP_FIELDS.has(currentKey) || OPENCLAW_STRIP_FIELDS.has(`metadata.${currentKey}`);

		if (shouldStrip) {
			if (topKeyMatch) {
				strippedFields.push(currentKey);
				// Check if this is a block (next lines are indented)
				inNestedBlock = true;
			}
			continue;
		}

		// Skip indented lines under stripped blocks
		if (inNestedBlock && /^\s+/.test(line) && !topKeyMatch) {
			continue;
		}
		inNestedBlock = false;

		keptLines.push(line);
	}

	const newContent = content.replace(frontmatterMatch[0], `${open}${keptLines.join("\n")}${close}`);

	return { content: newContent, hasAutoInstall, autoInstallDeps, strippedFields };
}

// ═══════════════════════════════════════════════════════════════════════════════
// Import Logic
// ═══════════════════════════════════════════════════════════════════════════════

type ImportResult = {
	imported: string[];
	blocked: string[];
	skipped: string[];
	errors: string[];
};

/**
 * Copy a skill directory, filtering out non-essential files.
 */
function copySkillDir(sourceDir: string, targetDir: string, convertedContent: string): void {
	fs.mkdirSync(targetDir, { recursive: true });

	// Write converted SKILL.md
	fs.writeFileSync(path.join(targetDir, "SKILL.md"), convertedContent, "utf-8");

	// Copy allowed subdirectories (references, assets)
	const allowedDirs = ["references", "assets"];
	for (const subDir of allowedDirs) {
		const sourceSubDir = path.join(sourceDir, subDir);
		if (fs.existsSync(sourceSubDir)) {
			copyDirRecursive(sourceSubDir, path.join(targetDir, subDir));
		}
	}
}

function copyDirRecursive(source: string, target: string): void {
	fs.mkdirSync(target, { recursive: true });
	const entries = safeReaddir(source);
	for (const entry of entries) {
		const srcPath = path.join(source, entry.name);
		const tgtPath = path.join(target, entry.name);
		if (entry.isDirectory()) {
			copyDirRecursive(srcPath, tgtPath);
		} else if (entry.isFile()) {
			fs.copyFileSync(srcPath, tgtPath);
		}
	}
}

/**
 * Import skills from an OpenClaw-format source directory.
 */
function importSkills(
	sourceDir: string,
	targetRoot: string,
	allowAutoInstall = false,
): ImportResult {
	const result: ImportResult = { imported: [], blocked: [], skipped: [], errors: [] };

	const discovered = discoverSkills(sourceDir);
	if (discovered.length === 0) {
		result.errors.push(`No skills found in ${sourceDir}`);
		return result;
	}

	console.log(`Found ${discovered.length} skill(s) in ${sourceDir}\n`);

	for (const skill of discovered) {
		const targetDir = path.join(targetRoot, skill.name);

		// Read and convert SKILL.md
		let content: string;
		try {
			content = fs.readFileSync(skill.skillMdPath, "utf-8");
		} catch (err) {
			result.errors.push(`Failed to read ${skill.skillMdPath}: ${err}`);
			continue;
		}

		const conversion = convertSkillMd(content);

		// Block skills with auto-install directives unless explicitly allowed
		if (conversion.hasAutoInstall && !allowAutoInstall) {
			result.skipped.push(skill.name);
			console.log(`  ⊘ ${skill.name}: SKIPPED (has auto-install directives)`);
			console.log(`    Deps: ${conversion.autoInstallDeps.join(", ")}`);
			console.log("    Use --allow-auto-install to import anyway.");
			continue;
		}
		if (conversion.hasAutoInstall) {
			console.log(`  ⚠ ${skill.name}: has auto-install deps (must install manually)`);
			console.log(`    Deps: ${conversion.autoInstallDeps.join(", ")}`);
		}

		// Copy to target (temporarily for scanning)
		try {
			copySkillDir(skill.dir, targetDir, conversion.content);
		} catch (err) {
			result.errors.push(`Failed to copy ${skill.name}: ${err}`);
			continue;
		}

		// Run scanner on the imported skill
		const scanResult = scanSkill(targetDir);

		if (scanResult.blocked) {
			// Remove the blocked skill
			try {
				fs.rmSync(targetDir, { recursive: true });
			} catch {
				// Best effort cleanup
			}
			result.blocked.push(skill.name);
			console.log(`  ✗ ${skill.name}: BLOCKED (malicious patterns detected)`);
			for (const finding of scanResult.findings) {
				if (finding.severity === "critical" || finding.severity === "high") {
					console.log(`    ${finding.severity.toUpperCase()}: ${finding.message}`);
				}
			}
		} else {
			result.imported.push(skill.name);
			const stripped = conversion.strippedFields.length
				? ` (stripped: ${conversion.strippedFields.join(", ")})`
				: "";
			console.log(`  ✓ ${skill.name}: imported${stripped}`);
		}
	}

	return result;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Command Registration
// ═══════════════════════════════════════════════════════════════════════════════

export function registerSkillsCommands(program: Command): void {
	const skills = program.command("skills").description("Manage telclaude skills");

	skills
		.command("import-openclaw")
		.description("Import skills from an OpenClaw-format directory")
		.argument("<source>", "Path to OpenClaw source directory")
		.option(
			"--target <dir>",
			"Target directory for imported skills",
			path.join(process.cwd(), ".claude", "skills", "openclaw"),
		)
		.option("--dry-run", "Show what would be imported without copying")
		.option(
			"--allow-auto-install",
			"Import skills with auto-install directives (default: skip them)",
		)
		.action(
			async (
				source: string,
				options: { target: string; dryRun?: boolean; allowAutoInstall?: boolean },
			) => {
				const sourceDir = path.resolve(source);

				if (!fs.existsSync(sourceDir)) {
					console.error(`Source directory not found: ${sourceDir}`);
					process.exit(1);
				}

				console.log(`=== OpenClaw Skill Import ===\n`);
				console.log(`Source: ${sourceDir}`);
				console.log(`Target: ${options.target}\n`);

				if (options.dryRun) {
					console.log("(dry run — no files will be copied)\n");
					const discovered = discoverSkills(sourceDir);
					if (discovered.length === 0) {
						console.log("No skills found.");
						return;
					}
					console.log(`Found ${discovered.length} skill(s):`);
					for (const skill of discovered) {
						console.log(`  - ${skill.name} (${path.relative(sourceDir, skill.dir)})`);
					}
					return;
				}

				const result = importSkills(sourceDir, options.target, options.allowAutoInstall);

				console.log("\n=== Import Summary ===");
				console.log(
					`Imported: ${result.imported.length}, Blocked: ${result.blocked.length}, Skipped: ${result.skipped.length}, Errors: ${result.errors.length}`,
				);

				if (result.errors.length > 0) {
					console.log("\nErrors:");
					for (const err of result.errors) {
						console.log(`  - ${err}`);
					}
					process.exitCode = 1;
				}

				if (result.blocked.length > 0) {
					console.log(
						"\nBlocked skills contained malicious patterns. Review and re-import manually if safe.",
					);
				}

				if (result.imported.length > 0) {
					console.log("\nImported skills will be available in the next agent session.");
				}
			},
		);

	skills
		.command("scan")
		.description("Scan all installed skills for malicious patterns")
		.option("--path <dir>", "Path to skills directory to scan")
		.action(async (options: { path?: string }) => {
			const { formatScanResults, scanAllSkills } = await import("../security/skill-scanner.js");

			const skillRoots: string[] = [];
			if (options.path) {
				skillRoots.push(path.resolve(options.path));
			} else {
				const cwd = process.cwd();
				skillRoots.push(path.join(cwd, ".claude", "skills"));
				skillRoots.push(path.join(cwd, ".claude", "skills-draft"));
				const configDir = process.env.CLAUDE_CONFIG_DIR;
				if (configDir) {
					skillRoots.push(path.join(configDir, "skills"));
				}
			}

			console.log("=== Skill Scanner ===\n");

			let allResults: ReturnType<typeof scanAllSkills> = [];
			for (const root of skillRoots) {
				if (fs.existsSync(root)) {
					console.log(`Scanning: ${root}`);
					allResults = allResults.concat(scanAllSkills(root));
				}
			}

			if (allResults.length === 0) {
				console.log("\nNo skills found to scan.");
				return;
			}

			console.log(formatScanResults(allResults));
			const blockedCount = allResults.filter((r) => r.blocked).length;
			if (blockedCount > 0) {
				process.exitCode = 1;
			}
		});
}
