/**
 * CLI for the relay-owned Hermes skill catalog.
 *
 * All writes go through the validated catalog installer in
 * `src/hermes/skills-catalog.ts`; the contained runtime only ever sees the
 * catalog as a read-only mount.
 */

import fs from "node:fs";
import path from "node:path";
import type { Command } from "commander";
import { getCuratorItem } from "../curator/store.js";
import type { CuratorItem } from "../curator/types.js";
import {
	type CatalogInstallResult,
	type HermesSkillCatalogKind,
	installSkillFromDir,
	listCatalog,
	removeSkill,
	verifyCatalogAgainstManifest,
} from "../hermes/skills-catalog.js";

const UPSTREAM_REL_SEGMENT_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;

function handleCommandError(err: unknown): void {
	console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
	process.exitCode = 1;
}

function resolveUpstreamSkillsRoot(flagValue: string | undefined): string {
	const root = flagValue?.trim() || process.env.TELCLAUDE_HERMES_UPSTREAM_SKILLS_DIR?.trim();
	if (!root) {
		throw new Error(
			"upstream installs require --upstream-root or TELCLAUDE_HERMES_UPSTREAM_SKILLS_DIR",
		);
	}
	const resolved = path.resolve(root);
	if (!fs.existsSync(resolved) || !fs.statSync(resolved).isDirectory()) {
		throw new Error(`upstream skills root is not a directory: ${resolved}`);
	}
	return resolved;
}

function resolveUpstreamSkillDir(upstreamRoot: string, rel: string): string {
	const segments = rel.split("/");
	if (
		segments.length === 0 ||
		segments.some((segment) => !UPSTREAM_REL_SEGMENT_PATTERN.test(segment))
	) {
		throw new Error(`invalid upstream skill path "${rel}"`);
	}
	const resolved = path.resolve(upstreamRoot, ...segments);
	if (resolved !== upstreamRoot && !resolved.startsWith(`${upstreamRoot}${path.sep}`)) {
		throw new Error(`upstream skill path escapes the upstream root: ${rel}`);
	}
	return resolved;
}

function printInstallResult(result: CatalogInstallResult, json: boolean | undefined): void {
	if (json) {
		console.log(JSON.stringify({ installed: result }, null, 2));
		return;
	}
	console.log(`Installed ${result.name} (sha256 ${result.sha256}) from ${result.origin}.`);
}

type CatalogCliOptions = {
	readonly catalog?: string;
};

function parseCatalogKind(value: string | undefined): HermesSkillCatalogKind {
	const kind = value?.trim() || "private";
	if (kind === "private" || kind === "social") return kind;
	throw new Error(`invalid catalog "${kind}"; expected private or social`);
}

function catalogOptions(options: CatalogCliOptions): { catalogKind: HermesSkillCatalogKind } {
	return { catalogKind: parseCatalogKind(options.catalog) };
}

function withCatalogOption(command: Command): Command {
	return command.option(
		"--catalog <private|social>",
		"Target Hermes skill catalog (private or social)",
		"private",
	);
}

type CuratorCatalogInstall = { sourceDir: string } | { upstreamRel: string };

function parseCuratorCatalogInstall(item: CuratorItem): CuratorCatalogInstall {
	const raw = item.proposedAction.catalogInstall;
	if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
		throw new Error(`curator item ${item.shortId} proposedAction.catalogInstall must be an object`);
	}
	const record = raw as Record<string, unknown>;
	const sourceDir = typeof record.sourceDir === "string" ? record.sourceDir.trim() : "";
	const upstreamRel = typeof record.upstreamRel === "string" ? record.upstreamRel.trim() : "";
	if ((sourceDir === "") === (upstreamRel === "")) {
		throw new Error(
			`curator item ${item.shortId} catalogInstall must carry exactly one of sourceDir or upstreamRel`,
		);
	}
	return sourceDir ? { sourceDir } : { upstreamRel };
}

export function registerHermesSkillsCommand(program: Command): void {
	const group = program
		.command("hermes-skills")
		.description("Manage the relay-owned Hermes external skill catalog");

	withCatalogOption(group.command("install"))
		.description("Validate and install a skill directory into the catalog")
		.argument("<dir>", "Skill directory (basename is the skill name)")
		.option("--origin <s>", "Origin recorded in the catalog manifest")
		.option("--json", "Output as JSON")
		.action((dir: string, opts: { origin?: string; json?: boolean } & CatalogCliOptions) => {
			try {
				const result = installSkillFromDir(dir, {
					origin: opts.origin?.trim() || `local:${path.resolve(dir)}`,
					...catalogOptions(opts),
				});
				printInstallResult(result, opts.json);
			} catch (err) {
				handleCommandError(err);
			}
		});

	withCatalogOption(group.command("install-upstream"))
		.description("Install a skill from a pinned upstream Hermes skills tree")
		.argument("<rel>", "Skill path relative to the upstream skills root")
		.option("--upstream-root <dir>", "Upstream Hermes skills tree root")
		.option("--json", "Output as JSON")
		.action((rel: string, opts: { upstreamRoot?: string; json?: boolean } & CatalogCliOptions) => {
			try {
				const upstreamRoot = resolveUpstreamSkillsRoot(opts.upstreamRoot);
				const srcDir = resolveUpstreamSkillDir(upstreamRoot, rel);
				const result = installSkillFromDir(srcDir, {
					origin: `upstream:${rel}`,
					...catalogOptions(opts),
				});
				printInstallResult(result, opts.json);
			} catch (err) {
				handleCommandError(err);
			}
		});

	withCatalogOption(group.command("list"))
		.description("List catalog manifest entries")
		.option("--json", "Output as JSON")
		.action((opts: { json?: boolean } & CatalogCliOptions) => {
			try {
				const skills = listCatalog(catalogOptions(opts));
				if (opts.json) {
					console.log(JSON.stringify({ skills }, null, 2));
					return;
				}
				if (skills.length === 0) {
					console.log("Catalog is empty.");
					return;
				}
				for (const skill of skills) {
					console.log(
						`${skill.name}  sha256 ${skill.sha256}  ${skill.origin}  ${skill.installedAt}`,
					);
				}
			} catch (err) {
				handleCommandError(err);
			}
		});

	withCatalogOption(group.command("remove"))
		.description("Remove a skill from the catalog tree and manifest")
		.argument("<name>", "Catalog skill name")
		.action((name: string, opts: CatalogCliOptions) => {
			try {
				if (!removeSkill(name, catalogOptions(opts))) {
					console.error(`Error: skill "${name}" is not in the catalog`);
					process.exitCode = 1;
					return;
				}
				console.log(`Removed ${name}.`);
			} catch (err) {
				handleCommandError(err);
			}
		});

	withCatalogOption(group.command("verify"))
		.description("Verify the catalog tree against the manifest")
		.option("--json", "Output as JSON")
		.action((opts: { json?: boolean } & CatalogCliOptions) => {
			try {
				const result = verifyCatalogAgainstManifest(catalogOptions(opts));
				if (opts.json) {
					console.log(JSON.stringify(result, null, 2));
				} else if (result.skills.length === 0) {
					console.log("Catalog is empty.");
				} else {
					for (const skill of result.skills) {
						console.log(
							`${skill.status === "ok" ? "ok   " : skill.status.padEnd(5)} ${skill.name}${skill.detail ? `  ${skill.detail}` : ""}`,
						);
					}
				}
				if (!result.ok) {
					process.exitCode = 1;
				}
			} catch (err) {
				handleCommandError(err);
			}
		});

	withCatalogOption(group.command("install-from-curator"))
		.description("Install a catalog skill proposed by an accepted skill_review curator item")
		.argument("<itemId>", "Curator item id or short id")
		.option("--upstream-root <dir>", "Upstream Hermes skills tree root (for upstreamRel items)")
		.option("--json", "Output as JSON")
		.action(
			(itemId: string, opts: { upstreamRoot?: string; json?: boolean } & CatalogCliOptions) => {
				try {
					const item = getCuratorItem(itemId);
					if (!item) {
						throw new Error(`unknown curator item '${itemId}'`);
					}
					if (item.kind !== "skill_review") {
						throw new Error(`curator item ${item.shortId} is ${item.kind}, not skill_review`);
					}
					if (item.status !== "accepted") {
						throw new Error(
							`curator item ${item.shortId} is ${item.status}; only accepted items can be installed`,
						);
					}
					const install = parseCuratorCatalogInstall(item);
					const srcDir =
						"sourceDir" in install
							? path.resolve(install.sourceDir)
							: resolveUpstreamSkillDir(
									resolveUpstreamSkillsRoot(opts.upstreamRoot),
									install.upstreamRel,
								);
					const result = installSkillFromDir(srcDir, {
						origin: `curator:${item.id}`,
						...catalogOptions(opts),
					});
					printInstallResult(result, opts.json);
				} catch (err) {
					handleCommandError(err);
				}
			},
		);
}
