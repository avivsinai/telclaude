import {
	type SpawnSyncOptionsWithStringEncoding,
	type SpawnSyncReturns,
	spawnSync,
} from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { Command } from "commander";
import JSON5 from "json5";

export type PluginPersona = "private" | "social";
export type PluginPersonaScope = PluginPersona | "both";

export type PluginTarget = {
	persona: PluginPersona;
	claudeHome: string;
};

export type PluginCapabilities = {
	disable: boolean;
	enable: boolean;
	install: boolean;
	list: boolean;
	marketplaceAdd: boolean;
	marketplaceUpdate: boolean;
	uninstall: boolean;
	update: boolean;
};

export type ClaudePluginRunner = {
	run(
		cmd: string,
		args: string[],
		options?: SpawnSyncOptionsWithStringEncoding,
	): SpawnSyncReturns<string>;
};

export type ManagedPluginTargetResult = PluginTarget & {
	actions: string[];
};

export type ManagedPluginMutationResult = {
	pluginId: string;
	targets: ManagedPluginTargetResult[];
};

export type ManagedPluginState = {
	pluginId: string;
	enabled: boolean;
	installed: boolean;
	versions: string[];
};

export type ManagedPluginListEntry = PluginTarget & {
	plugins: ManagedPluginState[];
};

type PluginCommandOptions = {
	persona?: PluginPersonaScope;
	env?: NodeJS.ProcessEnv;
	runner?: ClaudePluginRunner;
	marketplaceSource?: string;
};

type InstalledPluginsFile = {
	plugins?: Record<string, Array<{ version?: string }>>;
};

type KnownMarketplacesFile = Record<string, unknown>;

function createDefaultRunner(): ClaudePluginRunner {
	return {
		run(cmd, args, options) {
			return spawnSync(cmd, args, {
				encoding: "utf8",
				stdio: "pipe",
				...options,
			});
		},
	};
}

function normalizeDir(raw: string): string {
	return raw.replace(/[/\\]+$/, "");
}

function resolvePrivateClaudeHome(env: NodeJS.ProcessEnv): string {
	const raw =
		env.TELCLAUDE_PRIVATE_CLAUDE_HOME ??
		env.CLAUDE_CONFIG_DIR ??
		env.TELCLAUDE_CLAUDE_HOME ??
		path.join(os.homedir(), ".claude");
	return normalizeDir(path.resolve(raw));
}

function resolveSocialClaudeHome(env: NodeJS.ProcessEnv): string {
	const raw = env.TELCLAUDE_SOCIAL_CLAUDE_HOME;
	if (!raw) {
		throw new Error("TELCLAUDE_SOCIAL_CLAUDE_HOME is not configured.");
	}
	return normalizeDir(path.resolve(raw));
}

export function resolvePluginTargets(
	persona: PluginPersonaScope | string | undefined,
	env: NodeJS.ProcessEnv = process.env,
): PluginTarget[] {
	switch (persona ?? "private") {
		case "private":
			return [{ persona: "private", claudeHome: resolvePrivateClaudeHome(env) }];
		case "social":
			return [{ persona: "social", claudeHome: resolveSocialClaudeHome(env) }];
		case "both":
			return [
				{ persona: "private", claudeHome: resolvePrivateClaudeHome(env) },
				{ persona: "social", claudeHome: resolveSocialClaudeHome(env) },
			];
		default:
			throw new Error(`Invalid persona scope "${persona}". Expected private, social, or both.`);
	}
}

function includesCommand(helpText: string, commandName: string): boolean {
	return new RegExp(`(^|\\n)\\s*${commandName}\\b`, "m").test(helpText);
}

export function detectClaudePluginCapabilities(
	runner: ClaudePluginRunner = createDefaultRunner(),
): PluginCapabilities {
	const pluginHelp = runner.run("claude", ["plugin", "--help"]);
	const pluginStdout = pluginHelp.status === 0 ? pluginHelp.stdout : "";
	const marketplaceHelp = runner.run("claude", ["plugin", "marketplace", "--help"]);
	const marketplaceStdout = marketplaceHelp.status === 0 ? marketplaceHelp.stdout : "";

	return {
		disable: includesCommand(pluginStdout, "disable"),
		enable: includesCommand(pluginStdout, "enable"),
		install: includesCommand(pluginStdout, "install"),
		list: includesCommand(pluginStdout, "list"),
		marketplaceAdd: includesCommand(marketplaceStdout, "add"),
		marketplaceUpdate: includesCommand(marketplaceStdout, "update"),
		uninstall: includesCommand(pluginStdout, "uninstall"),
		update: includesCommand(pluginStdout, "update"),
	};
}

function assertCapabilities(
	capabilities: PluginCapabilities,
	required: Array<keyof PluginCapabilities>,
	context: string,
): void {
	const missing = required.filter((key) => !capabilities[key]);
	if (missing.length === 0) {
		return;
	}
	throw new Error(
		`The installed Claude CLI does not support ${context}. Missing subcommands: ${missing.join(", ")}.`,
	);
}

function parsePluginId(pluginId: string): { pluginName: string; marketplaceName: string } {
	const trimmed = pluginId.trim();
	const match = /^(?<pluginName>[a-z0-9][a-z0-9-]*)@(?<marketplaceName>[a-z0-9][a-z0-9-]*)$/i.exec(
		trimmed,
	);
	if (!match?.groups) {
		throw new Error(
			`Invalid plugin id "${pluginId}". Expected the official form <plugin-name>@<marketplace-name>.`,
		);
	}
	return {
		pluginName: match.groups.pluginName,
		marketplaceName: match.groups.marketplaceName,
	};
}

function readJsonFile<T>(filePath: string, fallback: T): T {
	try {
		const raw = fs.readFileSync(filePath, "utf8");
		return JSON5.parse(raw) as T;
	} catch (error) {
		if (
			typeof error === "object" &&
			error !== null &&
			"code" in error &&
			(error as NodeJS.ErrnoException).code === "ENOENT"
		) {
			return fallback;
		}
		throw new Error(
			`Failed to read Claude plugin metadata at ${filePath}: ${error instanceof Error ? error.message : String(error)}`,
		);
	}
}

function readSettingsEnabledPlugins(claudeHome: string): Record<string, boolean> {
	const settings = readJsonFile<Record<string, unknown>>(
		path.join(claudeHome, "settings.json"),
		{},
	);
	const enabledPlugins = settings.enabledPlugins;
	if (Array.isArray(enabledPlugins)) {
		return Object.fromEntries(enabledPlugins.map((pluginId) => [String(pluginId), true]));
	}
	if (enabledPlugins && typeof enabledPlugins === "object") {
		return Object.fromEntries(
			Object.entries(enabledPlugins as Record<string, unknown>).map(([pluginId, enabled]) => [
				pluginId,
				Boolean(enabled),
			]),
		);
	}
	return {};
}

function readInstalledPlugins(claudeHome: string): Record<string, Array<{ version?: string }>> {
	const installed = readJsonFile<InstalledPluginsFile>(
		path.join(claudeHome, "plugins", "installed_plugins.json"),
		{},
	);
	return installed.plugins ?? {};
}

function readKnownMarketplaces(claudeHome: string): KnownMarketplacesFile {
	return readJsonFile<KnownMarketplacesFile>(
		path.join(claudeHome, "plugins", "known_marketplaces.json"),
		{},
	);
}

function buildPluginEnv(baseEnv: NodeJS.ProcessEnv, claudeHome: string): NodeJS.ProcessEnv {
	return {
		...baseEnv,
		CLAUDE_CONFIG_DIR: claudeHome,
		TELCLAUDE_CLAUDE_HOME: claudeHome,
	};
}

function runClaudePluginCommand(
	runner: ClaudePluginRunner,
	target: PluginTarget,
	args: string[],
	baseEnv: NodeJS.ProcessEnv,
): SpawnSyncReturns<string> {
	const result = runner.run("claude", args, {
		encoding: "utf8",
		env: buildPluginEnv(baseEnv, target.claudeHome),
	});
	if (result.status !== 0) {
		const stderr = result.stderr.trim();
		const stdout = result.stdout.trim();
		throw new Error(
			[
				`Claude plugin command failed for ${target.persona} profile: claude ${args.join(" ")}`,
				stderr || stdout || "Unknown error",
			].join("\n"),
		);
	}
	return result;
}

function getPluginState(target: PluginTarget): {
	enabledPlugins: Record<string, boolean>;
	installedPlugins: Record<string, Array<{ version?: string }>>;
	knownMarketplaces: KnownMarketplacesFile;
} {
	return {
		enabledPlugins: readSettingsEnabledPlugins(target.claudeHome),
		installedPlugins: readInstalledPlugins(target.claudeHome),
		knownMarketplaces: readKnownMarketplaces(target.claudeHome),
	};
}

export function installManagedPlugin(
	pluginId: string,
	options: PluginCommandOptions = {},
): ManagedPluginMutationResult {
	const runner = options.runner ?? createDefaultRunner();
	const env = options.env ?? process.env;
	const targets = resolvePluginTargets(options.persona, env);
	const capabilities = detectClaudePluginCapabilities(runner);
	assertCapabilities(capabilities, ["install"], "official plugin installation");
	const { marketplaceName } = parsePluginId(pluginId);

	return {
		pluginId,
		targets: targets.map((target) => {
			const state = getPluginState(target);
			const actions: string[] = [];
			const installed = Array.isArray(state.installedPlugins[pluginId]);
			const enabled = state.enabledPlugins[pluginId] === true;
			const marketplaceKnown = Object.hasOwn(state.knownMarketplaces, marketplaceName);

			if (options.marketplaceSource && !marketplaceKnown) {
				assertCapabilities(capabilities, ["marketplaceAdd"], "plugin marketplace add");
				runClaudePluginCommand(
					runner,
					target,
					["plugin", "marketplace", "add", options.marketplaceSource],
					env,
				);
				actions.push("marketplace:add");
			}

			if (installed && !enabled) {
				assertCapabilities(capabilities, ["enable"], "plugin enable");
				runClaudePluginCommand(runner, target, ["plugin", "enable", pluginId], env);
				actions.push("plugin:enable");
			} else if (!installed) {
				runClaudePluginCommand(runner, target, ["plugin", "install", pluginId], env);
				actions.push("plugin:install");
			}

			return { ...target, actions };
		}),
	};
}

export function updateManagedPlugin(
	pluginId: string,
	options: PluginCommandOptions = {},
): ManagedPluginMutationResult {
	const runner = options.runner ?? createDefaultRunner();
	const env = options.env ?? process.env;
	const targets = resolvePluginTargets(options.persona, env);
	const capabilities = detectClaudePluginCapabilities(runner);
	assertCapabilities(capabilities, ["update"], "official plugin update");
	const { marketplaceName } = parsePluginId(pluginId);

	return {
		pluginId,
		targets: targets.map((target) => {
			const state = getPluginState(target);
			if (!Array.isArray(state.installedPlugins[pluginId])) {
				throw new Error(
					`Plugin "${pluginId}" is not installed in the ${target.persona} profile (${target.claudeHome}).`,
				);
			}

			const actions: string[] = [];
			const marketplaceKnown = Object.hasOwn(state.knownMarketplaces, marketplaceName);
			if (marketplaceKnown) {
				assertCapabilities(capabilities, ["marketplaceUpdate"], "plugin marketplace update");
				runClaudePluginCommand(
					runner,
					target,
					["plugin", "marketplace", "update", marketplaceName],
					env,
				);
				actions.push("marketplace:update");
			} else if (options.marketplaceSource) {
				assertCapabilities(capabilities, ["marketplaceAdd"], "plugin marketplace add");
				runClaudePluginCommand(
					runner,
					target,
					["plugin", "marketplace", "add", options.marketplaceSource],
					env,
				);
				actions.push("marketplace:add");
			}

			runClaudePluginCommand(runner, target, ["plugin", "update", pluginId], env);
			actions.push("plugin:update");
			return { ...target, actions };
		}),
	};
}

export function uninstallManagedPlugin(
	pluginId: string,
	options: PluginCommandOptions = {},
): ManagedPluginMutationResult {
	const runner = options.runner ?? createDefaultRunner();
	const env = options.env ?? process.env;
	const targets = resolvePluginTargets(options.persona, env);
	const capabilities = detectClaudePluginCapabilities(runner);
	assertCapabilities(capabilities, ["uninstall"], "official plugin uninstall");

	return {
		pluginId,
		targets: targets.map((target) => {
			runClaudePluginCommand(runner, target, ["plugin", "uninstall", pluginId], env);
			return { ...target, actions: ["plugin:uninstall"] };
		}),
	};
}

export function listManagedPlugins(
	options: { persona?: PluginPersonaScope; env?: NodeJS.ProcessEnv } = {},
): ManagedPluginListEntry[] {
	const targets = resolvePluginTargets(options.persona, options.env ?? process.env);
	return targets.map((target) => {
		const enabledPlugins = readSettingsEnabledPlugins(target.claudeHome);
		const installedPlugins = readInstalledPlugins(target.claudeHome);
		const pluginIds = Array.from(
			new Set([...Object.keys(enabledPlugins), ...Object.keys(installedPlugins)]),
		).sort((left, right) => left.localeCompare(right));

		return {
			...target,
			plugins: pluginIds.map((pluginId) => ({
				pluginId,
				enabled: enabledPlugins[pluginId] === true,
				installed: Array.isArray(installedPlugins[pluginId]),
				versions: Array.from(
					new Set(
						(installedPlugins[pluginId] ?? [])
							.map((entry) => entry.version?.trim())
							.filter((version): version is string => Boolean(version)),
					),
				).sort((left, right) => left.localeCompare(right)),
			})),
		};
	});
}

function logMutationResult(result: ManagedPluginMutationResult): void {
	for (const target of result.targets) {
		const actionSummary = target.actions.length > 0 ? target.actions.join(", ") : "no-op";
		console.log(`${target.persona}: ${actionSummary} (${target.claudeHome})`);
	}
}

function logPluginList(entries: ManagedPluginListEntry[]): void {
	for (const entry of entries) {
		console.log(`${entry.persona} (${entry.claudeHome})`);
		if (entry.plugins.length === 0) {
			console.log("  (no managed plugins)");
			continue;
		}
		for (const plugin of entry.plugins) {
			const versions = plugin.versions.length > 0 ? ` versions=${plugin.versions.join(",")}` : "";
			console.log(
				`  ${plugin.pluginId} installed=${plugin.installed ? "yes" : "no"} enabled=${plugin.enabled ? "yes" : "no"}${versions}`,
			);
		}
	}
}

function handlePluginCommandError(err: unknown): never {
	console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
	process.exit(1);
}

export function registerPluginsCommandGroup(parent: Command): void {
	parent
		.command("list")
		.description("List official Claude plugins installed in the private and/or social profiles")
		.option("--persona <scope>", "Target persona: private, social, or both", "private")
		.option("--json", "Emit machine-readable JSON")
		.action((options: { persona?: PluginPersonaScope; json?: boolean }) => {
			try {
				const entries = listManagedPlugins({ persona: options.persona });
				if (options.json) {
					process.stdout.write(`${JSON.stringify(entries, null, 2)}\n`);
					return;
				}
				logPluginList(entries);
			} catch (err) {
				handlePluginCommandError(err);
			}
		});

	parent
		.command("install")
		.description("Install an official Claude plugin into the target persona profile(s)")
		.argument("<plugin-id>", "Plugin id in the form <plugin>@<marketplace>")
		.option("--persona <scope>", "Target persona: private, social, or both", "private")
		.option(
			"--marketplace-source <source>",
			"Marketplace source for first-time install (GitHub shorthand, git URL, remote marketplace.json URL, or local path)",
		)
		.action(
			(pluginId: string, options: { persona?: PluginPersonaScope; marketplaceSource?: string }) => {
				try {
					logMutationResult(
						installManagedPlugin(pluginId, {
							persona: options.persona,
							marketplaceSource: options.marketplaceSource,
						}),
					);
				} catch (err) {
					handlePluginCommandError(err);
				}
			},
		);

	parent
		.command("update")
		.description("Update an official Claude plugin in the target persona profile(s)")
		.argument("<plugin-id>", "Plugin id in the form <plugin>@<marketplace>")
		.option("--persona <scope>", "Target persona: private, social, or both", "private")
		.option(
			"--marketplace-source <source>",
			"Marketplace source to add when the profile does not yet know the plugin marketplace",
		)
		.action(
			(pluginId: string, options: { persona?: PluginPersonaScope; marketplaceSource?: string }) => {
				try {
					logMutationResult(
						updateManagedPlugin(pluginId, {
							persona: options.persona,
							marketplaceSource: options.marketplaceSource,
						}),
					);
				} catch (err) {
					handlePluginCommandError(err);
				}
			},
		);

	parent
		.command("uninstall")
		.description("Uninstall an official Claude plugin from the target persona profile(s)")
		.argument("<plugin-id>", "Plugin id in the form <plugin>@<marketplace>")
		.option("--persona <scope>", "Target persona: private, social, or both", "private")
		.action((pluginId: string, options: { persona?: PluginPersonaScope }) => {
			try {
				logMutationResult(uninstallManagedPlugin(pluginId, { persona: options.persona }));
			} catch (err) {
				handlePluginCommandError(err);
			}
		});
}
