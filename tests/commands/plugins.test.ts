import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
	detectClaudePluginCapabilities,
	installManagedPlugin,
	listManagedPlugins,
	resolvePluginTargets,
	type ClaudePluginRunner,
	uninstallManagedPlugin,
	updateManagedPlugin,
} from "../../src/commands/plugins.js";

type RunnerCall = {
	cmd: string;
	args: string[];
	env?: NodeJS.ProcessEnv;
};

function createRunner(outputs: Record<string, { status?: number; stdout?: string; stderr?: string }>) {
	const calls: RunnerCall[] = [];
	const runner: ClaudePluginRunner = {
		run(cmd, args, options) {
			calls.push({ cmd, args, env: options?.env });
			const key = [cmd, ...args].join(" ");
			const next = outputs[key];
			if (!next) {
				throw new Error(`Unexpected runner call: ${key}`);
			}
			return {
				status: next.status ?? 0,
				stdout: next.stdout ?? "",
				stderr: next.stderr ?? "",
				pid: 1,
				output: [],
				signal: null,
			};
		},
	};
	return { runner, calls };
}

function writeJson(filePath: string, value: unknown): void {
	fs.mkdirSync(path.dirname(filePath), { recursive: true });
	fs.writeFileSync(filePath, JSON.stringify(value, null, 2), "utf8");
}

describe("resolvePluginTargets", () => {
	let tempRoot = "";

	beforeEach(() => {
		tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "plugins-command-"));
	});

	afterEach(() => {
		if (tempRoot && fs.existsSync(tempRoot)) {
			fs.rmSync(tempRoot, { recursive: true, force: true });
		}
	});

	it("defaults to the private persona", () => {
		const privateHome = path.join(tempRoot, "private");
		const targets = resolvePluginTargets(undefined, {
			TELCLAUDE_PRIVATE_CLAUDE_HOME: privateHome,
		});

		expect(targets).toEqual([{ persona: "private", claudeHome: privateHome }]);
	});

	it("returns both personas when requested", () => {
		const privateHome = path.join(tempRoot, "private");
		const socialHome = path.join(tempRoot, "social");
		const targets = resolvePluginTargets("both", {
			TELCLAUDE_PRIVATE_CLAUDE_HOME: privateHome,
			TELCLAUDE_SOCIAL_CLAUDE_HOME: socialHome,
		});

		expect(targets).toEqual([
			{ persona: "private", claudeHome: privateHome },
			{ persona: "social", claudeHome: socialHome },
		]);
	});

	it("fails closed when the requested social profile is not configured", () => {
		expect(() => resolvePluginTargets("social", {})).toThrow(
			"TELCLAUDE_SOCIAL_CLAUDE_HOME is not configured",
		);
	});

	it("rejects invalid persona scopes", () => {
		expect(() =>
			resolvePluginTargets("everywhere", {
				TELCLAUDE_PRIVATE_CLAUDE_HOME: path.join(tempRoot, "private"),
			}),
		).toThrow('Invalid persona scope "everywhere"');
	});
});

describe("detectClaudePluginCapabilities", () => {
	it("detects install and marketplace support from the official CLI help", () => {
		const { runner } = createRunner({
			"claude plugin --help": {
				stdout: `Usage: claude plugin [options] [command]

Commands:
  install [options] <plugin>
  list [options]
  marketplace
  update [options] <plugin>
  uninstall [options] <plugin>
  enable [options] <plugin>
  disable [options] [plugin]
`,
			},
			"claude plugin marketplace --help": {
				stdout: `Usage: claude plugin marketplace [options] [command]

Commands:
  add <source>
  list
  update [name]
`,
			},
		});

		expect(detectClaudePluginCapabilities(runner)).toEqual({
			disable: true,
			enable: true,
			install: true,
			list: true,
			marketplaceAdd: true,
			marketplaceUpdate: true,
			uninstall: true,
			update: true,
		});
	});

	it("reports missing plugin management support on older CLI builds", () => {
		const { runner } = createRunner({
			"claude plugin --help": {
				stdout: `Usage: claude plugin [options] [command]

Commands:
  validate <path>
`,
			},
			"claude plugin marketplace --help": {
				status: 1,
				stderr: "Unknown command",
			},
		});

		expect(detectClaudePluginCapabilities(runner)).toEqual({
			disable: false,
			enable: false,
			install: false,
			list: false,
			marketplaceAdd: false,
			marketplaceUpdate: false,
			uninstall: false,
			update: false,
		});
	});
});

describe("managed plugin commands", () => {
	let tempRoot = "";
	let privateHome = "";
	let socialHome = "";

	beforeEach(() => {
		tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "plugins-command-"));
		privateHome = path.join(tempRoot, "private");
		socialHome = path.join(tempRoot, "social");
	});

	afterEach(() => {
		if (tempRoot && fs.existsSync(tempRoot)) {
			fs.rmSync(tempRoot, { recursive: true, force: true });
		}
	});

	it("installs into the requested persona profiles via official claude plugin commands", () => {
		const { runner, calls } = createRunner({
			"claude plugin --help": {
				stdout:
					"Commands:\n  install [options] <plugin>\n  list [options]\n  marketplace\n  update [options] <plugin>\n  uninstall [options] <plugin>\n  enable [options] <plugin>\n  disable [options] [plugin]\n",
			},
			"claude plugin marketplace --help": {
				stdout: "Commands:\n  add <source>\n  update [name]\n",
			},
			"claude plugin marketplace add avivsinai/skills-marketplace": {
				stdout: "added\n",
			},
			"claude plugin install shaon@avivsinai-marketplace": {
				stdout: "installed\n",
			},
		});

		const result = installManagedPlugin("shaon@avivsinai-marketplace", {
			persona: "private",
			marketplaceSource: "avivsinai/skills-marketplace",
			env: {
				TELCLAUDE_PRIVATE_CLAUDE_HOME: privateHome,
			},
			runner,
		});

		expect(result.targets).toEqual([
			{
				persona: "private",
				claudeHome: privateHome,
				actions: ["marketplace:add", "plugin:install"],
			},
		]);
		expect(calls.at(-2)?.args).toEqual([
			"plugin",
			"marketplace",
			"add",
			"avivsinai/skills-marketplace",
		]);
		expect(calls.at(-1)?.args).toEqual(["plugin", "install", "shaon@avivsinai-marketplace"]);
		expect(calls.at(-1)?.env?.CLAUDE_CONFIG_DIR).toBe(privateHome);
	});

	it("enables an already-installed but disabled plugin instead of reinstalling it", () => {
		writeJson(path.join(privateHome, "settings.json"), {
			enabledPlugins: {
				"shaon@avivsinai-marketplace": false,
			},
		});
		writeJson(path.join(privateHome, "plugins", "installed_plugins.json"), {
			version: 2,
			plugins: {
				"shaon@avivsinai-marketplace": [
					{
						scope: "user",
						installPath: path.join(privateHome, "plugins", "cache", "avivsinai-marketplace", "shaon", "0.8.3"),
						version: "0.8.3",
						installedAt: "2026-04-20T00:00:00.000Z",
						lastUpdated: "2026-04-20T00:00:00.000Z",
					},
				],
			},
		});

		const { runner } = createRunner({
			"claude plugin --help": {
				stdout:
					"Commands:\n  install [options] <plugin>\n  list [options]\n  marketplace\n  update [options] <plugin>\n  uninstall [options] <plugin>\n  enable [options] <plugin>\n  disable [options] [plugin]\n",
			},
			"claude plugin marketplace --help": {
				stdout: "Commands:\n  add <source>\n  update [name]\n",
			},
			"claude plugin enable shaon@avivsinai-marketplace": {
				stdout: "enabled\n",
			},
		});

		const result = installManagedPlugin("shaon@avivsinai-marketplace", {
			persona: "private",
			env: {
				TELCLAUDE_PRIVATE_CLAUDE_HOME: privateHome,
			},
			runner,
		});

		expect(result.targets[0]?.actions).toEqual(["plugin:enable"]);
	});

	it("updates an installed plugin after refreshing the configured marketplace", () => {
		writeJson(path.join(privateHome, "settings.json"), {
			enabledPlugins: {
				"shaon@avivsinai-marketplace": true,
			},
		});
		writeJson(path.join(privateHome, "plugins", "installed_plugins.json"), {
			version: 2,
			plugins: {
				"shaon@avivsinai-marketplace": [
					{
						scope: "user",
						installPath: path.join(privateHome, "plugins", "cache", "avivsinai-marketplace", "shaon", "0.8.3"),
						version: "0.8.3",
						installedAt: "2026-04-20T00:00:00.000Z",
						lastUpdated: "2026-04-20T00:00:00.000Z",
					},
				],
			},
		});
		writeJson(path.join(privateHome, "plugins", "known_marketplaces.json"), {
			"avivsinai-marketplace": {
				source: {
					source: "github",
					repo: "avivsinai/skills-marketplace",
				},
			},
		});

		const { runner, calls } = createRunner({
			"claude plugin --help": {
				stdout:
					"Commands:\n  install [options] <plugin>\n  list [options]\n  marketplace\n  update [options] <plugin>\n  uninstall [options] <plugin>\n  enable [options] <plugin>\n  disable [options] [plugin]\n",
			},
			"claude plugin marketplace --help": {
				stdout: "Commands:\n  add <source>\n  update [name]\n",
			},
			"claude plugin marketplace update avivsinai-marketplace": {
				stdout: "updated marketplace\n",
			},
			"claude plugin update shaon@avivsinai-marketplace": {
				stdout: "updated plugin\n",
			},
		});

		const result = updateManagedPlugin("shaon@avivsinai-marketplace", {
			persona: "private",
			marketplaceSource: "avivsinai/skills-marketplace",
			env: {
				TELCLAUDE_PRIVATE_CLAUDE_HOME: privateHome,
			},
			runner,
		});

		expect(result.targets[0]?.actions).toEqual(["marketplace:update", "plugin:update"]);
		expect(calls.at(-2)?.args).toEqual([
			"plugin",
			"marketplace",
			"update",
			"avivsinai-marketplace",
		]);
		expect(calls.at(-1)?.args).toEqual(["plugin", "update", "shaon@avivsinai-marketplace"]);
	});

	it("lists the installed plugin state for each persona profile", () => {
		writeJson(path.join(privateHome, "settings.json"), {
			enabledPlugins: {
				"shaon@avivsinai-marketplace": true,
			},
		});
		writeJson(path.join(privateHome, "plugins", "installed_plugins.json"), {
			version: 2,
			plugins: {
				"shaon@avivsinai-marketplace": [
					{
						scope: "user",
						installPath: path.join(privateHome, "plugins", "cache", "avivsinai-marketplace", "shaon", "0.8.3"),
						version: "0.8.3",
						installedAt: "2026-04-20T00:00:00.000Z",
						lastUpdated: "2026-04-20T00:00:00.000Z",
					},
				],
			},
		});
		writeJson(path.join(socialHome, "settings.json"), {
			enabledPlugins: {
				"shaon@avivsinai-marketplace": false,
			},
		});
		writeJson(path.join(socialHome, "plugins", "installed_plugins.json"), {
			version: 2,
			plugins: {
				"shaon@avivsinai-marketplace": [
					{
						scope: "user",
						installPath: path.join(socialHome, "plugins", "cache", "avivsinai-marketplace", "shaon", "0.8.3"),
						version: "0.8.3",
						installedAt: "2026-04-20T00:00:00.000Z",
						lastUpdated: "2026-04-20T00:00:00.000Z",
					},
				],
			},
		});

		const listed = listManagedPlugins({
			persona: "both",
			env: {
				TELCLAUDE_PRIVATE_CLAUDE_HOME: privateHome,
				TELCLAUDE_SOCIAL_CLAUDE_HOME: socialHome,
			},
		});

		expect(listed).toEqual([
			{
				persona: "private",
				claudeHome: privateHome,
				plugins: [
					{
						enabled: true,
						installed: true,
						pluginId: "shaon@avivsinai-marketplace",
						versions: ["0.8.3"],
					},
				],
			},
			{
				persona: "social",
				claudeHome: socialHome,
				plugins: [
					{
						enabled: false,
						installed: true,
						pluginId: "shaon@avivsinai-marketplace",
						versions: ["0.8.3"],
					},
				],
			},
		]);
	});

	it("fails loudly when profile metadata is corrupted", () => {
		fs.mkdirSync(path.join(privateHome, "plugins"), { recursive: true });
		fs.writeFileSync(path.join(privateHome, "settings.json"), "{ invalid", "utf8");

		expect(() =>
			listManagedPlugins({
				persona: "private",
				env: {
					TELCLAUDE_PRIVATE_CLAUDE_HOME: privateHome,
				},
			}),
		).toThrow("Failed to read Claude plugin metadata");
	});

	it("uninstalls the plugin from each requested persona", () => {
		writeJson(path.join(privateHome, "settings.json"), {
			enabledPlugins: {
				"shaon@avivsinai-marketplace": true,
			},
		});
		writeJson(path.join(privateHome, "plugins", "installed_plugins.json"), {
			version: 2,
			plugins: {
				"shaon@avivsinai-marketplace": [{ version: "0.8.3" }],
			},
		});

		const { runner } = createRunner({
			"claude plugin --help": {
				stdout:
					"Commands:\n  install [options] <plugin>\n  list [options]\n  marketplace\n  update [options] <plugin>\n  uninstall [options] <plugin>\n  enable [options] <plugin>\n  disable [options] [plugin]\n",
			},
			"claude plugin marketplace --help": {
				stdout: "Commands:\n  add <source>\n  update [name]\n",
			},
			"claude plugin uninstall shaon@avivsinai-marketplace": {
				stdout: "uninstalled\n",
			},
		});

		const result = uninstallManagedPlugin("shaon@avivsinai-marketplace", {
			persona: "private",
			env: {
				TELCLAUDE_PRIVATE_CLAUDE_HOME: privateHome,
			},
			runner,
		});

		expect(result.targets[0]?.actions).toEqual(["plugin:uninstall"]);
	});
});
