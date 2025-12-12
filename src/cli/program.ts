import { createRequire } from "node:module";
import { Command } from "commander";

const require = createRequire(import.meta.url);

function getVersion(): string {
	try {
		// Resolve package.json relative to this module (works from src or dist)
		const pkg = require("../../package.json") as { version?: string };
		return pkg.version ?? "0.0.0";
	} catch {
		return "0.0.0";
	}
}

export function createProgram(): Command {
	const program = new Command();

	program
		.name("telclaude")
		.description("Telegram-Claude bridge with security layer")
		.version(getVersion())
		.option("-v, --verbose", "Enable verbose output")
		.option("-c, --config <path>", "Path to config file");

	return program;
}
