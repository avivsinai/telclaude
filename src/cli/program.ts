import { Command } from "commander";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function getVersion(): string {
	try {
		const pkgPath = path.resolve(__dirname, "../../package.json");
		const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));
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
