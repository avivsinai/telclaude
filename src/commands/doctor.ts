import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import type { Command } from "commander";
import { getChildLogger } from "../logging.js";
import { isSandboxAvailable } from "../sandbox/index.js";
import { isTOTPDaemonAvailable } from "../security/totp.js";

const logger = getChildLogger({ module: "cmd-doctor" });

function findSkills(root: string): string[] {
	const skillsRoot = path.join(root, ".claude", "skills");
	if (!fs.existsSync(skillsRoot)) return [];
	const entries = fs.readdirSync(skillsRoot, { withFileTypes: true });
	return entries
		.filter((e) => e.isDirectory())
		.map((e) => path.join(skillsRoot, e.name, "SKILL.md"))
		.filter((p) => fs.existsSync(p));
}

export function registerDoctorCommand(program: Command): void {
	program
		.command("doctor")
		.description("Check Claude CLI, login status, and local skills")
		.action(async () => {
			try {
				// Claude CLI version
				let version = "missing";
				try {
					version = execSync("claude --version", {
						encoding: "utf8",
						stdio: ["ignore", "pipe", "pipe"],
					}).trim();
				} catch (err) {
					console.error(
						"Claude CLI not found. Install it first (e.g., brew install anthropic-ai/cli/claude).",
					);
					process.exit(1);
				}

				// Login check
				let loggedIn = false;
				try {
					const who = execSync("claude /whoami", {
						encoding: "utf8",
						stdio: ["ignore", "pipe", "pipe"],
					}).trim();
					loggedIn = /Logged in/i.test(who) || who.length > 0;
				} catch {
					// fall through
				}

				// Skills check (repo-local)
				const skills = findSkills(process.cwd());

				// Sandbox check
				const sandboxAvailable = await isSandboxAvailable();

				// TOTP daemon check
				const totpDaemonAvailable = await isTOTPDaemonAvailable();

				console.log("=== telclaude doctor ===");
				console.log(`Claude CLI: ${version}`);
				console.log(
					`Logged in: ${loggedIn ? "yes" : "no"}${loggedIn ? "" : " (run: claude login)"}`,
				);
				console.log(`Local skills: ${skills.length > 0 ? "found" : "none found"}`);
				if (skills.length) {
					for (const s of skills) console.log(`  - ${s}`);
				}
				console.log(
					`Sandbox: ${sandboxAvailable ? "available" : "unavailable"}${sandboxAvailable ? "" : " (optional - OS-level isolation)"}`,
				);
				console.log(
					`TOTP daemon: ${totpDaemonAvailable ? "running" : "not running"}${totpDaemonAvailable ? "" : " (run: telclaude totp-daemon)"}`,
				);

				if (!loggedIn) {
					process.exitCode = 1;
				}
			} catch (err) {
				logger.error({ error: String(err) }, "doctor command failed");
				console.error(`Error: ${err}`);
				process.exit(1);
			}
		});
}
