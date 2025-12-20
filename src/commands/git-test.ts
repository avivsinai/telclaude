/**
 * CLI command for testing git connectivity and credentials.
 * Provides detailed diagnostics for troubleshooting git setup.
 */

import { execSync } from "node:child_process";

import type { Command } from "commander";

import { getChildLogger } from "../logging.js";
import {
	getGitCredentials,
	getGitCredentialsSource,
	testGitConnectivity,
} from "../services/git-credentials.js";

const logger = getChildLogger({ module: "cmd-git-test" });

export function registerGitTestCommand(program: Command): void {
	program
		.command("git-test")
		.description("Test git connectivity and credentials")
		.option("--verbose", "Show detailed output")
		.option("--repo <url>", "Test against a specific repository URL")
		.action(async (opts: { verbose?: boolean; repo?: string }) => {
			try {
				console.log("Git Configuration Test");
				console.log("======================");
				console.log("");

				let allPassed = true;

				// 1. Check credentials source
				console.log("1. Credentials Source");
				const source = await getGitCredentialsSource();
				if (source) {
					console.log(`   ✓ Credentials found in: ${source}`);
				} else {
					console.log("   ✗ No credentials configured");
					console.log("     Run: telclaude setup-git");
					allPassed = false;
				}
				console.log("");

				// 2. Check credential details
				console.log("2. Credential Details");
				const creds = await getGitCredentials();
				if (creds) {
					console.log(`   Username: ${creds.username}`);
					console.log(`   Email:    ${creds.email}`);
					console.log(`   Token:    ${maskToken(creds.token)}`);

					// Validate token format
					if (creds.token.startsWith("github_pat_") || creds.token.startsWith("ghp_")) {
						console.log("   ✓ Token format looks valid (GitHub)");
					} else if (creds.token.startsWith("glpat-")) {
						console.log("   ✓ Token format looks valid (GitLab)");
					} else {
						console.log("   ⚠ Token format not recognized - may still work");
					}
				} else {
					console.log("   (no credentials available)");
				}
				console.log("");

				// 3. Check git binary
				console.log("3. Git Installation");
				try {
					const gitVersion = execSync("git --version", { encoding: "utf8" }).trim();
					console.log(`   ✓ ${gitVersion}`);
				} catch {
					console.log("   ✗ Git not found in PATH");
					allPassed = false;
				}
				console.log("");

				// 4. Check git config
				console.log("4. Git Configuration");
				try {
					const userName = execSync("git config --global user.name", {
						encoding: "utf8",
					}).trim();
					const userEmail = execSync("git config --global user.email", {
						encoding: "utf8",
					}).trim();
					console.log(`   user.name:  ${userName || "(not set)"}`);
					console.log(`   user.email: ${userEmail || "(not set)"}`);

					if (userName && userEmail) {
						console.log("   ✓ Git identity is configured");
					} else {
						console.log("   ⚠ Git identity not fully configured");
						console.log("     Run: telclaude setup-git --apply");
					}
				} catch {
					console.log("   user.name:  (not set)");
					console.log("   user.email: (not set)");
					console.log("   ⚠ Git identity not configured");
					console.log("     Run: telclaude setup-git --apply");
				}
				console.log("");

				// 5. Test connectivity
				console.log("5. Connectivity Test");
				if (creds) {
					const testUrl = opts.repo || "https://github.com";
					console.log(`   Testing against: ${testUrl}`);
					const result = await testGitConnectivity(testUrl);
					if (result.success) {
						console.log(`   ✓ ${result.message}`);
					} else {
						console.log(`   ✗ ${result.message}`);
						allPassed = false;
					}
				} else {
					console.log("   (skipped - no credentials)");
				}
				console.log("");

				// 6. Environment variables (verbose only)
				if (opts.verbose) {
					console.log("6. Environment Variables");
					const envVars = [
						"GIT_USERNAME",
						"GIT_EMAIL",
						"GITHUB_TOKEN",
						"GIT_TOKEN",
						"GIT_AUTHOR_NAME",
						"GIT_AUTHOR_EMAIL",
						"GIT_COMMITTER_NAME",
						"GIT_COMMITTER_EMAIL",
					];
					for (const v of envVars) {
						const val = process.env[v];
						if (val) {
							if (v.includes("TOKEN")) {
								console.log(`   ${v}: ${maskToken(val)}`);
							} else {
								console.log(`   ${v}: ${val}`);
							}
						} else {
							console.log(`   ${v}: (not set)`);
						}
					}
					console.log("");
				}

				// Summary
				console.log("─".repeat(40));
				if (allPassed && creds) {
					console.log("✓ All tests passed - git is ready to use");
					process.exit(0);
				} else if (creds) {
					console.log("⚠ Some tests failed - check output above");
					process.exit(1);
				} else {
					console.log("✗ Git credentials not configured");
					console.log("  Run: telclaude setup-git");
					process.exit(1);
				}
			} catch (err) {
				logger.error({ error: String(err) }, "git-test command failed");
				console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
				process.exit(1);
			}
		});
}

/**
 * Mask a token for display.
 */
function maskToken(token: string): string {
	if (token.length <= 12) {
		return "****";
	}
	return `${token.slice(0, 8)}...${token.slice(-4)}`;
}
