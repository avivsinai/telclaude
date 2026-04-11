import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import type { Command } from "commander";
import { loadConfig } from "../config/config.js";
import { resolveConfigPath } from "../config/path.js";
import { getChildLogger } from "../logging.js";
import {
	buildAllowedDomainNames,
	buildAllowedDomains,
	DEFAULT_NETWORK_CONFIG,
	getDockerRuntimeRequirementMessage,
	getNetworkIsolationSummary,
	getSandboxMode,
	runNetworkSelfTest,
} from "../sandbox/index.js";
import { CORE_SECRET_PATTERNS, filterOutput, redactSecrets } from "../security/index.js";
import { formatScanResults, scanAllSkills } from "../security/skill-scanner.js";
import { isTOTPDaemonAvailable } from "../security/totp.js";
import { formatAuditReport, runAuditCollectors } from "./audit-collectors.js";
import { formatFixReport, runAutoFix } from "./audit-fixers.js";

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

// Test data for --secrets self-test
const SECRET_TEST_CASES = [
	{
		name: "GitHub PAT",
		input: "key: ghp_abc123def456ghi789jkl012mno345pqr678",
		shouldRedact: true,
	},
	{
		name: "AWS Access Key",
		input: "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
		shouldRedact: true,
	},
	{
		name: "Private Key",
		input: "-----BEGIN RSA PRIVATE KEY-----\nMIIE...",
		shouldRedact: true,
	},
	{ name: "Anthropic API Key", input: "sk-ant-api03-abc123...", shouldRedact: true },
	{
		name: "Telegram Bot Token",
		input: "1234567890:ABCdefGHIjklMNOpqrSTUvwxYZ12345678901",
		shouldRedact: true,
	},
	{ name: "Normal text", input: "Hello, this is a normal message.", shouldRedact: false },
	{ name: "Code snippet", input: "const x = 42; return x * 2;", shouldRedact: false },
];

export function registerDoctorCommand(program: Command): void {
	program
		.command("doctor")
		.description("Check Claude CLI, login status, and local skills")
		.option("--network", "Run network isolation self-test")
		.option("--secrets", "Run secret detection self-test")
		.option("--skills", "Run skill static code scanner")
		.option("--security", "Run comprehensive security audit")
		.option("--fix", "Auto-fix safe security issues (requires --security)")
		.action(
			async (options: {
				network?: boolean;
				secrets?: boolean;
				skills?: boolean;
				security?: boolean;
				fix?: boolean;
			}) => {
				try {
					// Claude CLI version
					let version = "missing";
					try {
						version = execSync("claude --version", {
							encoding: "utf8",
							stdio: ["ignore", "pipe", "pipe"],
						}).trim();
					} catch {
						console.error(
							"Claude CLI not found. Install it first (e.g., brew install anthropic-ai/cli/claude).",
						);
						process.exit(1);
					}

					// Login check
					let loggedIn = false;
					try {
						const who = execSync("claude whoami", {
							encoding: "utf8",
							stdio: ["ignore", "pipe", "pipe"],
						}).trim();
						loggedIn = /Logged in/i.test(who) || who.length > 0;
					} catch {
						// fall through
					}

					// Skills check (repo-local)
					const skills = findSkills(process.cwd());

					// Sandbox mode check
					const sandboxMode = getSandboxMode();

					// TOTP daemon check
					const totpDaemonAvailable = await isTOTPDaemonAvailable();

					// Load config for profile info
					const cfg = loadConfig();
					const profile = cfg.security?.profile ?? "simple";
					const additionalDomains = cfg.security?.network?.additionalDomains ?? [];
					const allowedDomainNames = buildAllowedDomainNames(additionalDomains);
					const allowedDomains = buildAllowedDomains(additionalDomains);

					console.log("=== telclaude doctor ===\n");

					// Claude CLI section
					console.log("📦 Claude CLI");
					console.log(`   Version: ${version}`);
					console.log(
						`   Logged in: ${loggedIn ? "✓ yes" : "✗ no"}${loggedIn ? "" : " (run: claude login)"}`,
					);
					console.log(
						`   Local skills: ${skills.length > 0 ? `✓ ${skills.length} found` : "none found"}`,
					);
					if (skills.length) {
						for (const s of skills) console.log(`     - ${path.basename(path.dirname(s))}`);
					}

					// Security section
					console.log("\n🔒 Security");
					console.log(`   Profile: ${profile}`);
					if (profile === "strict") {
						console.log(
							`     Observer: ${cfg.security?.observer?.enabled !== false ? "enabled" : "disabled"}`,
						);
						console.log("     Approvals: enabled");
					} else if (profile === "simple") {
						console.log("     Observer: disabled (simple profile)");
						console.log("     Approvals: disabled (simple profile)");
					} else {
						console.log("     ⚠️  TEST PROFILE - NO SECURITY");
					}

					// Five pillars status
					console.log("\n🛡️  Security Pillars");
					const sandboxDesc =
						sandboxMode === "docker"
							? "Docker container (SDK sandbox disabled)"
							: "unsupported non-Docker runtime";
					console.log(`   1. Filesystem isolation: ✓ ${sandboxDesc}`);
					console.log("   2. Environment isolation: ✓ minimal env vars passed to sandbox");

					// Network isolation - default is strict allowlist
					const netSummaryPillars = getNetworkIsolationSummary(
						{ ...DEFAULT_NETWORK_CONFIG, allowedDomains },
						allowedDomainNames,
					);
					if (netSummaryPillars.isPermissive) {
						console.log(
							"   3. Network isolation: ⚠️  OPEN (metadata blocked, but wildcard egress enabled)",
						);
					} else {
						console.log(
							`   3. Network isolation: ✓ ${netSummaryPillars.allowedDomains} domains allowed`,
						);
					}
					if (additionalDomains.length > 0) {
						console.log(`     Additional domains: ${additionalDomains.length}`);
					}
					if (process.env.TELCLAUDE_NETWORK_MODE) {
						console.log(
							`     TELCLAUDE_NETWORK_MODE=${process.env.TELCLAUDE_NETWORK_MODE} (env override)`,
						);
					}

					console.log(`   4. Secret filtering: ✓ ${CORE_SECRET_PATTERNS.length} CORE patterns`);
					console.log(
						`   5. Auth/TOTP: ${totpDaemonAvailable ? "✓ daemon running" : "⚠️  daemon not running"}`,
					);

					// Sandbox details
					console.log("\n📦 Sandbox");
					console.log(`   Mode: ${sandboxMode === "docker" ? "Docker" : "Native (unsupported)"}`);
					if (sandboxMode === "docker") {
						console.log("   SDK sandbox: disabled (container provides isolation)");
					} else {
						console.log(`   ${getDockerRuntimeRequirementMessage("Telclaude")}`);
					}

					// TOTP details
					console.log("\n🔐 TOTP Daemon");
					console.log(`   Status: ${totpDaemonAvailable ? "✓ running" : "✗ not running"}`);
					if (!totpDaemonAvailable) {
						console.log("   Start with: telclaude totp-daemon");
					}

					// Overall health
					console.log("\n📊 Overall Health");
					const issues: string[] = [];
					if (!loggedIn) issues.push("Claude not logged in");
					if (!totpDaemonAvailable) issues.push("TOTP daemon not running");
					if (sandboxMode !== "docker") {
						issues.push("Native/non-Docker runtime is unsupported");
					}

					if (issues.length === 0) {
						console.log("   ✓ All checks passed");
					} else {
						console.log(`   ⚠️  ${issues.length} issue(s) found:`);
						for (const issue of issues) {
							console.log(`     - ${issue}`);
						}
					}

					if (!loggedIn) {
						process.exitCode = 1;
					}
					if (sandboxMode !== "docker") {
						process.exitCode = 1;
					}

					// Run --network self-test if requested
					if (options.network) {
						console.log("\n🌐 Network Isolation Self-Test");
						const netResult = runNetworkSelfTest({
							...DEFAULT_NETWORK_CONFIG,
							allowedDomains,
						});
						for (const test of netResult.tests) {
							console.log(`   ${test.passed ? "✓" : "✗"} ${test.name}: ${test.details ?? ""}`);
						}
						console.log(
							`\n   Result: ${netResult.passed ? "✓ All tests passed" : "✗ Some tests failed"}`,
						);
						if (!netResult.passed) {
							process.exitCode = 1;
						}

						// Show network summary
						const netSummary = getNetworkIsolationSummary(
							{ ...DEFAULT_NETWORK_CONFIG, allowedDomains },
							allowedDomainNames,
						);
						console.log("\n   Network Summary:");
						console.log(`     Allowed domains: ${netSummary.allowedDomains}`);
						if (netSummary.domainsWithPost.length > 0) {
							console.log(`     ⚠️  POST enabled for: ${netSummary.domainsWithPost.join(", ")}`);
						}
						console.log(`     Blocked metadata endpoints: ${netSummary.blockedMetadataEndpoints}`);
						console.log(`     Blocked private networks: ${netSummary.blockedPrivateNetworks}`);
					}

					// Run --secrets self-test if requested
					if (options.secrets) {
						console.log("\n🔑 Secret Detection Self-Test");
						let passed = 0;
						let failed = 0;

						for (const testCase of SECRET_TEST_CASES) {
							const result = filterOutput(testCase.input);
							const wasRedacted = result.blocked;

							if (wasRedacted === testCase.shouldRedact) {
								console.log(`   ✓ ${testCase.name}: ${wasRedacted ? "redacted" : "allowed"}`);
								passed++;
							} else {
								console.log(
									`   ✗ ${testCase.name}: expected ${testCase.shouldRedact ? "redact" : "allow"}, got ${wasRedacted ? "redact" : "allow"}`,
								);
								failed++;
							}
						}

						console.log(
							`\n   Result: ${failed === 0 ? "✓" : "✗"} ${passed}/${passed + failed} tests passed`,
						);
						if (failed > 0) {
							process.exitCode = 1;
						}

						// Show redaction example
						console.log("\n   Redaction Example:");
						const exampleInput = "API key: ghp_abc123def456ghi789jkl012mno345pqr678";
						const exampleOutput = redactSecrets(exampleInput);
						console.log(`     Input:  "${exampleInput}"`);
						console.log(`     Output: "${exampleOutput}"`);
					}

					// Run --skills scanner if requested
					if (options.skills) {
						console.log("\n🔍 Skill Static Code Scanner");
						const cwd = process.cwd();
						const skillRoots = [
							path.join(cwd, ".claude", "skills"),
							path.join(cwd, ".claude", "skills-draft"),
						];
						// Also check CLAUDE_CONFIG_DIR skills (Docker profiles)
						const configDir = process.env.CLAUDE_CONFIG_DIR;
						if (configDir) {
							skillRoots.push(path.join(configDir, "skills"));
						}

						let totalResults: Awaited<ReturnType<typeof scanAllSkills>> = [];
						for (const root of skillRoots) {
							if (fs.existsSync(root)) {
								console.log(`\n   Scanning: ${root}`);
								const results = scanAllSkills(root);
								totalResults = totalResults.concat(results);
							}
						}

						if (totalResults.length === 0) {
							console.log("   No skills found to scan.");
						} else {
							console.log(formatScanResults(totalResults));
							const blockedCount = totalResults.filter((r) => r.blocked).length;
							if (blockedCount > 0) {
								process.exitCode = 1;
							}
						}
					}

					// Run --security audit if requested
					if (options.security) {
						console.log("\n\uD83D\uDD10 Security Audit (Deep Collectors)");
						const auditReport = runAuditCollectors(cfg, process.cwd());
						console.log(formatAuditReport(auditReport));
						if (auditReport.summary.critical > 0) {
							process.exitCode = 1;
						}

						// Auto-fix if --fix is passed
						if (options.fix) {
							console.log("\n\uD83D\uDD27 Auto-Remediation (--fix)");
							const configPath = resolveConfigPath();
							const fixReport = runAutoFix(cfg, configPath, process.cwd());
							console.log(formatFixReport(fixReport));
							if (fixReport.summary.errors > 0) {
								process.exitCode = 1;
							}
						}
					}

					// Warn if --fix is passed without --security
					if (options.fix && !options.security) {
						console.log("\n--fix requires --security. Run: telclaude doctor --security --fix");
					}

					// Show hint for tests if not running them
					if (!options.network && !options.secrets && !options.skills && !options.security) {
						console.log("\nRun `telclaude doctor --network` for network isolation self-test.");
						console.log("Run `telclaude doctor --secrets` for secret detection self-test.");
						console.log("Run `telclaude doctor --skills` for skill static code scanner.");
						console.log("Run `telclaude doctor --security` for comprehensive security audit.");
					}
				} catch (err) {
					logger.error({ error: String(err) }, "doctor command failed");
					console.error(`Error: ${err}`);
					process.exit(1);
				}
			},
		);
}
