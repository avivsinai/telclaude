import fs from "node:fs";
import type { Command } from "commander";
import { loadConfig } from "../config/config.js";
import { resolveConfigPath } from "../config/path.js";
import { getChildLogger } from "../logging.js";
import {
	buildAllowedDomainNames,
	buildAllowedDomains,
	DEFAULT_NETWORK_CONFIG,
	getNetworkIsolationSummary,
	runNetworkSelfTest,
} from "../sandbox/index.js";
import { CORE_SECRET_PATTERNS, filterOutput, redactSecrets } from "../security/index.js";
import { formatScanResults, scanAllSkills } from "../security/skill-scanner.js";
import { formatAuditReport, runAuditCollectors } from "./audit-collectors.js";
import { formatFixReport, runAutoFix } from "./audit-fixers.js";
import {
	buildReport,
	type CheckResult,
	type CheckStatus,
	checkClaudeCli,
	checkClaudeLogin,
	checkConfigLoaded,
	checkDockerContainers,
	checkNetworkConfig,
	checkProviders,
	checkSandbox,
	checkSkills,
	checkTelegramToken,
	checkTotpDaemon,
	checkVaultDaemon,
	type DoctorReport,
	worstStatus,
} from "./doctor-helpers.js";
import { getAllDraftSkillRoots, getAllSkillRoots } from "./skill-path.js";

const logger = getChildLogger({ module: "cmd-doctor" });

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

// ─────────────────────────────────────────────────────────────────────────────
// Structured doctor run — used by both the default CLI output and `--json`
// ─────────────────────────────────────────────────────────────────────────────

export async function runDoctor(cwd: string = process.cwd()): Promise<DoctorReport> {
	const checks: CheckResult[] = [];

	// Config is foundational — load it first so later checks can see it.
	let cfg: ReturnType<typeof loadConfig>;
	try {
		cfg = loadConfig();
	} catch (err) {
		checks.push({
			name: "config.loaded",
			category: "Config",
			status: "fail",
			summary: "config failed to parse",
			detail: err instanceof Error ? err.message : String(err),
			remediation: "telclaude onboard",
		});
		return buildReport(checks);
	}

	checks.push(...checkConfigLoaded(cfg));
	checks.push(checkClaudeCli());
	checks.push(checkClaudeLogin());
	checks.push(await checkTelegramToken(cfg));
	checks.push(await checkVaultDaemon());
	checks.push(await checkTotpDaemon());
	checks.push(...checkNetworkConfig(cfg));
	checks.push(...(await checkProviders(cfg)));
	checks.push(...(await checkSkills(cwd)));
	checks.push(...(await checkSandbox()));
	checks.push(...(await checkDockerContainers()));

	return buildReport(checks);
}

// ─────────────────────────────────────────────────────────────────────────────
// Pretty-printing
// ─────────────────────────────────────────────────────────────────────────────

const STATUS_ICON: Record<CheckStatus, string> = {
	pass: "\u2713",
	warn: "\u26A0\uFE0F ",
	fail: "\u2717",
	skip: "\u2022",
};

function printReport(report: DoctorReport): void {
	const byCategory = new Map<string, CheckResult[]>();
	for (const check of report.checks) {
		const list = byCategory.get(check.category) ?? [];
		list.push(check);
		byCategory.set(check.category, list);
	}

	console.log("=== telclaude doctor ===\n");
	for (const [category, checks] of byCategory) {
		console.log(category);
		for (const check of checks) {
			console.log(`  ${STATUS_ICON[check.status]} ${check.summary}`);
			if (check.detail) {
				for (const line of check.detail.split("\n")) {
					console.log(`      ${line}`);
				}
			}
			if (check.remediation) {
				console.log(`      try: ${check.remediation}`);
			}
		}
		console.log("");
	}

	const { pass: p, warn: w, fail: f, skip: s } = report.summary;
	const worst = worstStatus(report.checks);
	const tag =
		worst === "fail" ? "FAIL" : worst === "warn" ? "WARN" : worst === "skip" ? "SKIP" : "PASS";
	console.log(`Summary: ${tag} — pass=${p} warn=${w} fail=${f} skip=${s}`);
}

function exitCodeFromReport(report: DoctorReport): number {
	const worst = worstStatus(report.checks);
	if (worst === "fail") return 1;
	// Warnings alone don't fail CI; callers can still see them in --json
	return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Command registration
// ─────────────────────────────────────────────────────────────────────────────

export function registerDoctorCommand(program: Command): void {
	program
		.command("doctor")
		.description(
			"Full health check across config, Telegram, vault, TOTP, providers, skills, sandbox, and Docker",
		)
		.option("--json", "Emit structured JSON report (for CI consumption)")
		.option("--network", "Additionally run the network isolation self-test")
		.option("--secrets", "Additionally run the secret detection self-test")
		.option("--skills", "Additionally dump the full skill scanner report")
		.option("--security", "Additionally run the deep security audit")
		.option("--fix", "Auto-fix safe security issues (requires --security)")
		.action(
			async (options: {
				json?: boolean;
				network?: boolean;
				secrets?: boolean;
				skills?: boolean;
				security?: boolean;
				fix?: boolean;
			}) => {
				try {
					const report = await runDoctor();

					if (options.json) {
						// JSON mode: structured output only. Extra flags still
						// run the verbose dumps but go to stderr so `--json`
						// stdout stays clean.
						process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
						if (options.network) runNetworkDump(process.stderr);
						if (options.secrets) runSecretsDump(process.stderr);
						if (options.skills) runSkillsDump(process.stderr);
						if (options.security) runSecurityDump(process.stderr, options.fix);
						process.exit(exitCodeFromReport(report));
					}

					printReport(report);

					if (options.network) runNetworkDump(process.stdout);
					if (options.secrets) runSecretsDump(process.stdout);
					if (options.skills) runSkillsDump(process.stdout);
					if (options.security) runSecurityDump(process.stdout, options.fix);

					if (options.fix && !options.security) {
						console.log("\n--fix requires --security. Run: telclaude dev doctor --security --fix");
					}

					if (!options.network && !options.secrets && !options.skills && !options.security) {
						console.log("\nTip: use `telclaude dev doctor --json` for machine-readable output,");
						console.log(
							"     or add --network / --secrets / --skills / --security for verbose dumps.",
						);
					}

					process.exitCode = exitCodeFromReport(report);
				} catch (err) {
					logger.error({ error: String(err) }, "doctor command failed");
					console.error(`Error: ${err}`);
					process.exit(1);
				}
			},
		);
}

// ─────────────────────────────────────────────────────────────────────────────
// Legacy verbose dumps (preserved behind feature flags for back-compat)
// ─────────────────────────────────────────────────────────────────────────────

function runNetworkDump(stream: NodeJS.WriteStream): void {
	const cfg = loadConfig();
	const additionalDomains = cfg.security?.network?.additionalDomains ?? [];
	const allowedDomainNames = buildAllowedDomainNames(additionalDomains);
	const allowedDomains = buildAllowedDomains(additionalDomains);

	stream.write("\n\u{1F310} Network Isolation Self-Test\n");
	const netResult = runNetworkSelfTest({
		...DEFAULT_NETWORK_CONFIG,
		allowedDomains,
	});
	for (const test of netResult.tests) {
		stream.write(`   ${test.passed ? "\u2713" : "\u2717"} ${test.name}: ${test.details ?? ""}\n`);
	}
	stream.write(
		`\n   Result: ${netResult.passed ? "\u2713 All tests passed" : "\u2717 Some tests failed"}\n`,
	);
	if (!netResult.passed) {
		process.exitCode = 1;
	}

	const netSummary = getNetworkIsolationSummary(
		{ ...DEFAULT_NETWORK_CONFIG, allowedDomains },
		allowedDomainNames,
	);
	stream.write("\n   Network Summary:\n");
	stream.write(`     Allowed domains: ${netSummary.allowedDomains}\n`);
	if (netSummary.domainsWithPost.length > 0) {
		stream.write(`     \u26A0\uFE0F  POST enabled for: ${netSummary.domainsWithPost.join(", ")}\n`);
	}
	stream.write(`     Blocked metadata endpoints: ${netSummary.blockedMetadataEndpoints}\n`);
	stream.write(`     Blocked private networks: ${netSummary.blockedPrivateNetworks}\n`);
	stream.write(`     CORE secret patterns: ${CORE_SECRET_PATTERNS.length}\n`);
}

function runSecretsDump(stream: NodeJS.WriteStream): void {
	stream.write("\n\u{1F510} Secret Detection Self-Test\n");
	let passed = 0;
	let failed = 0;

	for (const testCase of SECRET_TEST_CASES) {
		const result = filterOutput(testCase.input);
		const wasRedacted = result.blocked;
		if (wasRedacted === testCase.shouldRedact) {
			stream.write(`   \u2713 ${testCase.name}: ${wasRedacted ? "redacted" : "allowed"}\n`);
			passed++;
		} else {
			stream.write(
				`   \u2717 ${testCase.name}: expected ${testCase.shouldRedact ? "redact" : "allow"}, got ${wasRedacted ? "redact" : "allow"}\n`,
			);
			failed++;
		}
	}

	stream.write(
		`\n   Result: ${failed === 0 ? "\u2713" : "\u2717"} ${passed}/${passed + failed} tests passed\n`,
	);
	if (failed > 0) {
		process.exitCode = 1;
	}

	stream.write("\n   Redaction Example:\n");
	const exampleInput = "API key: ghp_abc123def456ghi789jkl012mno345pqr678";
	const exampleOutput = redactSecrets(exampleInput);
	stream.write(`     Input:  "${exampleInput}"\n`);
	stream.write(`     Output: "${exampleOutput}"\n`);
}

function runSkillsDump(stream: NodeJS.WriteStream): void {
	stream.write("\n\u{1F50D} Skill Static Code Scanner\n");
	const roots = [...getAllSkillRoots(), ...getAllDraftSkillRoots()];

	let totalResults: ReturnType<typeof scanAllSkills> = [];
	for (const root of roots) {
		if (fs.existsSync(root)) {
			stream.write(`\n   Scanning: ${root}\n`);
			totalResults = totalResults.concat(scanAllSkills(root));
		}
	}

	if (totalResults.length === 0) {
		stream.write("   No skills found to scan.\n");
	} else {
		stream.write(`${formatScanResults(totalResults)}\n`);
		const blockedCount = totalResults.filter((r) => r.blocked).length;
		if (blockedCount > 0) {
			process.exitCode = 1;
		}
	}
}

function runSecurityDump(stream: NodeJS.WriteStream, fix?: boolean): void {
	const cfg = loadConfig();
	stream.write("\n\u{1F510} Security Audit (Deep Collectors)\n");
	const auditReport = runAuditCollectors(cfg, process.cwd());
	stream.write(`${formatAuditReport(auditReport)}\n`);
	if (auditReport.summary.critical > 0) {
		process.exitCode = 1;
	}

	if (fix) {
		stream.write("\n\u{1F527} Auto-Remediation (--fix)\n");
		const configPath = resolveConfigPath();
		const fixReport = runAutoFix(cfg, configPath, process.cwd());
		stream.write(`${formatFixReport(fixReport)}\n`);
		if (fixReport.summary.errors > 0) {
			process.exitCode = 1;
		}
	}
}
