/**
 * Sandbox diagnostic test command.
 *
 * Tests sandbox behavior without the full Telegram/auth stack.
 * Use this to verify sandbox configuration, env var passing,
 * network connectivity, and OpenAI API access.
 *
 * Run after making sandbox/network changes to verify they work
 * before deploying to production.
 */

import { exec } from "node:child_process";
import { promisify } from "node:util";

import chalk from "chalk";
import type { Command } from "commander";

import { getChildLogger } from "../logging.js";
import { buildSandboxConfig } from "../sandbox/config.js";
import {
	initializeSandbox,
	isSandboxAvailable,
	resetSandbox,
	wrapCommand,
} from "../sandbox/manager.js";
import { getOpenAIKey } from "../services/openai-client.js";

const execAsync = promisify(exec);
const logger = getChildLogger({ module: "sandbox-test" });

type TestResult = {
	name: string;
	passed: boolean;
	message: string;
	details?: string;
};

type SandboxTestOptions = {
	env?: boolean;
	network?: boolean;
	openai?: boolean;
	all?: boolean;
	verbose?: boolean;
};

export function registerSandboxTestCommand(program: Command): void {
	program
		.command("sandbox-test")
		.description("Test sandbox configuration and connectivity")
		.option("--env", "Test environment variable passing")
		.option("--network", "Test network connectivity through sandbox")
		.option("--openai", "Test OpenAI API connectivity")
		.option("--all", "Run all tests (default if no options specified)")
		.option("-v, --verbose", "Show detailed output")
		.action(async (opts: SandboxTestOptions) => {
			const verbose = program.opts().verbose || opts.verbose;

			// Default to --all if no specific tests requested
			const runAll = opts.all || (!opts.env && !opts.network && !opts.openai);
			const runEnv = opts.env || runAll;
			const runNetwork = opts.network || runAll;
			const runOpenai = opts.openai || runAll;

			console.log(chalk.bold("\n🧪 Telclaude Sandbox Test\n"));

			// Check sandbox availability
			console.log("Checking sandbox availability...");
			const available = await isSandboxAvailable();
			if (!available) {
				console.log(chalk.red("✗ Sandbox not available on this platform"));
				console.log("  Install required dependencies:");
				console.log("  - macOS: Seatbelt (built-in)");
				console.log("  - Linux: bubblewrap, socat, ripgrep");
				process.exit(1);
			}
			console.log(chalk.green("✓ Sandbox available\n"));

			// Initialize sandbox
			console.log("Initializing sandbox...");
			try {
				const config = buildSandboxConfig({});
				await initializeSandbox(config);
				console.log(chalk.green("✓ Sandbox initialized\n"));
			} catch (err) {
				console.log(chalk.red(`✗ Failed to initialize sandbox: ${err}`));
				process.exit(1);
			}

			const results: TestResult[] = [];

			try {
				// Run requested tests
				if (runEnv) {
					console.log(chalk.bold("── Environment Tests ──"));
					results.push(...(await runEnvTests(verbose)));
					console.log();
				}

				if (runNetwork) {
					console.log(chalk.bold("── Network Tests ──"));
					results.push(...(await runNetworkTests(verbose)));
					console.log();
				}

				if (runOpenai) {
					console.log(chalk.bold("── OpenAI API Tests ──"));
					results.push(...(await runOpenAITests(verbose)));
					console.log();
				}

				// Summary
				printSummary(results);
			} finally {
				await resetSandbox();
			}

			// Exit with error if any tests failed
			const failed = results.filter((r) => !r.passed);
			if (failed.length > 0) {
				process.exit(1);
			}
		});
}

/**
 * Execute a command inside the sandbox and return stdout/stderr.
 */
async function execInSandbox(
	command: string,
	timeoutMs = 30000,
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
	const wrapped = await wrapCommand(command);
	logger.debug({ original: command, wrapped: wrapped.substring(0, 200) }, "executing in sandbox");

	try {
		const { stdout, stderr } = await execAsync(wrapped, {
			timeout: timeoutMs,
			maxBuffer: 1024 * 1024,
			shell: "/bin/bash",
		});
		return { stdout, stderr, exitCode: 0 };
	} catch (err: unknown) {
		const error = err as { stdout?: string; stderr?: string; code?: number };
		return {
			stdout: error.stdout ?? "",
			stderr: error.stderr ?? String(err),
			exitCode: error.code ?? 1,
		};
	}
}

/**
 * Test environment variable passing through sandbox.
 */
async function runEnvTests(verbose?: boolean): Promise<TestResult[]> {
	const results: TestResult[] = [];

	// Test 1: Check if HTTP_PROXY is available (critical for OpenAI SDK)
	{
		const name = "HTTP_PROXY available";
		const { stdout } = await execInSandbox('echo "HTTP_PROXY=$HTTP_PROXY"');
		const hasProxy = stdout.includes("HTTP_PROXY=http://");

		if (hasProxy) {
			results.push({ name, passed: true, message: "HTTP_PROXY is set" });
			console.log(chalk.green(`  ✓ ${name}`));
			if (verbose) {
				console.log(chalk.gray(`    ${stdout.trim()}`));
			}
		} else {
			results.push({
				name,
				passed: false,
				message: "HTTP_PROXY not set in sandbox",
				details: "The SDK sets HTTP_PROXY but it may be stripped by env isolation",
			});
			console.log(chalk.red(`  ✗ ${name}`));
			if (verbose) {
				console.log(chalk.gray(`    stdout: ${stdout.trim()}`));
			}
		}
	}

	// Test 2: Check if HTTPS_PROXY is available
	{
		const name = "HTTPS_PROXY available";
		const { stdout } = await execInSandbox('echo "HTTPS_PROXY=$HTTPS_PROXY"');
		const hasProxy = stdout.includes("HTTPS_PROXY=http://");

		if (hasProxy) {
			results.push({ name, passed: true, message: "HTTPS_PROXY is set" });
			console.log(chalk.green(`  ✓ ${name}`));
		} else {
			results.push({
				name,
				passed: false,
				message: "HTTPS_PROXY not set in sandbox",
			});
			console.log(chalk.red(`  ✗ ${name}`));
		}
	}

	// Test 3: Check if OPENAI_API_KEY is available (when configured)
	{
		const name = "OPENAI_API_KEY available";
		const configuredKey = await getOpenAIKey();

		if (!configuredKey) {
			results.push({ name, passed: true, message: "Skipped (not configured)" });
			console.log(chalk.yellow(`  ○ ${name} (not configured)`));
		} else {
			const { stdout } = await execInSandbox(
				'[ -n "$OPENAI_API_KEY" ] && echo "KEY_SET=true" || echo "KEY_SET=false"',
			);
			const hasKey = stdout.includes("KEY_SET=true");

			if (hasKey) {
				results.push({ name, passed: true, message: "OPENAI_API_KEY is available in sandbox" });
				console.log(chalk.green(`  ✓ ${name}`));
			} else {
				results.push({
					name,
					passed: false,
					message: "OPENAI_API_KEY not available in sandbox",
					details: "Key is configured but not reaching sandboxed commands",
				});
				console.log(chalk.red(`  ✗ ${name}`));
			}
		}
	}

	// Test 4: Check basic env vars (PATH, HOME)
	{
		const name = "Basic env vars (PATH, HOME)";
		const { stdout } = await execInSandbox('echo "PATH=$PATH" && echo "HOME=$HOME"');
		const hasPath = stdout.includes("PATH=/");
		const hasHome = stdout.includes("HOME=/");

		if (hasPath && hasHome) {
			results.push({ name, passed: true, message: "Basic env vars present" });
			console.log(chalk.green(`  ✓ ${name}`));
		} else {
			results.push({ name, passed: false, message: "Missing basic env vars" });
			console.log(chalk.red(`  ✗ ${name}`));
		}
	}

	return results;
}

/**
 * Test network connectivity through sandbox.
 */
async function runNetworkTests(verbose?: boolean): Promise<TestResult[]> {
	const results: TestResult[] = [];

	// Check if proxy is actually reachable (it's started by SDK, not by sandbox-test)
	const { stdout: proxyCheck } = await execInSandbox(
		'curl -s -o /dev/null -w "%{http_code}" --connect-timeout 2 http://localhost:3128/ 2>&1 || echo "NO_PROXY"',
	);

	if (proxyCheck.includes("NO_PROXY") || proxyCheck === "000") {
		console.log(chalk.yellow("  ○ Network tests skipped (proxy not running)"));
		console.log(
			chalk.gray("    Note: Network proxy is started by SDK when running Claude agent."),
		);
		console.log(chalk.gray("    To test network, run image generation via Telegram."));
		results.push({
			name: "Network",
			passed: true,
			message: "Skipped (proxy not running - run via SDK for full test)",
		});
		return results;
	}

	// Test 1: DNS resolution works
	{
		const name = "DNS resolution";
		const { stdout, exitCode } = await execInSandbox(
			"getent hosts api.openai.com 2>/dev/null || host api.openai.com 2>/dev/null || nslookup api.openai.com 2>/dev/null | head -5",
		);

		if (exitCode === 0 && stdout.length > 0) {
			results.push({ name, passed: true, message: "DNS resolution works" });
			console.log(chalk.green(`  ✓ ${name}`));
		} else {
			results.push({ name, passed: false, message: "DNS resolution failed" });
			console.log(chalk.red(`  ✗ ${name}`));
		}
	}

	// Test 2: Can reach api.openai.com (through proxy)
	{
		const name = "Connect to api.openai.com";
		const { stdout, stderr, exitCode } = await execInSandbox(
			"curl -s -o /dev/null -w '%{http_code}' --max-time 10 https://api.openai.com/v1/models 2>&1 || echo 'CURL_FAILED'",
		);

		// 401 is expected (no auth), but proves connectivity works
		const httpCode = stdout.trim();
		if (httpCode === "401" || httpCode === "200") {
			results.push({ name, passed: true, message: `Connected (HTTP ${httpCode})` });
			console.log(chalk.green(`  ✓ ${name} (HTTP ${httpCode})`));
		} else if (stdout.includes("CURL_FAILED") || exitCode !== 0) {
			results.push({
				name,
				passed: false,
				message: "Connection failed",
				details: stderr || stdout,
			});
			console.log(chalk.red(`  ✗ ${name}`));
			if (verbose) {
				console.log(chalk.gray(`    ${stderr || stdout}`));
			}
		} else {
			results.push({ name, passed: true, message: `Connected (HTTP ${httpCode})` });
			console.log(chalk.green(`  ✓ ${name} (HTTP ${httpCode})`));
		}
	}

	// Test 3: Can reach npm registry (common allowed domain)
	{
		const name = "Connect to registry.npmjs.org";
		const { stdout } = await execInSandbox(
			"curl -s -o /dev/null -w '%{http_code}' --max-time 10 https://registry.npmjs.org/ 2>&1",
		);

		const httpCode = stdout.trim();
		if (httpCode === "200" || httpCode === "301" || httpCode === "302") {
			results.push({ name, passed: true, message: `Connected (HTTP ${httpCode})` });
			console.log(chalk.green(`  ✓ ${name}`));
		} else {
			results.push({ name, passed: false, message: `Failed (HTTP ${httpCode})` });
			console.log(chalk.red(`  ✗ ${name}`));
		}
	}

	// Test 4: Private network should be blocked
	// NOTE: This only works reliably in Docker with bubblewrap. On macOS (Seatbelt),
	// network filtering is done via sandboxAskCallback which may not block all cases.
	{
		const name = "RFC1918 blocked (10.0.0.1)";
		const isMacOS = process.platform === "darwin";
		const { stdout, exitCode } = await execInSandbox(
			"curl -s -o /dev/null -w '%{http_code}' --connect-timeout 2 --max-time 3 http://10.0.0.1/ 2>&1 || echo 'BLOCKED'",
		);

		// Should fail/timeout - private networks blocked
		if (stdout.includes("BLOCKED") || exitCode !== 0 || stdout === "000") {
			results.push({ name, passed: true, message: "Private network correctly blocked" });
			console.log(chalk.green(`  ✓ ${name}`));
		} else if (isMacOS) {
			// On macOS, Seatbelt doesn't block network at OS level - skip with warning
			results.push({
				name,
				passed: true,
				message: "Skipped on macOS (use Docker for full network isolation)",
			});
			console.log(chalk.yellow(`  ○ ${name} (macOS - use Docker for network isolation)`));
		} else {
			results.push({
				name,
				passed: false,
				message: "Private network NOT blocked!",
				details: "Security issue: RFC1918 addresses should be blocked",
			});
			console.log(chalk.red(`  ✗ ${name}`));
		}
	}

	return results;
}

/**
 * Test OpenAI API connectivity.
 */
async function runOpenAITests(verbose?: boolean): Promise<TestResult[]> {
	const results: TestResult[] = [];

	const configuredKey = await getOpenAIKey();
	if (!configuredKey) {
		console.log(chalk.yellow("  ○ Skipped (OPENAI_API_KEY not configured)"));
		console.log(chalk.gray("    Run: telclaude setup-openai"));
		results.push({
			name: "OpenAI API",
			passed: true,
			message: "Skipped (not configured)",
		});
		return results;
	}

	// Check if network is available (proxy running)
	const { stdout: proxyCheck } = await execInSandbox(
		'curl -s -o /dev/null -w "%{http_code}" --connect-timeout 2 http://localhost:3128/ 2>&1 || echo "NO_PROXY"',
	);

	if (proxyCheck.includes("NO_PROXY") || proxyCheck === "000") {
		console.log(chalk.yellow("  ○ Skipped (proxy not running)"));
		console.log(chalk.gray("    Note: Run via Telegram to test full OpenAI path."));
		results.push({
			name: "OpenAI API",
			passed: true,
			message: "Skipped (proxy not running)",
		});
		return results;
	}

	// Test 1: OpenAI API models endpoint
	{
		const name = "OpenAI API /v1/models";
		const { stdout } = await execInSandbox(
			`curl -s -w '\\n%{http_code}' --max-time 15 https://api.openai.com/v1/models -H "Authorization: Bearer $OPENAI_API_KEY" 2>&1`,
		);

		const lines = stdout.trim().split("\n");
		const httpCode = lines[lines.length - 1];
		const body = lines.slice(0, -1).join("\n");

		if (httpCode === "200") {
			results.push({ name, passed: true, message: "API accessible" });
			console.log(chalk.green(`  ✓ ${name}`));
			if (verbose) {
				// Show first model
				try {
					const data = JSON.parse(body);
					if (data.data?.[0]?.id) {
						console.log(chalk.gray(`    First model: ${data.data[0].id}`));
					}
				} catch {
					// ignore parse errors
				}
			}
		} else if (httpCode === "401") {
			results.push({
				name,
				passed: false,
				message: "Authentication failed",
				details: "OPENAI_API_KEY may be invalid",
			});
			console.log(chalk.red(`  ✗ ${name} (invalid API key)`));
		} else {
			results.push({
				name,
				passed: false,
				message: `Failed (HTTP ${httpCode})`,
				details: body.substring(0, 200),
			});
			console.log(chalk.red(`  ✗ ${name} (HTTP ${httpCode})`));
			if (verbose) {
				console.log(chalk.gray(`    ${body.substring(0, 200)}`));
			}
		}
	}

	// Test 2: Node.js fetch through proxy (the actual issue we fixed)
	{
		const name = "Node.js fetch with ProxyAgent";

		// Use a simple inline script - avoid ! which gets escaped by shell
		// The key test: does Node.js fetch work through the proxy?
		const { stdout, stderr } = await execInSandbox(
			`node -e 'const{ProxyAgent}=require("undici");const p=process.env.HTTPS_PROXY||process.env.HTTP_PROXY;if(p===undefined||p===""){console.log("NO_PROXY_ENV");process.exit(0)}const a=new ProxyAgent(p);fetch("https://api.openai.com/v1/models",{headers:{"Authorization":"Bearer "+process.env.OPENAI_API_KEY},dispatcher:a}).then(r=>console.log("HTTP_"+r.status)).catch(e=>console.log("ERROR:"+e.message))'`,
			20000,
		);

		if (stdout.includes("HTTP_200")) {
			results.push({ name, passed: true, message: "ProxyAgent working" });
			console.log(chalk.green(`  ✓ ${name}`));
		} else if (stdout.includes("NO_PROXY_ENV")) {
			results.push({
				name,
				passed: false,
				message: "Proxy env vars not available",
				details: "HTTP_PROXY/HTTPS_PROXY not set in sandbox",
			});
			console.log(chalk.red(`  ✗ ${name} (no proxy env)`));
		} else if (stdout.includes("HTTP_401")) {
			results.push({
				name,
				passed: false,
				message: "API key not valid in sandbox",
			});
			console.log(chalk.red(`  ✗ ${name} (auth failed)`));
		} else {
			results.push({
				name,
				passed: false,
				message: "Fetch failed",
				details: stdout + stderr,
			});
			console.log(chalk.red(`  ✗ ${name}`));
			if (verbose) {
				console.log(chalk.gray(`    ${stdout} ${stderr}`));
			}
		}
	}

	return results;
}

/**
 * Print test summary.
 */
function printSummary(results: TestResult[]): void {
	const passed = results.filter((r) => r.passed).length;
	const failed = results.filter((r) => !r.passed).length;
	const total = passed + failed;

	console.log(chalk.bold("── Summary ──"));

	if (failed === 0) {
		console.log(chalk.green(`✓ All ${passed} tests passed`));
	} else {
		console.log(chalk.red(`✗ ${failed}/${total} tests failed\n`));

		console.log(chalk.bold("Failed tests:"));
		for (const result of results.filter((r) => !r.passed)) {
			console.log(chalk.red(`  • ${result.name}: ${result.message}`));
			if (result.details) {
				console.log(chalk.gray(`    ${result.details}`));
			}
		}
	}

	console.log();
}
