/**
 * Integration test command for testing the full SDK path.
 *
 * This command runs queries through the actual Claude SDK inside the supported
 * Docker runtime, testing:
 * - Agent/relay SDK execution
 * - Docker runtime wiring
 * - Skill execution (image-generator, etc.)
 *
 * This allows testing without Telegram/auth overhead.
 */

import fs from "node:fs";
import path from "node:path";

import chalk from "chalk";
import type { Command } from "commander";
import { executeRemoteQuery } from "../agent/client.js";
import type { PermissionTier } from "../config/config.js";
import { getMediaOutboxDirSync } from "../media/store.js";
import { assertDockerRuntime } from "../sandbox/index.js";
import { executeQueryStream } from "../sdk/client.js";
import { getOpenAIKey } from "../services/openai-client.js";

type IntegrationTestOptions = {
	image?: boolean;
	echo?: boolean;
	env?: boolean;
	network?: boolean;
	voice?: boolean;
	agents?: boolean;
	all?: boolean;
	verbose?: boolean;
	timeout?: string;
};

const LOCAL_INTEGRATION_CWD = "/tmp/telclaude-integration";
let integrationQueryCounter = 0;

export function registerIntegrationTestCommand(program: Command): void {
	program
		.command("integration-test")
		.description("Test the supported Docker SDK path (agent, relay, and skills)")
		.option("--image", "Test image generation through SDK")
		.option("--echo", "Test simple echo command through SDK")
		.option("--env", "Test Docker runtime env contract through SDK")
		.option("--network", "Test Docker runtime wiring through SDK")
		.option("--voice", "Test voice message response (TTS skill)")
		.option("--agents", "Test direct agent transport (real agent, no Telegram)")
		.option("--all", "Run all integration tests")
		.option("-v, --verbose", "Show detailed output")
		.option("--timeout <ms>", "Query timeout in ms", "120000")
		.action(async (opts: IntegrationTestOptions) => {
			assertDockerRuntime("telclaude integration-test");

			const verbose = program.opts().verbose || opts.verbose;
			const timeoutMs = Number.parseInt(opts.timeout ?? "120000", 10);

			const runAll =
				opts.all ||
				(!opts.image && !opts.echo && !opts.env && !opts.network && !opts.voice && !opts.agents);
			const runImage = opts.image || runAll;
			const runEcho = opts.echo || runAll;
			const runEnv = opts.env || runAll;
			const runNetwork = opts.network || runAll;
			const runVoice = opts.voice || runAll;
			const runAgents = opts.agents || runAll;

			console.log(chalk.bold("\n🔬 Telclaude Integration Test\n"));
			console.log("This tests the full SDK path (not just sandbox config).\n");

			const results: { name: string; passed: boolean; message: string; duration?: number }[] = [];

			if (runEcho) {
				console.log(chalk.bold("── Echo Test ──"));
				const result = await testEcho(verbose, timeoutMs);
				results.push(result);
				console.log();
			}

			if (runEnv) {
				console.log(chalk.bold("── Environment Test ──"));
				const hasKey = await getOpenAIKey();
				const result = await testEnvPassing(verbose, timeoutMs, hasKey !== null);
				results.push(result);
				console.log();
			}

			if (runNetwork) {
				console.log(chalk.bold("── Runtime Wiring Test ──"));
				const result = await testNetworkProxy(verbose, timeoutMs);
				results.push(result);
				console.log();
			}

			if (runImage) {
				console.log(chalk.bold("── Image Generation Test ──"));
				const hasKey = await getOpenAIKey();
				if (!hasKey) {
					console.log(chalk.yellow("  ○ Skipped (OpenAI/image generation not configured)"));
					results.push({
						name: "Image generation",
						passed: true,
						message: "Skipped (image generation not configured)",
					});
				} else {
					if (verbose) {
						console.log(
							chalk.gray("  Note: Testing the supported telclaude image-generation path..."),
						);
					}
					const result = await testImageGeneration(verbose, timeoutMs);
					results.push(result);
				}
				console.log();
			}

			if (runVoice) {
				console.log(chalk.bold("── Voice Message Response Test ──"));
				const hasKey = await getOpenAIKey();
				if (!hasKey) {
					console.log(chalk.yellow("  ○ Skipped (OpenAI/TTS not configured)"));
					results.push({
						name: "Voice message response",
						passed: true,
						message: "Skipped (TTS not configured)",
					});
				} else {
					const result = await testVoiceMessageResponse(verbose, timeoutMs);
					results.push(result);
				}
				console.log();
			}

			if (runAgents) {
				console.log(chalk.bold("── Agent Transport Test (No Telegram) ──"));
				const agentUrl = process.env.TELCLAUDE_AGENT_URL;
				if (!agentUrl) {
					console.log(chalk.yellow("  ○ Skipped (TELCLAUDE_AGENT_URL not configured)"));
					results.push({
						name: "Agent transport (no Telegram)",
						passed: true,
						message: "Skipped (TELCLAUDE_AGENT_URL not configured)",
					});
				} else {
					const result = await testAgentTransport(verbose, timeoutMs, agentUrl);
					results.push(result);
				}
				console.log();
			}

			// Summary
			const passed = results.filter((r) => r.passed).length;
			const failed = results.filter((r) => !r.passed).length;

			console.log(chalk.bold("── Summary ──"));
			if (failed === 0) {
				console.log(chalk.green(`✓ All ${passed} tests passed`));
			} else {
				console.log(chalk.red(`✗ ${failed}/${passed + failed} tests failed\n`));
				for (const r of results.filter((r) => !r.passed)) {
					console.log(chalk.red(`  • ${r.name}: ${r.message}`));
				}
			}

			process.exit(failed > 0 ? 1 : 0);
		});
}

/**
 * Run a query through the SDK and collect results.
 */
async function runSdkQuery(
	prompt: string,
	opts: {
		enableSkills: boolean;
		timeoutMs: number;
		tier?: PermissionTier;
		onText?: (text: string) => void;
		onToolUse?: (name: string, input: unknown) => void;
	},
): Promise<{ output: string; success: boolean; error?: string }> {
	let output = "";
	let querySuccess = false;
	let error: string | undefined;
	const agentUrl = process.env.TELCLAUDE_AGENT_URL;

	const controller = new AbortController();
	const timeout = setTimeout(() => controller.abort(), opts.timeoutMs);

	try {
		fs.mkdirSync(LOCAL_INTEGRATION_CWD, { recursive: true });

		const stream = agentUrl
			? executeRemoteQuery(prompt, {
					agentUrl,
					scope: "telegram",
					cwd: ".",
					tier: opts.tier ?? "WRITE_LOCAL",
					poolKey: `integration-test:sdk:${++integrationQueryCounter}`,
					userId: "integration:sdk",
					enableSkills: opts.enableSkills,
					timeoutMs: opts.timeoutMs,
					abortController: controller,
				})
			: executeQueryStream(prompt, {
					tier: opts.tier ?? "WRITE_LOCAL",
					enableSkills: opts.enableSkills,
					permissionMode: "acceptEdits",
					cwd: LOCAL_INTEGRATION_CWD,
					abortController: controller,
				});

		for await (const chunk of stream) {
			if (controller.signal.aborted) {
				throw new Error("Query timed out");
			}

			if (chunk.type === "text") {
				output += chunk.content;
				opts.onText?.(chunk.content);
			} else if (chunk.type === "tool_use") {
				opts.onToolUse?.(chunk.toolName, chunk.input);
			} else if (chunk.type === "done") {
				querySuccess = chunk.result.success;
				error = chunk.result.error;
			}
		}
	} finally {
		clearTimeout(timeout);
	}

	return { output, success: querySuccess, error };
}

async function testAgentTransport(
	verbose: boolean,
	timeoutMs: number,
	agentUrl: string,
): Promise<{ name: string; passed: boolean; message: string; duration?: number }> {
	const name = "Agent transport (no Telegram)";
	console.log(`  Targeting: ${agentUrl}`);
	try {
		const startTime = Date.now();
		let response = "";
		let querySuccess = false;
		let queryError: string | undefined;
		const expected = "AGENT_TRANSPORT_OK";
		const stream = executeRemoteQuery(`Reply only with this exact text: ${expected}`, {
			agentUrl,
			scope: "telegram",
			cwd: ".",
			tier: "READ_ONLY",
			poolKey: "integration-test:agent",
			userId: "integration:agent",
			enableSkills: false,
			timeoutMs,
		});

		for await (const chunk of stream) {
			if (chunk.type === "text") {
				response += chunk.content;
				if (verbose) {
					process.stdout.write(chalk.gray(chunk.content));
				}
			} else if (chunk.type === "done") {
				querySuccess = chunk.result.success;
				queryError = chunk.result.error;
				if (chunk.result.response) {
					response = chunk.result.response;
				}
			}
		}

		const duration = Date.now() - startTime;
		const normalized = response.toUpperCase();
		const expectedNormalized = expected.toUpperCase();
		if (querySuccess && normalized.includes(expectedNormalized)) {
			console.log(chalk.green(`  ✓ ${name} (${duration}ms)`));
			return { name, passed: true, message: "OK", duration };
		}
		if (queryError) {
			console.log(chalk.red(`  ✗ ${name}: ${queryError}`));
			return { name, passed: false, message: queryError };
		}

		console.log(chalk.red(`  ✗ ${name}: expected ${expected} response`));
		if (verbose) {
			console.log(chalk.gray(`    Response: ${response.slice(0, 300)}`));
		}
		return { name, passed: false, message: `Unexpected output (expected ${expected})` };
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		console.log(chalk.red(`  ✗ ${name}: ${message}`));
		return { name, passed: false, message };
	}
}

function escapeRegExp(input: string): string {
	return input.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function normalizeSlashes(input: string): string {
	return input.replace(/\\/g, "/");
}

function getMediaRootsForTests(): string[] {
	const outboxRoot = getMediaOutboxDirSync();
	const legacyRoot = path.join(process.cwd(), ".telclaude-media");
	const roots = [outboxRoot, legacyRoot];
	return Array.from(new Set(roots.filter(Boolean)));
}

function buildMediaPattern(roots: string[], category: string, ext: string): RegExp {
	const rootPattern = roots
		.map((root) => escapeRegExp(normalizeSlashes(root)))
		.filter(Boolean)
		.join("|");
	return new RegExp(`(?:${rootPattern})[/\\\\]${category}[/\\\\][^\\s"']+\\.${ext}`, "i");
}

function extractMediaPath(text: string, pattern: RegExp): string | null {
	const match = text.match(pattern);
	if (!match) return null;
	return match[0].replace(/[.,!?;:'")\]]+$/, "");
}

/**
 * Test simple echo through SDK.
 * This verifies the SDK can run Bash commands in sandbox.
 */
async function testEcho(
	verbose: boolean,
	timeoutMs: number,
): Promise<{ name: string; passed: boolean; message: string; duration?: number }> {
	const name = "Echo via SDK";

	try {
		console.log("  Running echo test via SDK...");
		const startTime = Date.now();

		const { output, error } = await runSdkQuery(
			'Run this exact bash command and show me the output: echo "INTEGRATION_TEST_OK"',
			{
				enableSkills: false,
				timeoutMs,
				onText: (text) => {
					if (verbose) {
						process.stdout.write(chalk.gray(text));
					}
				},
			},
		);

		const duration = Date.now() - startTime;

		if (output.includes("INTEGRATION_TEST_OK")) {
			console.log(chalk.green(`  ✓ ${name} (${duration}ms)`));
			return { name, passed: true, message: "OK", duration };
		}
		if (error) {
			console.log(chalk.red(`  ✗ ${name}: ${error}`));
			return { name, passed: false, message: error };
		}
		console.log(chalk.red(`  ✗ ${name}: Marker not found in output`));
		if (verbose) {
			console.log(chalk.gray(`    Output: ${output.substring(0, 300)}`));
		}
		return { name, passed: false, message: "Unexpected output" };
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		console.log(chalk.red(`  ✗ ${name}: ${message}`));
		return { name, passed: false, message };
	}
}

/**
 * Test the supported Docker runtime env contract.
 * In the agent container we expect a writable cwd, HOME, proxy wiring, and no raw OpenAI key.
 */
async function testEnvPassing(
	verbose: boolean,
	timeoutMs: number,
	expectOpenAIKey: boolean,
): Promise<{ name: string; passed: boolean; message: string; duration?: number }> {
	const name = "Docker runtime env via SDK";
	const usesRemoteAgent = Boolean(process.env.TELCLAUDE_AGENT_URL);

	try {
		console.log("  Running environment variable test via SDK...");
		const startTime = Date.now();

		const { output, error } = await runSdkQuery(
			`Run these bash checks and report the exact markers you see:

pwd
test -w . && echo "CWD_WRITABLE" || echo "CWD_READONLY"
test -n "$HOME" && echo "HOME_SET" || echo "HOME_EMPTY"
test -n "$TELCLAUDE_CREDENTIAL_PROXY_URL" && echo "CRED_PROXY_SET" || echo "CRED_PROXY_EMPTY"
test -z "$OPENAI_API_KEY" && echo "RAW_OPENAI_KEY_ABSENT" || echo "RAW_OPENAI_KEY_PRESENT"`,
			{
				enableSkills: false,
				timeoutMs,
				tier: expectOpenAIKey ? "FULL_ACCESS" : "WRITE_LOCAL",
				onText: (text) => {
					if (verbose) {
						process.stdout.write(chalk.gray(text));
					}
				},
			},
		);

		const duration = Date.now() - startTime;
		const cwdWritable = output.includes("CWD_WRITABLE");
		const homeSet = output.includes("HOME_SET");
		const credentialProxySet = output.includes("CRED_PROXY_SET");
		const rawOpenAIKeyAbsent = output.includes("RAW_OPENAI_KEY_ABSENT");

		const passed = usesRemoteAgent
			? cwdWritable && homeSet && credentialProxySet && rawOpenAIKeyAbsent
			: cwdWritable && homeSet;

		if (passed) {
			console.log(chalk.green(`  ✓ ${name} (${duration}ms)`));
			if (verbose) {
				console.log(chalk.gray(`    CWD writable: ${cwdWritable}`));
				console.log(chalk.gray(`    HOME set: ${homeSet}`));
				if (usesRemoteAgent) {
					console.log(chalk.gray(`    Credential proxy set: ${credentialProxySet}`));
					console.log(chalk.gray(`    Raw OpenAI key absent: ${rawOpenAIKeyAbsent}`));
				}
			}
			return { name, passed: true, message: "OK", duration };
		}
		if (error) {
			console.log(chalk.red(`  ✗ ${name}: ${error}`));
			return { name, passed: false, message: error };
		}
		const details = usesRemoteAgent
			? `cwdWritable=${cwdWritable}, homeSet=${homeSet}, credProxySet=${credentialProxySet}, rawOpenAIKeyAbsent=${rawOpenAIKeyAbsent}`
			: `cwdWritable=${cwdWritable}, homeSet=${homeSet}`;
		console.log(chalk.red(`  ✗ ${name}: ${details}`));
		if (verbose) {
			console.log(chalk.gray(`    Output: ${output.substring(0, 300)}`));
		}
		return { name, passed: false, message: details };
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		console.log(chalk.red(`  ✗ ${name}: ${message}`));
		return { name, passed: false, message };
	}
}

/**
 * Test image generation through the supported telclaude path.
 * In Docker this should use relay-backed credentials/capabilities, not raw key injection.
 */
async function testImageGeneration(
	verbose: boolean,
	timeoutMs: number,
): Promise<{ name: string; passed: boolean; message: string; duration?: number }> {
	const name = "Image generation via SDK";

	try {
		console.log("  Running image generation test via SDK...");
		const startTime = Date.now();

		let imagePath = "";

		const { output, error } = await runSdkQuery(
			`Run this exact bash command to generate a tiny test image through telclaude and then print the saved absolute PNG path:

telclaude generate-image "red circle on white background" --size 1024x1024 --quality low

After it completes, verify the file exists with ls -la on that exact path and print the path again.`,
			{
				enableSkills: false,
				timeoutMs,
				tier: "FULL_ACCESS",
				onText: (text) => {
					if (verbose) {
						process.stdout.write(chalk.gray(text));
					}
					// Extract file path - match any absolute path ending in .png
					const match = text.match(/\/[^\s"']+\.png/);
					if (match) {
						imagePath = match[0];
					}
				},
			},
		);

		const duration = Date.now() - startTime;

		// Also check full output for path
		if (!imagePath) {
			const match = output.match(/\/[^\s"']+\.png/);
			if (match) {
				imagePath = match[0];
			}
		}

		// Verify the image was created
		if (imagePath && fs.existsSync(imagePath)) {
			const stats = fs.statSync(imagePath);
			console.log(chalk.green(`  ✓ ${name} (${duration}ms)`));
			console.log(chalk.gray(`    Image: ${imagePath} (${(stats.size / 1024).toFixed(1)} KB)`));

			// Clean up test image
			try {
				fs.unlinkSync(imagePath);
			} catch {
				// ignore cleanup errors
			}

			return { name, passed: true, message: "OK", duration };
		}
		if (error) {
			console.log(chalk.red(`  ✗ ${name}: ${error}`));
			return { name, passed: false, message: error };
		}
		if (
			output.toLowerCase().includes("error") ||
			output.toLowerCase().includes("failed") ||
			output.toLowerCase().includes("timeout") ||
			output.toLowerCase().includes("connection")
		) {
			console.log(chalk.red(`  ✗ ${name}: Generation failed`));
			if (verbose) {
				console.log(chalk.gray(`    Output: ${output.substring(0, 500)}`));
			}
			// Extract error message if present
			const errMatch = output.match(/error[:\s]+([^\n]+)/i);
			return { name, passed: false, message: errMatch?.[1] ?? "Generation failed" };
		}
		console.log(chalk.red(`  ✗ ${name}: No image path found`));
		if (verbose) {
			console.log(chalk.gray(`    Output: ${output.substring(0, 500)}`));
		}
		return { name, passed: false, message: "No image path in output" };
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		console.log(chalk.red(`  ✗ ${name}: ${message}`));
		return { name, passed: false, message };
	}
}

/**
 * Test Docker runtime wiring through the supported agent path.
 * Verifies relay health and credential-proxy health instead of retired SDK sandbox HTTP_PROXY behavior.
 */
async function testNetworkProxy(
	verbose: boolean,
	timeoutMs: number,
): Promise<{ name: string; passed: boolean; message: string; duration?: number }> {
	const name = "Docker runtime wiring via SDK";
	const usesRemoteAgent = Boolean(process.env.TELCLAUDE_AGENT_URL);

	try {
		console.log("  Running Docker runtime wiring diagnostic via SDK...");
		const startTime = Date.now();

		const { output, error } = await runSdkQuery(
			usesRemoteAgent
				? `Run these exact checks and report the markers:

echo "CAPABILITIES=$TELCLAUDE_CAPABILITIES_URL"
echo "CRED_PROXY=$TELCLAUDE_CREDENTIAL_PROXY_URL"
curl -sf "$TELCLAUDE_CAPABILITIES_URL/health" && echo "CAP_HEALTH_OK" || echo "CAP_HEALTH_FAIL"
curl -sf "$TELCLAUDE_CREDENTIAL_PROXY_URL/health" && echo "HTTP_PROXY_HEALTH_OK" || echo "HTTP_PROXY_HEALTH_FAIL"

Report the exact markers only.`
				: `Run these exact checks and report the markers:

test -w . && echo "CWD_WRITABLE" || echo "CWD_READONLY"
curl -sf http://localhost:8790/health && echo "CAP_HEALTH_OK" || echo "CAP_HEALTH_FAIL"

Report the exact markers only.`,
			{
				enableSkills: false,
				timeoutMs,
				onText: (text) => {
					if (verbose) {
						process.stdout.write(chalk.gray(text));
					}
				},
			},
		);

		const duration = Date.now() - startTime;
		const cwdWritable = output.includes("CWD_WRITABLE");
		const capabilityHealthOk = output.includes("CAP_HEALTH_OK");
		const httpProxyHealthOk = output.includes("HTTP_PROXY_HEALTH_OK");

		if (verbose) {
			console.log(chalk.gray(`\n    CWD writable: ${cwdWritable}`));
			console.log(chalk.gray(`    Capabilities health OK: ${capabilityHealthOk}`));
			if (usesRemoteAgent) {
				console.log(chalk.gray(`    Credential proxy health OK: ${httpProxyHealthOk}`));
			}
		}

		if (
			(usesRemoteAgent && capabilityHealthOk && httpProxyHealthOk) ||
			(!usesRemoteAgent && cwdWritable && capabilityHealthOk)
		) {
			console.log(chalk.green(`  ✓ ${name} (${duration}ms)`));
			return { name, passed: true, message: "OK", duration };
		}
		if (error) {
			console.log(chalk.red(`  ✗ ${name}: ${error}`));
			return { name, passed: false, message: error };
		}
		const details = usesRemoteAgent
			? `capabilityHealthOk=${capabilityHealthOk}, httpProxyHealthOk=${httpProxyHealthOk}`
			: `cwdWritable=${cwdWritable}, capabilityHealthOk=${capabilityHealthOk}`;
		console.log(chalk.red(`  ✗ ${name}: ${details}`));
		if (verbose) {
			console.log(chalk.gray(`    Output: ${output.substring(0, 800)}`));
		}
		return { name, passed: false, message: details };
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		console.log(chalk.red(`  ✗ ${name}: ${message}`));
		return { name, passed: false, message };
	}
}

/**
 * Test voice message response through SDK.
 * Simulates receiving a voice message and verifies Claude follows the TTS skill:
 * 1. Uses --voice-message flag (creates .ogg in /voice/ not .mp3 in /tts/)
 * 2. Outputs ONLY the file path (no extra text)
 * 3. Responds in the same language as the input
 */
async function testVoiceMessageResponse(
	verbose: boolean,
	timeoutMs: number,
): Promise<{ name: string; passed: boolean; message: string; duration?: number }> {
	const name = "Voice message response";

	try {
		console.log("  Testing voice message response via SDK...");
		console.log(chalk.gray("  Simulating incoming voice message and checking response format..."));
		const startTime = Date.now();

		let voicePath = "";
		let bashCommand = "";
		const mediaRoots = getMediaRootsForTests();
		const voicePattern = buildMediaPattern(mediaRoots, "voice", "ogg");
		const ttsPattern = buildMediaPattern(mediaRoots, "tts", "mp3");
		const normalizedVoiceRoots = mediaRoots.map((root) => {
			const normalized = normalizeSlashes(path.join(root, "voice"));
			return normalized.endsWith("/") ? normalized : `${normalized}/`;
		});

		// Simulate a voice message being received (this is how it appears to Claude via Telegram)
		const { output, error } = await runSdkQuery(
			`You just received a voice message from a user. Here is the transcript:

[Voice Message Transcript]: "Hello, how are you doing today?"

According to your text-to-speech skill, when a user sends a voice message, you MUST:
1. Use the --voice-message flag with telclaude tts
2. Reply in the SAME language (English in this case)
3. Output ONLY the file path - no other text

Respond to this voice message now.`,
			{
				enableSkills: true,
				timeoutMs,
				tier: "FULL_ACCESS",
				onText: (text) => {
					if (verbose) {
						process.stdout.write(chalk.gray(text));
					}
					// Look for voice file path
					const voiceMatch = extractMediaPath(text, voicePattern);
					if (voiceMatch) {
						voicePath = voiceMatch;
					}
					// Also check for wrong path (tts instead of voice)
					const ttsMatch = extractMediaPath(text, ttsPattern);
					if (ttsMatch && !voicePath) {
						voicePath = ttsMatch; // Will be flagged as wrong format
					}
				},
				onToolUse: (toolName, input) => {
					if (toolName === "Bash" && typeof input === "object" && input !== null) {
						const cmd = (input as { command?: string }).command ?? "";
						if (cmd.includes("telclaude tts")) {
							bashCommand = cmd;
						}
					}
				},
			},
		);

		const duration = Date.now() - startTime;

		// Also scan full output for paths
		if (!voicePath) {
			const voiceMatch = extractMediaPath(output, voicePattern);
			if (voiceMatch) {
				voicePath = voiceMatch;
			}
			const ttsMatch = extractMediaPath(output, ttsPattern);
			if (ttsMatch && !voicePath) {
				voicePath = ttsMatch;
			}
		}

		// Validation checks
		const issues: string[] = [];

		// Check 0: Did it call telclaude tts at all?
		if (!bashCommand) {
			issues.push("No telclaude tts command was executed");
		}

		// Check 1: Did it use --voice-message flag?
		if (bashCommand && !bashCommand.includes("--voice-message")) {
			issues.push("Missing --voice-message flag");
		}

		// Check 2: Is the file in /voice/ directory (not /tts/)?
		if (voicePath) {
			const normalizedPath = normalizeSlashes(voicePath);
			const isVoiceDir = normalizedVoiceRoots.some((root) => normalizedPath.startsWith(root));
			if (!isVoiceDir) {
				issues.push("Wrong directory: expected /voice/ within media outbox");
			}
		}

		// Check 3: Is the format .ogg (not .mp3)?
		if (voicePath && !voicePath.endsWith(".ogg")) {
			issues.push("Wrong format: used .mp3 instead of .ogg");
		}

		// Check 4: Does the file actually exist? (prevents hallucinated paths)
		if (voicePath) {
			try {
				if (!fs.existsSync(voicePath)) {
					issues.push("Voice file does not exist (path may be hallucinated)");
				}
			} catch {
				issues.push("Could not verify voice file existence");
			}
		}

		// Check 5: Is the output minimal (just path, no extra text)?
		// Allow some leeway for thinking/tool output but flag excessive text
		const outputLines = output
			.trim()
			.split("\n")
			.filter((l) => l.trim());
		const nonPathLines = outputLines.filter((line) => {
			const normalized = normalizeSlashes(line);
			const containsRoot = mediaRoots.some((root) => normalized.includes(normalizeSlashes(root)));
			return !containsRoot && !line.includes(".telclaude-media") && line.trim().length > 0;
		});
		const hasExcessiveText = nonPathLines.length > 3 || output.length > 500;
		if (hasExcessiveText && voicePath) {
			issues.push("Excessive text in response (should be path only)");
		}

		// Results
		if (voicePath && issues.length === 0) {
			console.log(chalk.green(`  ✓ ${name} (${duration}ms)`));
			if (verbose) {
				console.log(chalk.gray(`    Voice file: ${voicePath}`));
				console.log(chalk.gray(`    Command: ${bashCommand.substring(0, 100)}...`));
			}
			return { name, passed: true, message: "OK", duration };
		}

		if (voicePath && issues.length > 0) {
			// Partial success - generated audio but with issues
			console.log(chalk.yellow(`  ⚠ ${name}: Generated audio but with issues`));
			for (const issue of issues) {
				console.log(chalk.yellow(`    • ${issue}`));
			}
			if (verbose) {
				console.log(chalk.gray(`    Path: ${voicePath}`));
				console.log(chalk.gray(`    Command: ${bashCommand}`));
			}
			return { name, passed: false, message: issues.join("; "), duration };
		}

		if (error) {
			console.log(chalk.red(`  ✗ ${name}: ${error}`));
			return { name, passed: false, message: error };
		}

		console.log(chalk.red(`  ✗ ${name}: No voice file generated`));
		if (verbose) {
			console.log(chalk.gray(`    Output: ${output.substring(0, 500)}`));
		}
		return { name, passed: false, message: "No voice file generated" };
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		console.log(chalk.red(`  ✗ ${name}: ${message}`));
		return { name, passed: false, message };
	}
}
