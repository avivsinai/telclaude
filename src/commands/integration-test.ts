/**
 * Integration test command for testing the full SDK path.
 *
 * This command runs queries through the actual Claude SDK, testing:
 * - SDK sandbox initialization (native mode)
 * - Network proxy setup by SDK
 * - Skill execution (image-generator, etc.)
 *
 * This allows testing without Telegram/auth overhead.
 */

import fs from "node:fs";

import chalk from "chalk";
import type { Command } from "commander";

import { executeQueryStream } from "../sdk/client.js";
import { getOpenAIKey } from "../services/openai-client.js";

type IntegrationTestOptions = {
	image?: boolean;
	echo?: boolean;
	env?: boolean;
	network?: boolean;
	voice?: boolean;
	all?: boolean;
	verbose?: boolean;
	timeout?: string;
};

export function registerIntegrationTestCommand(program: Command): void {
	program
		.command("integration-test")
		.description("Test full SDK path (sandbox, network proxy, skills)")
		.option("--image", "Test image generation through SDK")
		.option("--echo", "Test simple echo command through SDK")
		.option("--env", "Test environment variable passing through SDK")
		.option("--network", "Test sandbox network proxy configuration")
		.option("--voice", "Test voice message response (TTS skill)")
		.option("--all", "Run all integration tests")
		.option("-v, --verbose", "Show detailed output")
		.option("--timeout <ms>", "Query timeout in ms", "120000")
		.action(async (opts: IntegrationTestOptions) => {
			const verbose = program.opts().verbose || opts.verbose;
			const timeoutMs = Number.parseInt(opts.timeout ?? "120000", 10);

			const runAll =
				opts.all || (!opts.image && !opts.echo && !opts.env && !opts.network && !opts.voice);
			const runImage = opts.image || runAll;
			const runEcho = opts.echo || runAll;
			const runEnv = opts.env || runAll;
			const runNetwork = opts.network || runAll;
			const runVoice = opts.voice || runAll;

			console.log(chalk.bold("\n🔬 Telclaude Integration Test\n"));
			console.log("This tests the full SDK path (not just sandbox config).\n");

			// SDK handles sandbox initialization internally when sandbox.enabled=true
			// No need to pre-check - SDK will fail with clear error if unavailable

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
				console.log(chalk.bold("── Network Proxy Test ──"));
				const result = await testNetworkProxy(verbose, timeoutMs);
				results.push(result);
				console.log();
			}

			if (runImage) {
				console.log(chalk.bold("── Image Generation Test ──"));
				const hasKey = await getOpenAIKey();
				if (!hasKey) {
					console.log(chalk.yellow("  ○ Skipped (OPENAI_API_KEY not configured)"));
					results.push({
						name: "Image generation",
						passed: true,
						message: "Skipped (no API key)",
					});
				} else {
					// Note: Image generation through SDK sandbox may fail locally because:
					// - The telclaude CLI inside sandbox can't access ~/.telclaude (blocked)
					// - However, OPENAI_API_KEY is injected via env var by buildSdkOptions()
					// - In Docker, this works because the key comes from env var, not keychain
					if (verbose) {
						console.log(chalk.gray("  Note: Testing image generation through SDK sandbox..."));
						console.log(chalk.gray("  The SDK should inject OPENAI_API_KEY into the environment."));
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
					console.log(chalk.yellow("  ○ Skipped (OPENAI_API_KEY not configured)"));
					results.push({
						name: "Voice message response",
						passed: true,
						message: "Skipped (no API key)",
					});
				} else {
					const result = await testVoiceMessageResponse(verbose, timeoutMs);
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
		onText?: (text: string) => void;
		onToolUse?: (name: string, input: unknown) => void;
	},
): Promise<{ output: string; success: boolean; error?: string }> {
	let output = "";
	let querySuccess = false;
	let error: string | undefined;

	const controller = new AbortController();
	const timeout = setTimeout(() => controller.abort(), opts.timeoutMs);

	try {
		const stream = executeQueryStream(prompt, {
			tier: "WRITE_LOCAL",
			enableSkills: opts.enableSkills,
			permissionMode: "acceptEdits",
			cwd: process.cwd(),
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
 * Test environment variable passing through SDK.
 * Verifies that the SDK properly injects env vars (like OPENAI_API_KEY) into the sandbox.
 */
async function testEnvPassing(
	verbose: boolean,
	timeoutMs: number,
	expectOpenAIKey: boolean,
): Promise<{ name: string; passed: boolean; message: string; duration?: number }> {
	const name = "Env vars via SDK";

	try {
		console.log("  Running environment variable test via SDK...");
		const startTime = Date.now();

		// Ask the SDK to check if OPENAI_API_KEY is in the environment
		const checkVar = expectOpenAIKey ? "OPENAI_API_KEY" : "HOME";
		const { output, error } = await runSdkQuery(
			`Run this bash command and tell me if the environment variable is set: test -n "$${checkVar}" && echo "ENV_VAR_SET" || echo "ENV_VAR_EMPTY"`,
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

		// Check for various ways the model might respond
		const outputLower = output.toLowerCase();
		const isSet =
			output.includes("ENV_VAR_SET") ||
			outputLower.includes("is set") ||
			outputLower.includes("is defined") ||
			outputLower.includes("exists") ||
			outputLower.includes("has a value") ||
			outputLower.includes("non-empty");
		const isEmpty =
			output.includes("ENV_VAR_EMPTY") ||
			outputLower.includes("is not set") ||
			outputLower.includes("is empty") ||
			outputLower.includes("not defined") ||
			outputLower.includes("does not exist");

		if (isSet && !isEmpty) {
			console.log(chalk.green(`  ✓ ${name} (${duration}ms)`));
			if (verbose) {
				console.log(chalk.gray(`    Checked: ${checkVar} is set in sandbox environment`));
			}
			return { name, passed: true, message: "OK", duration };
		}
		if (isEmpty) {
			// This is expected if we're checking OPENAI_API_KEY and it wasn't injected
			if (expectOpenAIKey) {
				console.log(chalk.red(`  ✗ ${name}: OPENAI_API_KEY not passed to sandbox`));
				return { name, passed: false, message: "OPENAI_API_KEY not in sandbox env" };
			}
			console.log(chalk.green(`  ✓ ${name} (${duration}ms)`));
			return { name, passed: true, message: "OK (no key expected)", duration };
		}
		if (error) {
			console.log(chalk.red(`  ✗ ${name}: ${error}`));
			return { name, passed: false, message: error };
		}
		console.log(chalk.red(`  ✗ ${name}: Unexpected output`));
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
 * Test image generation through SDK.
 * This tests the full path: SDK → sandbox → OpenAI API
 *
 * Note: This test verifies the SDK can make OpenAI API calls from within the sandbox.
 * The `telclaude generate-image` CLI won't work inside the sandbox because it needs
 * access to ~/.telclaude for config. Instead, we test that the API is reachable and
 * that the OPENAI_API_KEY is properly passed.
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

		// Use curl to call OpenAI API directly (CLI can't access ~/.telclaude in sandbox)
		// Uses gpt-image-1.5 with b64_json output to match prod (image-generation.ts)
		const { output, error } = await runSdkQuery(
			`Generate a simple test image using the OpenAI API. The OPENAI_API_KEY env var is available.

Run this curl command to generate an image and save it:
curl -s https://api.openai.com/v1/images/generations \\
  -H "Authorization: Bearer $OPENAI_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"model":"gpt-image-1.5","prompt":"red circle on white background","size":"1024x1024","output_format":"png"}' \\
  | jq -r '.data[0].b64_json' | base64 -d > ./test-image.png

Verify the file was created with: ls -la ./test-image.png
Tell me the absolute path to the saved PNG file.`,
			{
				enableSkills: true,
				timeoutMs,
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
 * Test network proxy configuration through SDK.
 * Runs diagnostic commands inside the sandbox to verify the proxy chain.
 * Tests actual HTTP requests through the proxy to verify end-to-end connectivity.
 */
async function testNetworkProxy(
	verbose: boolean,
	timeoutMs: number,
): Promise<{ name: string; passed: boolean; message: string; duration?: number }> {
	const name = "Network proxy via SDK";

	try {
		console.log("  Running network proxy diagnostic via SDK...");
		const startTime = Date.now();

		// Test actual HTTP request through the proxy (this is what matters)
		const { output, error } = await runSdkQuery(
			`Test the sandbox network proxy by running these commands and reporting results:

1. Show proxy environment:
   echo "HTTP_PROXY=$HTTP_PROXY"
   echo "SANDBOX_RUNTIME=$SANDBOX_RUNTIME"

2. Test HTTPS fetch through proxy (this is the real test):
   curl -s --max-time 10 https://api.openai.com/v1/models 2>&1 | head -c 200

Report results clearly. Mark "FETCH_SUCCESS" if curl returns any JSON (even 401), "FETCH_FAIL" if it times out or errors.`,
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

		// Check for proxy environment (port is dynamic, just check for localhost)
		const hasProxy =
			output.includes("HTTP_PROXY=http://localhost:") || output.includes("http://localhost:");

		// Check for sandbox runtime
		const inSandbox = output.includes("SANDBOX_RUNTIME=1");

		// Check for successful fetch (any JSON response, including 401 auth error)
		const fetchSuccess =
			output.includes("FETCH_SUCCESS") ||
			output.includes('"error"') || // OpenAI error response
			output.includes('"data"') || // OpenAI success response
			output.includes("invalid_api_key") || // Auth error = network worked
			output.includes("401"); // Unauthorized = network worked

		// Check for network failure
		const fetchFail =
			output.includes("FETCH_FAIL") ||
			output.includes("Could not resolve host") ||
			output.includes("Connection refused") ||
			output.includes("Operation timed out") ||
			output.includes("EAI_AGAIN");

		if (verbose) {
			console.log(chalk.gray(`\n    Proxy env detected: ${hasProxy}`));
			console.log(chalk.gray(`    Running in sandbox: ${inSandbox}`));
			console.log(chalk.gray(`    Fetch succeeded: ${fetchSuccess}`));
			console.log(chalk.gray(`    Fetch failed: ${fetchFail}`));
		}

		if (fetchSuccess && !fetchFail) {
			console.log(chalk.green(`  ✓ ${name} (${duration}ms)`));
			return { name, passed: true, message: "Proxy working - HTTPS fetch succeeded", duration };
		}
		if (fetchFail) {
			// This is the actual failure case we're investigating
			const reason = output.includes("EAI_AGAIN")
				? "DNS resolution failed (EAI_AGAIN)"
				: output.includes("Connection refused")
					? "Proxy connection refused"
					: output.includes("Operation timed out")
						? "Request timed out"
						: "Network request failed";
			console.log(chalk.red(`  ✗ ${name}: ${reason}`));
			if (verbose) {
				console.log(chalk.gray(`    Full output: ${output.substring(0, 800)}`));
			}
			return { name, passed: false, message: reason };
		}
		if (!hasProxy) {
			console.log(chalk.red(`  ✗ ${name}: No proxy environment vars`));
			return { name, passed: false, message: "HTTP_PROXY not set in sandbox" };
		}
		if (error) {
			console.log(chalk.red(`  ✗ ${name}: ${error}`));
			return { name, passed: false, message: error };
		}
		console.log(chalk.yellow(`  ? ${name}: Unexpected output`));
		if (verbose) {
			console.log(chalk.gray(`    Output: ${output.substring(0, 500)}`));
		}
		return { name, passed: false, message: "Unexpected output" };
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
				onText: (text) => {
					if (verbose) {
						process.stdout.write(chalk.gray(text));
					}
					// Look for voice file path
					const voiceMatch = text.match(/\/[^\s"']*\.telclaude-media\/voice\/[^\s"']+\.ogg/);
					if (voiceMatch) {
						voicePath = voiceMatch[0];
					}
					// Also check for wrong path (tts instead of voice)
					const ttsMatch = text.match(/\/[^\s"']*\.telclaude-media\/tts\/[^\s"']+\.mp3/);
					if (ttsMatch && !voicePath) {
						voicePath = ttsMatch[0]; // Will be flagged as wrong format
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
			const voiceMatch = output.match(/\/[^\s"']*\.telclaude-media\/voice\/[^\s"']+\.ogg/);
			if (voiceMatch) {
				voicePath = voiceMatch[0];
			}
			const ttsMatch = output.match(/\/[^\s"']*\.telclaude-media\/tts\/[^\s"']+\.mp3/);
			if (ttsMatch && !voicePath) {
				voicePath = ttsMatch[0];
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
		if (voicePath && !voicePath.includes(".telclaude-media/voice/")) {
			issues.push("Wrong directory: used /tts/ instead of /voice/");
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
		const nonPathLines = outputLines.filter(
			(l) => !l.includes(".telclaude-media") && l.trim().length > 0,
		);
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
