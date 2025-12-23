/**
 * Diagnostic command to test sandbox network proxy chain.
 *
 * This command tests each component of the proxy chain to identify
 * where network failures occur inside the bubblewrap sandbox.
 *
 * Run inside container: telclaude diagnose-sandbox-network
 */

import type { Command } from "commander";
import * as net from "node:net";
import { getChildLogger } from "../logging.js";

export function registerDiagnoseSandboxNetworkCommand(program: Command): void {
	program
		.command("diagnose-sandbox-network")
		.description("Diagnose sandbox network proxy chain (run inside container)")
		.action(async () => {
			await diagnoseSandboxNetwork();
		});
}

const logger = getChildLogger({ module: "diagnose-sandbox-network" });

interface DiagResult {
	step: string;
	success: boolean;
	details: string;
	error?: string;
}

export async function diagnoseSandboxNetwork(): Promise<void> {
	const results: DiagResult[] = [];

	console.log("=== Sandbox Network Diagnostic ===\n");

	// Step 1: Check environment variables
	console.log("1. Checking proxy environment variables...");
	const proxyVars = {
		HTTP_PROXY: process.env.HTTP_PROXY,
		HTTPS_PROXY: process.env.HTTPS_PROXY,
		http_proxy: process.env.http_proxy,
		https_proxy: process.env.https_proxy,
		ALL_PROXY: process.env.ALL_PROXY,
		NO_PROXY: process.env.NO_PROXY,
		SANDBOX_RUNTIME: process.env.SANDBOX_RUNTIME,
	};

	const hasProxy = !!(proxyVars.HTTP_PROXY || proxyVars.http_proxy);
	results.push({
		step: "Check proxy env vars",
		success: hasProxy,
		details: hasProxy
			? `HTTP_PROXY=${proxyVars.HTTP_PROXY || proxyVars.http_proxy}`
			: "No proxy env vars set - NOT running inside sandbox",
	});

	for (const [key, value] of Object.entries(proxyVars)) {
		console.log(`   ${key}=${value || "(not set)"}`);
	}
	console.log();

	// Step 2: Check if we can connect to localhost:3128 (proxy port)
	console.log("2. Testing TCP connection to localhost:3128...");
	const proxyConnectResult = await testTcpConnect("127.0.0.1", 3128, 5000);
	results.push({
		step: "TCP connect to localhost:3128",
		success: proxyConnectResult.success,
		details: proxyConnectResult.success
			? "Successfully connected to proxy port"
			: "FAILED to connect to proxy port",
		error: proxyConnectResult.error,
	});
	console.log(
		`   Result: ${proxyConnectResult.success ? "✓ SUCCESS" : "✗ FAILED"}`,
	);
	if (proxyConnectResult.error) {
		console.log(`   Error: ${proxyConnectResult.error}`);
	}
	console.log();

	// Step 3: Check if we can connect to localhost:1080 (SOCKS port)
	console.log("3. Testing TCP connection to localhost:1080...");
	const socksConnectResult = await testTcpConnect("127.0.0.1", 1080, 5000);
	results.push({
		step: "TCP connect to localhost:1080",
		success: socksConnectResult.success,
		details: socksConnectResult.success
			? "Successfully connected to SOCKS port"
			: "FAILED to connect to SOCKS port",
		error: socksConnectResult.error,
	});
	console.log(
		`   Result: ${socksConnectResult.success ? "✓ SUCCESS" : "✗ FAILED"}`,
	);
	if (socksConnectResult.error) {
		console.log(`   Error: ${socksConnectResult.error}`);
	}
	console.log();

	// Step 4: Test HTTP CONNECT through proxy
	if (proxyConnectResult.success) {
		console.log("4. Testing HTTP CONNECT through proxy...");
		const connectResult = await testHttpConnect(
			"127.0.0.1",
			3128,
			"api.openai.com",
			443,
			5000,
		);
		results.push({
			step: "HTTP CONNECT through proxy",
			success: connectResult.success,
			details: connectResult.success
				? `Proxy returned: ${connectResult.response}`
				: "FAILED to establish tunnel",
			error: connectResult.error,
		});
		console.log(
			`   Result: ${connectResult.success ? "✓ SUCCESS" : "✗ FAILED"}`,
		);
		if (connectResult.response) {
			console.log(`   Response: ${connectResult.response}`);
		}
		if (connectResult.error) {
			console.log(`   Error: ${connectResult.error}`);
		}
		console.log();
	} else {
		console.log("4. Skipping HTTP CONNECT test (proxy port unreachable)\n");
		results.push({
			step: "HTTP CONNECT through proxy",
			success: false,
			details: "Skipped - proxy port unreachable",
		});
	}

	// Step 5: Test direct DNS resolution (should fail in sandbox)
	console.log("5. Testing direct DNS resolution (should FAIL in sandbox)...");
	const dnsResult = await testDnsResolve("api.openai.com", 5000);
	results.push({
		step: "Direct DNS resolution",
		success: !dnsResult.success, // We EXPECT this to fail in sandbox
		details: dnsResult.success
			? `WARNING: DNS resolved to ${dnsResult.addresses?.join(", ")} - sandbox may not be isolating network!`
			: "DNS failed as expected in sandbox",
		error: dnsResult.error,
	});
	console.log(
		`   Result: ${dnsResult.success ? "⚠ UNEXPECTED SUCCESS" : "✓ FAILED (expected)"}`,
	);
	if (dnsResult.addresses) {
		console.log(`   Addresses: ${dnsResult.addresses.join(", ")}`);
	}
	if (dnsResult.error) {
		console.log(`   Error: ${dnsResult.error}`);
	}
	console.log();

	// Step 6: Test undici ProxyAgent
	console.log("6. Testing undici ProxyAgent fetch...");
	if (hasProxy) {
		const fetchResult = await testProxyAgentFetch(
			proxyVars.HTTP_PROXY || proxyVars.http_proxy || "",
			"https://api.openai.com/v1/models",
			10000,
		);
		results.push({
			step: "ProxyAgent fetch",
			success: fetchResult.success,
			details: fetchResult.success
				? `HTTP ${fetchResult.status}: ${fetchResult.statusText}`
				: "FAILED to fetch through proxy",
			error: fetchResult.error,
		});
		console.log(
			`   Result: ${fetchResult.success ? "✓ SUCCESS" : "✗ FAILED"}`,
		);
		if (fetchResult.status) {
			console.log(`   Status: ${fetchResult.status} ${fetchResult.statusText}`);
		}
		if (fetchResult.error) {
			console.log(`   Error: ${fetchResult.error}`);
		}
	} else {
		console.log("   Skipping - no proxy configured");
		results.push({
			step: "ProxyAgent fetch",
			success: false,
			details: "Skipped - no proxy configured",
		});
	}
	console.log();

	// Summary
	console.log("=== Summary ===");
	const failures = results.filter((r) => !r.success);
	if (failures.length === 0) {
		console.log("All tests passed! Sandbox network proxy is working.");
	} else {
		console.log(`${failures.length} test(s) failed:`);
		for (const f of failures) {
			console.log(`  - ${f.step}: ${f.details}`);
			if (f.error) console.log(`    Error: ${f.error}`);
		}
	}

	// Log full results for debugging
	logger.info({ results }, "Sandbox network diagnostic complete");
}

async function testTcpConnect(
	host: string,
	port: number,
	timeoutMs: number,
): Promise<{ success: boolean; error?: string }> {
	return new Promise((resolve) => {
		const socket = new net.Socket();
		const timeout = setTimeout(() => {
			socket.destroy();
			resolve({ success: false, error: "Connection timed out" });
		}, timeoutMs);

		socket.connect(port, host, () => {
			clearTimeout(timeout);
			socket.destroy();
			resolve({ success: true });
		});

		socket.on("error", (err) => {
			clearTimeout(timeout);
			resolve({ success: false, error: err.message });
		});
	});
}

async function testHttpConnect(
	proxyHost: string,
	proxyPort: number,
	targetHost: string,
	targetPort: number,
	timeoutMs: number,
): Promise<{ success: boolean; response?: string; error?: string }> {
	return new Promise((resolve) => {
		const socket = new net.Socket();
		const timeout = setTimeout(() => {
			socket.destroy();
			resolve({ success: false, error: "Connection timed out" });
		}, timeoutMs);

		socket.connect(proxyPort, proxyHost, () => {
			// Send HTTP CONNECT request
			socket.write(
				`CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\n` +
					`Host: ${targetHost}:${targetPort}\r\n` +
					`\r\n`,
			);
		});

		socket.on("data", (data) => {
			clearTimeout(timeout);
			const response = data.toString().split("\r\n")[0];
			const success = response.includes("200");
			socket.destroy();
			resolve({ success, response });
		});

		socket.on("error", (err) => {
			clearTimeout(timeout);
			resolve({ success: false, error: err.message });
		});
	});
}

async function testDnsResolve(
	hostname: string,
	timeoutMs: number,
): Promise<{ success: boolean; addresses?: string[]; error?: string }> {
	const dns = await import("node:dns/promises");

	return new Promise((resolve) => {
		const timeout = setTimeout(() => {
			resolve({ success: false, error: "DNS lookup timed out" });
		}, timeoutMs);

		dns
			.resolve4(hostname)
			.then((addresses) => {
				clearTimeout(timeout);
				resolve({ success: true, addresses });
			})
			.catch((err) => {
				clearTimeout(timeout);
				resolve({ success: false, error: err.code || err.message });
			});
	});
}

async function testProxyAgentFetch(
	proxyUrl: string,
	targetUrl: string,
	timeoutMs: number,
): Promise<{
	success: boolean;
	status?: number;
	statusText?: string;
	error?: string;
}> {
	try {
		const { ProxyAgent } = await import("undici");
		const agent = new ProxyAgent(proxyUrl);

		const controller = new AbortController();
		const timeout = setTimeout(() => controller.abort(), timeoutMs);

		const response = await fetch(targetUrl, {
			dispatcher: agent as unknown as RequestInit["dispatcher"],
			signal: controller.signal,
			method: "GET",
		});

		clearTimeout(timeout);
		return {
			success: response.ok || response.status === 401, // 401 is expected without API key
			status: response.status,
			statusText: response.statusText,
		};
	} catch (err) {
		const error = err as Error;
		return {
			success: false,
			error: error.message || String(err),
		};
	}
}
