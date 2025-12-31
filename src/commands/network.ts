/**
 * CLI commands for managing private network endpoint allowlists.
 *
 * Allows users to configure access to local network services like
 * Home Assistant, Plex, NAS, etc.
 *
 * Commands:
 * - telclaude network list - List configured private endpoints
 * - telclaude network add <label> - Add a new private endpoint
 * - telclaude network remove <label> - Remove a private endpoint
 * - telclaude network test <url> - Test if a URL would be allowed
 */

import fs from "node:fs";
import type { Command } from "commander";
import { Validator } from "ip-num";
import JSON5 from "json5";
import { getConfigPath, loadConfig, type PrivateEndpoint } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import {
	cachedDNSLookup,
	checkPrivateNetworkAccess,
	clearDNSCache,
} from "../sandbox/network-proxy.js";

const logger = getChildLogger({ module: "cmd-network" });

/**
 * Read and parse config file, returning raw JSON for modification.
 */
function readConfigFile(): Record<string, unknown> {
	const configPath = getConfigPath();
	try {
		const content = fs.readFileSync(configPath, "utf-8");
		return JSON5.parse(content);
	} catch {
		return {};
	}
}

/**
 * Write config file with pretty formatting.
 */
function writeConfigFile(config: Record<string, unknown>): void {
	const configPath = getConfigPath();
	fs.writeFileSync(configPath, JSON.stringify(config, null, 2), "utf-8");
}

/**
 * Validate CIDR notation.
 */
function isValidCidr(cidr: string): boolean {
	const [isValid] = Validator.isValidIPv4CidrRange(cidr);
	if (isValid) return true;

	// Also check IPv6 CIDR
	if (cidr.includes(":") && cidr.includes("/")) {
		const [isValidV6] = Validator.isValidIPv6CidrRange(cidr);
		return isValidV6;
	}

	return false;
}

/**
 * Validate IP address or hostname.
 */
function isValidHost(host: string): boolean {
	const [isValidV4] = Validator.isValidIPv4String(host);
	if (isValidV4) return true;

	const [isValidV6] = Validator.isValidIPv6String(host);
	if (isValidV6) return true;

	// Allow hostname pattern (basic validation)
	return /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$/.test(
		host,
	);
}

export function registerNetworkCommand(program: Command): void {
	const network = program
		.command("network")
		.description("Manage private network endpoint allowlists");

	// List command
	network
		.command("list")
		.description("List configured private endpoints")
		.option("--json", "Output as JSON")
		.action((opts: { json?: boolean }) => {
			try {
				const config = loadConfig();
				const endpoints = config.security?.network?.privateEndpoints ?? [];

				if (opts.json) {
					console.log(JSON.stringify(endpoints, null, 2));
					return;
				}

				if (endpoints.length === 0) {
					console.log("No private endpoints configured.");
					console.log("\nAdd endpoints with: telclaude network add <label> --host <ip>");
					return;
				}

				console.log("Configured Private Endpoints:\n");
				for (const endpoint of endpoints) {
					const target = endpoint.cidr ?? endpoint.host;
					const ports = endpoint.ports?.join(", ") ?? "80, 443 (default)";
					console.log(`  ${endpoint.label}`);
					console.log(`    Target: ${target}`);
					console.log(`    Ports:  ${ports}`);
					if (endpoint.description) {
						console.log(`    Desc:   ${endpoint.description}`);
					}
					console.log();
				}
			} catch (err) {
				logger.error({ error: String(err) }, "network list failed");
				console.error(`Error: ${err}`);
				process.exit(1);
			}
		});

	// Add command
	network
		.command("add <label>")
		.description("Add a new private endpoint")
		.option("--host <host>", "IP address or hostname (e.g., 192.168.1.100, homeassistant.local)")
		.option("--cidr <cidr>", "CIDR range (e.g., 192.168.1.0/24)")
		.option("--ports <ports>", "Comma-separated list of allowed ports (default: 80,443)")
		.option("--description <desc>", "Optional description")
		.action(
			(
				label: string,
				opts: { host?: string; cidr?: string; ports?: string; description?: string },
			) => {
				try {
					// Validate inputs
					if (!opts.host && !opts.cidr) {
						console.error("Error: Must specify either --host or --cidr");
						process.exit(1);
					}

					if (opts.host && opts.cidr) {
						console.error("Error: Cannot specify both --host and --cidr");
						process.exit(1);
					}

					if (opts.host && !isValidHost(opts.host)) {
						console.error(`Error: Invalid host format: ${opts.host}`);
						process.exit(1);
					}

					if (opts.cidr && !isValidCidr(opts.cidr)) {
						console.error(`Error: Invalid CIDR format: ${opts.cidr}`);
						process.exit(1);
					}

					// Parse ports
					let ports: number[] | undefined;
					if (opts.ports) {
						ports = opts.ports.split(",").map((p) => {
							const port = Number.parseInt(p.trim(), 10);
							if (Number.isNaN(port) || port < 1 || port > 65535) {
								console.error(`Error: Invalid port: ${p}`);
								process.exit(1);
							}
							return port;
						});
					}

					// Read and modify config
					const rawConfig = readConfigFile();
					if (!rawConfig.security) rawConfig.security = {};
					const security = rawConfig.security as Record<string, unknown>;
					if (!security.network) security.network = {};
					const network = security.network as Record<string, unknown>;
					if (!network.privateEndpoints) network.privateEndpoints = [];
					const endpoints = network.privateEndpoints as PrivateEndpoint[];

					// Check for duplicate label
					if (endpoints.some((e) => e.label === label)) {
						console.error(`Error: Endpoint with label "${label}" already exists`);
						console.error("Use 'telclaude network remove' first to replace it");
						process.exit(1);
					}

					// Create new endpoint
					const newEndpoint: PrivateEndpoint = {
						label,
						...(opts.host && { host: opts.host }),
						...(opts.cidr && { cidr: opts.cidr }),
						...(ports && { ports }),
						...(opts.description && { description: opts.description }),
					};

					endpoints.push(newEndpoint);
					writeConfigFile(rawConfig);

					console.log(`✓ Added private endpoint: ${label}`);
					console.log(`  Target: ${opts.host ?? opts.cidr}`);
					console.log(`  Ports:  ${ports?.join(", ") ?? "80, 443 (default)"}`);
					if (opts.description) {
						console.log(`  Desc:   ${opts.description}`);
					}
				} catch (err) {
					logger.error({ error: String(err) }, "network add failed");
					console.error(`Error: ${err}`);
					process.exit(1);
				}
			},
		);

	// Remove command
	network
		.command("remove <label>")
		.description("Remove a private endpoint")
		.action((label: string) => {
			try {
				const rawConfig = readConfigFile();
				const security = rawConfig.security as Record<string, unknown> | undefined;
				const networkConfig = security?.network as Record<string, unknown> | undefined;
				const endpoints = networkConfig?.privateEndpoints as PrivateEndpoint[] | undefined;

				if (!endpoints || endpoints.length === 0) {
					console.error("Error: No private endpoints configured");
					process.exit(1);
				}

				const index = endpoints.findIndex((e) => e.label === label);
				if (index === -1) {
					console.error(`Error: Endpoint with label "${label}" not found`);
					process.exit(1);
				}

				const removed = endpoints.splice(index, 1)[0];
				writeConfigFile(rawConfig);

				console.log(`✓ Removed private endpoint: ${label}`);
				console.log(`  Was: ${removed.host ?? removed.cidr}`);
			} catch (err) {
				logger.error({ error: String(err) }, "network remove failed");
				console.error(`Error: ${err}`);
				process.exit(1);
			}
		});

	// Test command
	network
		.command("test <url>")
		.description("Test if a URL would be allowed by current configuration")
		.action(async (url: string) => {
			try {
				// Parse URL
				let parsedUrl: URL;
				try {
					parsedUrl = new URL(url);
				} catch {
					console.error(`Error: Invalid URL format: ${url}`);
					process.exit(1);
				}

				// Clear DNS cache to get fresh results
				clearDNSCache(parsedUrl.hostname);

				const config = loadConfig();
				const endpoints = config.security?.network?.privateEndpoints ?? [];

				// Extract port
				const port = parsedUrl.port
					? Number.parseInt(parsedUrl.port, 10)
					: parsedUrl.protocol === "https:"
						? 443
						: 80;

				console.log(`Testing: ${url}`);
				console.log(`  Host: ${parsedUrl.hostname}`);
				console.log(`  Port: ${port}`);
				console.log();

				// Resolve hostname
				const resolved = await cachedDNSLookup(parsedUrl.hostname);
				if (resolved && resolved.length > 0) {
					console.log(`  Resolved IPs: ${resolved.join(", ")}`);
				} else if (!resolved) {
					console.log("  DNS resolution failed");
				}
				console.log();

				// Check access
				const result = await checkPrivateNetworkAccess(parsedUrl.hostname, port, endpoints);

				if (result.allowed) {
					if (result.matchedEndpoint) {
						console.log(`✓ ALLOWED (matched private endpoint: ${result.matchedEndpoint.label})`);
					} else {
						console.log("✓ ALLOWED (public address, domain allowlist will apply)");
					}
				} else {
					console.log(`✗ BLOCKED`);
					console.log(`  Reason: ${result.reason}`);
				}
			} catch (err) {
				logger.error({ error: String(err) }, "network test failed");
				console.error(`Error: ${err}`);
				process.exit(1);
			}
		});
}
