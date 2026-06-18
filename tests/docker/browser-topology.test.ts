import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const repoRoot = path.resolve(import.meta.dirname, "../..");

function readDockerFile(relativePath: string): string {
	return fs.readFileSync(path.join(repoRoot, relativePath), "utf8");
}

function serviceBlock(compose: string, serviceName: string): string | null {
	const anchor = `\n  ${serviceName}:\n`;
	const start = compose.indexOf(anchor);
	if (start < 0) return null;
	const rest = compose.slice(start + anchor.length);
	const nextService = rest.search(/\n {2}[a-zA-Z0-9_-]+:\n/);
	return nextService < 0 ? rest : rest.slice(0, nextService);
}

function networkBlock(compose: string, networkName: string): string | null {
	const networksStart = compose.indexOf("\nnetworks:\n");
	if (networksStart < 0) return null;
	const networks = compose.slice(networksStart + "\nnetworks:\n".length);
	const anchor = `\n  ${networkName}:\n`;
	const start = networks.startsWith(`  ${networkName}:\n`) ? 0 : networks.indexOf(anchor);
	if (start < 0) return null;
	const rest = networks.slice(start + (start === 0 ? `  ${networkName}:\n`.length : anchor.length));
	const nextNetwork = rest.search(/\n {2}[a-zA-Z0-9_-]+:\n/);
	return nextNetwork < 0 ? rest : rest.slice(0, nextNetwork);
}

function networksSection(service: string | null): string {
	if (!service) return "";
	const start = service.indexOf("\n    networks:\n");
	if (start < 0) return "";
	const rest = service.slice(start + "\n    networks:\n".length);
	const nextTopLevelKey = rest.search(/\n {4}[a-zA-Z0-9_-]+:\n/);
	return nextTopLevelKey < 0 ? rest : rest.slice(0, nextTopLevelKey);
}

function composeVariable(expression: string): string {
	return ["$", `{${expression}}`].join("");
}

describe("Browser trust-domain Docker topology", () => {
	it("pins Camoufox package install and runs the canary in the browser image", () => {
		const dockerfile = readDockerFile("docker/Dockerfile.browser");
		const canary = readDockerFile("docker/browser-canary.py");
		const camoufoxVersionArg = ["$", "{CAMOUFOX_VERSION}"].join("");
		const playwrightVersionArg = ["$", "{PLAYWRIGHT_VERSION}"].join("");

		expect(dockerfile).toContain("ARG CAMOUFOX_VERSION=0.4.11");
		expect(dockerfile).toContain("ARG PLAYWRIGHT_VERSION=1.60.0");
		expect(dockerfile).toContain(`"playwright==${playwrightVersionArg}"`);
		expect(dockerfile).toContain(`"camoufox[geoip]==${camoufoxVersionArg}"`);
		expect(dockerfile).toContain("python -m camoufox fetch");
		expect(dockerfile).toContain("telclaude-browser-canary.py");
		expect(dockerfile).toContain('"--serve"');
		expect(canary).toContain("from camoufox.server import launch_server");
		expect(canary).toContain("playwright.firefox.connect");
		expect(canary).toContain('DEFAULT_WS_PATH = "/playwright"');
		expect(dockerfile).not.toContain("TELCLAUDE_VAULT_SOCKET");
		expect(dockerfile).not.toContain("OPENAI_API_KEY");
	});

	it("keeps tc-browser on an internal relay-only network with proxy egress", () => {
		const compose = readDockerFile("docker/docker-compose.browser.yml");
		const relay = serviceBlock(compose, "telclaude");
		const browser = serviceBlock(compose, "tc-browser");
		const relayNetworks = networksSection(relay);
		const browserNetworks = networksSection(browser);
		const browserNetwork = networkBlock(compose, "relay-browser-net");
		const browserIp = composeVariable("TELCLAUDE_BROWSER_IP:-172.30.94.11");

		expect(relay).toContain("TELCLAUDE_BROWSER_CONNECT_PROXY_ENABLED=1");
		expect(relay).toContain("TELCLAUDE_BROWSER_CONNECT_PROXY_REQUIRE_CONTEXT=");
		expect(relay).toContain("TELCLAUDE_BROWSER_CONTEXT_TOKEN_SECRET=");
		expect(relay).toContain("TELCLAUDE_BROWSER_WS_ENDPOINT=ws://tc-browser:");
		expect(relay).toContain(`TELCLAUDE_BROWSER_PEER_ADDRESS=${browserIp}`);
		expect(relayNetworks).toContain("relay-browser-net:");
		expect(relayNetworks).toContain(
			`ipv4_address: ${composeVariable("TELCLAUDE_BROWSER_RELAY_IP:-172.30.94.10")}`,
		);

		expect(browser).toContain("docker/Dockerfile.browser");
		expect(browser).toContain("PLAYWRIGHT_VERSION:");
		expect(browser).toContain(composeVariable("TELCLAUDE_BROWSER_PLAYWRIGHT_VERSION:-1.60.0"));
		expect(browser).toContain("telclaude-browser:camoufox-0.4.11-pw-1.60.0");
		expect(browser).toContain(
			`TELCLAUDE_BROWSER_PORT=${composeVariable("TELCLAUDE_BROWSER_PORT:-3006")}`,
		);
		expect(browser).toContain(
			`TELCLAUDE_BROWSER_INTERNAL_PORT=${composeVariable("TELCLAUDE_BROWSER_INTERNAL_PORT:-3106")}`,
		);
		expect(browser).toContain(
			`TELCLAUDE_BROWSER_WS_PATH=${composeVariable("TELCLAUDE_BROWSER_WS_PATH:-/playwright")}`,
		);
		expect(browser).toContain("TELCLAUDE_BROWSER_WS_ENDPOINT=ws://tc-browser:");
		expect(browser).toContain("TELCLAUDE_BROWSER_CONNECT_PROXY_URL=http://telclaude:");
		expect(browser).not.toContain("HTTP_PROXY=http://telclaude:");
		expect(browser).not.toContain("HTTPS_PROXY=http://telclaude:");
		expect(browser).toContain("cap_drop:");
		expect(browser).toContain("- ALL");
		expect(browser).toContain("read_only: true");
		expect(browser).toContain("no-new-privileges:true");
		expect(browserNetworks).toContain("relay-browser-net:");
		expect(browserNetworks).toContain(`ipv4_address: ${browserIp}`);
		for (const forbidden of [
			"relay-egress",
			"relay-vault-net",
			"relay-google-net",
			"relay-whatsapp-net",
			"relay-totp-net",
			"google-egress",
			"vault-egress",
			"whatsapp-egress",
		]) {
			expect(browserNetworks).not.toContain(`- ${forbidden}`);
		}
		for (const forbiddenEnv of [
			"TELCLAUDE_VAULT_SOCKET",
			"OPENAI_API_KEY",
			"ANTHROPIC_API_KEY",
			"TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN",
			"TELCLAUDE_WHATSAPP_BRIDGE_SECRET",
		]) {
			expect(browser).not.toContain(forbiddenEnv);
		}
		expect(compose).toContain("BrowserServer endpoint itself has no");
		expect(browserNetwork).toContain("name: telclaude-relay-browser");
		expect(browserNetwork).toContain("internal: true");
		expect(browserNetwork).toContain(
			`subnet: ${composeVariable("TELCLAUDE_BROWSER_SUBNET:-172.30.94.0/24")}`,
		);
	});
});
