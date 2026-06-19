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
		const packageInstallIndex = dockerfile.indexOf("python -m pip install");
		const runtimeUserIndex = dockerfile.indexOf("\nUSER browser");

		expect(dockerfile).toContain("ARG CAMOUFOX_VERSION=0.4.11");
		expect(dockerfile).toContain("ARG PLAYWRIGHT_VERSION=1.59.0");
		expect(dockerfile).toContain("ENV PYTHONNOUSERSITE=1");
		expect(dockerfile).toContain("ENV XDG_CACHE_HOME=/opt/camoufox-cache");
		expect(packageInstallIndex).toBeGreaterThan(-1);
		expect(runtimeUserIndex).toBeGreaterThan(-1);
		expect(packageInstallIndex).toBeLessThan(runtimeUserIndex);
		expect(dockerfile).toContain(`"playwright==${playwrightVersionArg}"`);
		expect(dockerfile).toContain(`"camoufox[geoip]==${camoufoxVersionArg}"`);
		expect(dockerfile).toContain("python -m camoufox fetch");
		expect(dockerfile).toContain("telclaude-browser-canary.py");
		expect(dockerfile).toContain('"--serve"');
		expect(canary).toContain("from camoufox.utils import launch_options");
		expect(canary).toContain('LOCAL_DATA / "launchServer.js"');
		expect(canary).toContain("strip_none_values(config)");
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
		const browserPeerAddress = composeVariable(
			"TELCLAUDE_BROWSER_IP:?set tc-browser static container IP for context token binding",
		);
		const browserNetworkIp = composeVariable(
			"TELCLAUDE_BROWSER_IP:?set tc-browser static container IP on relay-browser-net",
		);

		expect(relay).toContain("TELCLAUDE_BROWSER_CONNECT_PROXY_ENABLED=1");
		expect(relay).toContain("TELCLAUDE_BROWSER_CONNECT_PROXY_REQUIRE_CONTEXT=");
		expect(relay).toContain("TELCLAUDE_BROWSER_CONTEXT_TOKEN_SECRET=");
		expect(relay).toContain("TELCLAUDE_BROWSER_WS_ENDPOINT=ws://tc-browser:");
		expect(relay).toContain(`TELCLAUDE_BROWSER_PEER_ADDRESS=${browserPeerAddress}`);
		expect(relay).toContain(
			"TELCLAUDE_INTERNAL_HOSTS=${TELCLAUDE_INTERNAL_HOSTS:-telclaude,google-services,tc-hermes-contained,tc-hermes-social,tc-browser}",
		);
		expect(relay).toContain("tc-browser:");
		expect(relay).toContain("condition: service_healthy");
		expect(relayNetworks).toContain("relay-browser-net:");
		expect(relayNetworks).toContain(
			`ipv4_address: ${composeVariable(
				"TELCLAUDE_BROWSER_RELAY_IP:?set relay static container IP on relay-browser-net",
			)}`,
		);

		expect(browser).toContain("docker/Dockerfile.browser");
		expect(browser).not.toContain("depends_on:");
		expect(browser).toContain("PLAYWRIGHT_VERSION:");
		expect(browser).toContain(composeVariable("TELCLAUDE_BROWSER_PLAYWRIGHT_VERSION:-1.59.0"));
		expect(browser).toContain("telclaude-browser:camoufox-0.4.11-pw-1.59.0");
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
		expect(browserNetworks).toContain(`ipv4_address: ${browserNetworkIp}`);
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
			expect(browserNetworks).not.toMatch(new RegExp(`(^|\\n)\\s*${forbidden}:`));
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
			`subnet: ${composeVariable(
				"TELCLAUDE_BROWSER_SUBNET:?set relay-browser subnet containing relay and tc-browser IPs",
			)}`,
		);
	});

	it("keeps firewall refresh rebuilding internal browser rules in permissive mode", () => {
		const firewall = readDockerFile("docker/init-firewall.sh");
		const refreshStart = firewall.indexOf("refresh_firewall() {");
		expect(refreshStart).toBeGreaterThan(-1);
		const refreshBody = firewall.slice(refreshStart, firewall.indexOf("\n# ─", refreshStart + 1));
		const internalIndex = refreshBody.indexOf("[firewall-refresh] checking internal hosts");
		const privateEndpointIndex = refreshBody.indexOf("re-added private endpoint rules");
		const permissiveIndex = refreshBody.indexOf("TELCLAUDE_NETWORK_MODE=$NETWORK_MODE");
		const domainIndex = refreshBody.indexOf("[firewall-refresh] checking allowed domains");

		expect(refreshBody).toContain("iptables -F TELCLAUDE_ALLOW");
		expect(internalIndex).toBeGreaterThan(-1);
		expect(privateEndpointIndex).toBeGreaterThan(-1);
		expect(permissiveIndex).toBeGreaterThan(-1);
		expect(domainIndex).toBeGreaterThan(-1);
		expect(internalIndex).toBeLessThan(permissiveIndex);
		expect(privateEndpointIndex).toBeLessThan(permissiveIndex);
		expect(permissiveIndex).toBeLessThan(domainIndex);
		expect(refreshBody).not.toContain("skipping refresh (permissive mode - no domain allowlist)");
	});

	it("keeps production deploys on the browser overlay and restarts the relay after tc-browser is ready", () => {
		const workflow = readDockerFile(".github/workflows/ci.yml");
		const deployStart = workflow.indexOf("  deploy:");
		expect(deployStart).toBeGreaterThan(-1);
		const deployJob = workflow.slice(deployStart);
		const browserComposeIndex = deployJob.indexOf("-f docker-compose.browser.yml");
		const browserUpIndex = deployJob.indexOf("up -d --remove-orphans tc-browser");
		const waitBrowserIndex = deployJob.indexOf("wait_for_container_ready tc-browser 180");
		const stackUpIndex = deployJob.indexOf("up -d --remove-orphans\n");
		const restartIndex = deployJob.indexOf("docker restart telclaude");
		const waitRelayIndex = deployJob.indexOf("wait_for_container_ready telclaude 180");
		const fullWaitIndex = deployJob.indexOf("up -d --remove-orphans --wait --wait-timeout 480");

		expect(browserComposeIndex).toBeGreaterThan(-1);
		expect(browserUpIndex).toBeGreaterThan(-1);
		expect(waitBrowserIndex).toBeGreaterThan(browserUpIndex);
		expect(stackUpIndex).toBeGreaterThan(waitBrowserIndex);
		expect(restartIndex).toBeGreaterThan(stackUpIndex);
		expect(waitRelayIndex).toBeGreaterThan(restartIndex);
		expect(fullWaitIndex).toBeGreaterThan(waitRelayIndex);
		expect(browserComposeIndex).toBeLessThan(browserUpIndex);
		expect(deployJob).toContain("tc-browser");
		expect(deployJob).toContain("telclaude-relay-browser");
		expect(deployJob).toContain("docker_browser-net");
	});

	it("redacts post-deploy health-gate diagnostics", () => {
		const workflow = readDockerFile(".github/workflows/ci.yml");
		const hookStart = workflow.indexOf("Install William post-deploy health gate");
		const nextStep = workflow.indexOf("Ensure William reminder capability scopes", hookStart);
		expect(hookStart).toBeGreaterThan(-1);
		expect(nextStep).toBeGreaterThan(hookStart);
		const hookStep = workflow.slice(hookStart, nextStep);

		expect(hookStep).toContain("redact_deploy_logs() {");
		expect(hookStep).toContain(
			'docker compose "${compose_files[@]}" "${compose_profiles[@]}" ps 2>&1 | redact_deploy_logs || true',
		);
		expect(hookStep).toContain(
			"docker inspect --format '{{json .State}}' \"$container\" 2>&1 | redact_deploy_logs || true",
		);
		expect(hookStep).toContain(
			'docker logs --tail=120 "$container" 2>&1 | redact_deploy_logs || true',
		);
	});

	it("persists required William browser network and session-cookie deploy settings", () => {
		const workflow = readDockerFile(".github/workflows/ci.yml");
		const persistStart = workflow.indexOf("Persist William Hermes deploy keys");
		const installHookStart = workflow.indexOf("Install William post-deploy health gate");
		expect(persistStart).toBeGreaterThan(-1);
		expect(installHookStart).toBeGreaterThan(persistStart);
		const persistStep = workflow.slice(persistStart, installHookStart);
		const readDeployEnvStart = persistStep.indexOf("read_deploy_env() {");
		const readDeployEnv = persistStep.slice(
			readDeployEnvStart,
			persistStep.indexOf("\n          }", readDeployEnvStart) + "\n          }".length,
		);
		expect(readDeployEnv).toContain('for file in "$compose_env_file" "$shell_env_file"; do');
		expect(persistStep).toContain("normalize_internal_hosts() {");
		expect(persistStep).toContain(
			"required_internal_hosts='telclaude,google-services,tc-hermes-contained,tc-hermes-social,tc-browser'",
		);
		expect(persistStep).toContain(
			'internal_hosts="$(read_deploy_env TELCLAUDE_INTERNAL_HOSTS || true)"',
		);
		expect(persistStep).toContain(
			'internal_hosts="$(normalize_internal_hosts "$internal_hosts" "$required_internal_hosts")"',
		);
		expect(persistStep).toContain(
			'printf \'TELCLAUDE_INTERNAL_HOSTS=%s\\n\' "$internal_hosts" >> "$GITHUB_ENV"',
		);
		expect(persistStep).toContain(
			"printf 'export TELCLAUDE_INTERNAL_HOSTS=%q\\n' \"$internal_hosts\"",
		);
		expect(persistStep).toContain("printf 'TELCLAUDE_INTERNAL_HOSTS=%s\\n' \"$internal_hosts\"");

		for (const [key, variable] of [
			["TELCLAUDE_BROWSER_CONTEXT_TOKEN_SECRET", "browser_context_token"],
			["TELCLAUDE_BROWSER_COOKIE_STORE_KEY", "browser_cookie_store_key"],
			["TELCLAUDE_BROWSER_CATASTROPHIC_DOMAINS", "browser_catastrophic_domains"],
			["TELCLAUDE_BROWSER_SUBNET", "browser_subnet"],
			["TELCLAUDE_BROWSER_RELAY_IP", "browser_relay_ip"],
			["TELCLAUDE_BROWSER_IP", "browser_ip"],
		] as const) {
			expect(persistStep).toContain(key);
			expect(persistStep).toContain(`${variable}="$(read_deploy_env ${key} || true)"`);
			expect(persistStep).toContain(`printf 'export ${key}=`);
			expect(persistStep).toContain(`printf '${key}=`);
		}
		for (const variable of ["browser_context_token", "browser_cookie_store_key"]) {
			expect(persistStep).toContain(
				`[ -n "$${variable}" ] || ${variable}="$(openssl rand -base64 48 | tr '+/' '-_' | tr -d '=')"`,
			);
		}
		expect(persistStep).not.toContain(
			`[ -n "$browser_catastrophic_domains" ] || browser_catastrophic_domains=`,
		);
	});
});
