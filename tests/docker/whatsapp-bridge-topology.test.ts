import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const repoRoot = path.resolve(import.meta.dirname, "../..");
const whatsappSidecarUrlEnv =
	"TELCLAUDE_WHATSAPP_SIDECAR_URL=$" +
	"{TELCLAUDE_WHATSAPP_SIDECAR_URL:-http://whatsapp-bridge:3004}";
const whatsappAllowedRecipientsEnv =
	"TELCLAUDE_WHATSAPP_ALLOWED_RECIPIENTS=$" + "{TELCLAUDE_WHATSAPP_ALLOWED_RECIPIENTS:-}";
const whatsappBridgeSecretEnv =
	"TELCLAUDE_WHATSAPP_BRIDGE_SECRET=$" + "{TELCLAUDE_WHATSAPP_BRIDGE_SECRET:-}";
const internalHostsEnvPattern = /TELCLAUDE_INTERNAL_HOSTS=\$\{TELCLAUDE_INTERNAL_HOSTS:-([^}]*)\}/;

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
	const start = networks.indexOf(anchor);
	if (start < 0) return null;
	const rest = networks.slice(start + anchor.length);
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

describe("WhatsApp bridge Docker topology", () => {
	it.each([
		"docker/docker-compose.yml",
		"docker/docker-compose.deploy.yml",
	])("keeps %s on a dedicated relay-to-bridge network", (relativePath) => {
		const compose = readDockerFile(relativePath);
		const relay = serviceBlock(compose, "telclaude");
		const bridge = serviceBlock(compose, "whatsapp-bridge");
		const whatsappNetwork = networkBlock(compose, "relay-whatsapp-net");
		const whatsappEgressNetwork = networkBlock(compose, "whatsapp-egress");
		const relayNetworks = networksSection(relay);
		const bridgeNetworks = networksSection(bridge);

		expect(relay).toContain("TELCLAUDE_INTERNAL_HOSTS=${TELCLAUDE_INTERNAL_HOSTS:-telclaude");
		expect(relay).toContain(whatsappSidecarUrlEnv);
		expect(relay).toContain(whatsappBridgeSecretEnv);
		expect(relay).toContain(whatsappAllowedRecipientsEnv);
		expect(relayNetworks).toContain("- relay-whatsapp-net");
		expect(relayNetworks).not.toContain("- whatsapp-egress");
		expect(bridge).toContain('profiles: ["whatsapp"]');
		if (relativePath === "docker/docker-compose.yml") {
			expect(bridge).toContain("docker/Dockerfile.whatsapp-bridge");
		} else {
			expect(bridge).toContain("telclaude-whatsapp-bridge:latest");
		}
		expect(bridge).toContain("healthcheck:");
		expect(bridge).toContain("http://localhost:3004/health");
		expect(bridge).toContain(whatsappBridgeSecretEnv);
		expect(bridgeNetworks).toContain("- relay-whatsapp-net");
		expect(bridgeNetworks).toContain("- whatsapp-egress");
		expect(bridgeNetworks).not.toContain("- relay-egress");
		expect(bridgeNetworks).not.toContain("- relay-vault-net");
		expect(bridgeNetworks).not.toContain("- relay-totp-net");
		expect(bridgeNetworks).not.toContain("- relay-google-net");
		expect(bridge).not.toContain("TELCLAUDE_WHATSAPP_ALLOWED_RECIPIENTS");
		expect(whatsappNetwork).toContain("name: telclaude-relay-whatsapp");
		expect(whatsappNetwork).toContain("internal: true");
		expect(whatsappEgressNetwork).toContain("name: telclaude-whatsapp-egress");
		expect(whatsappEgressNetwork).not.toContain("internal: true");
		expect(relay?.match(internalHostsEnvPattern)?.[1]).not.toContain("whatsapp-bridge");

		for (const service of ["google-services", "totp", "vault"]) {
			expect(serviceBlock(compose, service) ?? "").not.toContain("- relay-whatsapp-net");
			expect(serviceBlock(compose, service) ?? "").not.toContain("- whatsapp-egress");
		}
	});

	it("auto-allows the configured WhatsApp bridge host in the firewall script", () => {
		const firewall = readDockerFile("docker/init-firewall.sh");

		expect(firewall).toContain("TELCLAUDE_WHATSAPP_SIDECAR_URL");
		expect(firewall).toContain("WHATSAPP_BRIDGE_HOST");
		expect(firewall).toContain('[ "$WHATSAPP_BRIDGE_HOST" = "whatsapp-bridge" ]');
		expect(firewall).toContain('append_internal_host "$WHATSAPP_BRIDGE_HOST"');
	});

	it("does not attach the Hermes live-run network to the WhatsApp bridge path", () => {
		const hermesCompose = readDockerFile("docker/docker-compose.hermes.yml");

		expect(hermesCompose).not.toContain("relay-whatsapp-net");
		expect(hermesCompose).not.toContain("whatsapp-bridge");
		expect(hermesCompose).toContain("telclaude-hermes-private");
	});
});
