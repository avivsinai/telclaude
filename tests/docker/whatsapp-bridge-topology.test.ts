import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const repoRoot = path.resolve(import.meta.dirname, "../..");
const whatsappSidecarUrlEnv =
	"TELCLAUDE_WHATSAPP_SIDECAR_URL=$" + "{TELCLAUDE_WHATSAPP_SIDECAR_URL:-}";
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

describe("WhatsApp bridge Docker topology", () => {
	it.each([
		"docker/docker-compose.yml",
		"docker/docker-compose.deploy.yml",
	])("keeps %s on a dedicated relay-to-bridge network", (relativePath) => {
		const compose = readDockerFile(relativePath);
		const relay = serviceBlock(compose, "telclaude");
		const whatsappNetwork = networkBlock(compose, "relay-whatsapp-net");

		expect(relay).toContain("TELCLAUDE_INTERNAL_HOSTS=${TELCLAUDE_INTERNAL_HOSTS:-telclaude");
		expect(relay).toContain(whatsappSidecarUrlEnv);
		expect(relay).toContain("- relay-whatsapp-net");
		expect(whatsappNetwork).toContain("name: telclaude-relay-whatsapp");
		expect(whatsappNetwork).toContain("internal: true");
		expect(relay?.match(internalHostsEnvPattern)?.[1]).not.toContain("whatsapp-bridge");

		for (const service of ["google-services", "totp", "vault"]) {
			expect(serviceBlock(compose, service) ?? "").not.toContain("- relay-whatsapp-net");
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
