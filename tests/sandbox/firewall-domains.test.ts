import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
	FIREWALL_WILDCARD_EXPANSIONS,
	getFirewallAllowedDomains,
	renderFirewallAllowedDomainsShellScript,
} from "../../src/sandbox/firewall-domains.js";
import { DEFAULT_ALLOWED_DOMAIN_NAMES } from "../../src/sandbox/domains.js";

const initFirewallPath = path.resolve("docker/init-firewall.sh");

function extractShellFunction(source: string, name: string): string {
	const match = source.match(new RegExp(`${name}\\(\\) \\{[\\s\\S]*?\\n\\}`));
	if (!match) throw new Error(`Missing shell function: ${name}`);
	return match[0];
}

function runShellHarness(script: string, args: string[]): string[] {
	const output = execFileSync("bash", ["-c", script, "firewall-domain-harness", ...args], {
		encoding: "utf8",
	});
	return output
		.split("\n")
		.map((line) => line.trim())
		.filter(Boolean);
}

function extractComposeService(source: string, serviceName: string): string {
	const lines = source.split("\n");
	const start = lines.findIndex((line) => line === `  ${serviceName}:`);
	if (start < 0) throw new Error(`Missing compose service: ${serviceName}`);
	const end = lines.findIndex(
		(line, index) =>
			index > start &&
			(line === "volumes:" || line === "networks:" || /^  [a-zA-Z0-9_-]+:$/.test(line)),
	);
	return lines.slice(start, end < 0 ? undefined : end).join("\n");
}

describe("firewall domain generation", () => {
	it("keeps exact sandbox domains in the generated firewall allowlist", () => {
		const allowlist = new Set(getFirewallAllowedDomains());
		for (const domain of DEFAULT_ALLOWED_DOMAIN_NAMES.filter((entry) => !entry.startsWith("*."))) {
			expect(allowlist.has(domain)).toBe(true);
		}
	});

	it("expands every wildcard sandbox domain explicitly for the shell firewall", () => {
		const allowlist = new Set(getFirewallAllowedDomains());
		for (const wildcard of DEFAULT_ALLOWED_DOMAIN_NAMES.filter((entry) => entry.startsWith("*."))) {
			const expansions = FIREWALL_WILDCARD_EXPANSIONS[wildcard];
			expect(expansions?.length ?? 0).toBeGreaterThan(0);
			for (const domain of expansions ?? []) {
				expect(allowlist.has(domain)).toBe(true);
			}
		}
	});

	it("matches the checked-in generated shell fragment", () => {
		const generatedPath = path.resolve("docker/allowed-domains.generated.sh");
		const actual = fs.readFileSync(generatedPath, "utf8");
		expect(actual).toBe(renderFirewallAllowedDomainsShellScript());
	});

	it("lets the Docker firewall consume configured additional domains", () => {
		const initScript = fs.readFileSync(initFirewallPath, "utf8");
		expect(initScript).toContain("security?.network?.additionalDomains");
		expect(initScript).toContain("append_allowed_domain");
		expect(initScript).toContain('ALLOWED_DOMAINS+=("$normalized")');
	});

	it("keeps additional-domain controls on the relay/Hermes paths", () => {
		const initScript = fs.readFileSync(initFirewallPath, "utf8");
		expect(initScript).toContain("TELCLAUDE_FIREWALL_SKIP_ADDITIONAL_DOMAINS");

		const hermesCompose = fs.readFileSync(path.resolve("docker/docker-compose.hermes.yml"), "utf8");
		expect(extractComposeService(hermesCompose, "tc-hermes-contained")).toContain(
			"TELCLAUDE_FIREWALL_SKIP_ADDITIONAL_DOMAINS=1",
		);
		expect(extractComposeService(hermesCompose, "tc-hermes-social")).toContain(
			"TELCLAUDE_FIREWALL_SKIP_ADDITIONAL_DOMAINS=1",
		);
	});

	it("validates additional firewall domains before appending them", () => {
		const initScript = fs.readFileSync(initFirewallPath, "utf8");
		const harness = [
			"set -eu",
			'ALLOWED_DOMAINS=("api.openai.com")',
			extractShellFunction(initScript, "append_allowed_domain"),
			'for domain in "$@"; do append_allowed_domain "$domain"; done',
			'printf "%s\\n" "${ALLOWED_DOMAINS[@]}"',
		].join("\n");

		const lines = runShellHarness(harness, [
			" ChatGPT.COM ",
			"chatgpt.com",
			"api.openai.com",
			"*.evil.com",
			"a;rm -rf /",
			"host:443",
			"example..com",
			".hidden.example",
			"bad_domain.example",
		]);

		expect(lines.filter((line) => !line.startsWith("[firewall] WARNING"))).toEqual([
			"api.openai.com",
			"chatgpt.com",
		]);
		expect(lines.filter((line) => line.startsWith("[firewall] WARNING"))).toHaveLength(6);
	});

	it("keeps private and metadata IP literals out of firewall domain accepts", () => {
		const initScript = fs.readFileSync(initFirewallPath, "utf8");
		const harness = [
			"set -eu",
			'BLOCKED_METADATA_IPS=("169.254.169.254" "169.254.170.2" "100.100.100.200")',
			extractShellFunction(initScript, "is_public_ip"),
			'for ip in "$@"; do',
			'  if is_public_ip "$ip"; then printf "%s:public\\n" "$ip"; else printf "%s:blocked\\n" "$ip"; fi',
			"done",
		].join("\n");

		expect(
			runShellHarness(harness, [
				"169.254.169.254",
				"169.254.170.2",
				"100.100.100.200",
				"10.0.0.1",
				"172.16.0.1",
				"192.168.1.1",
				"100.64.0.1",
				"104.18.32.47",
			]),
		).toEqual([
			"169.254.169.254:blocked",
			"169.254.170.2:blocked",
			"100.100.100.200:blocked",
			"10.0.0.1:blocked",
			"172.16.0.1:blocked",
			"192.168.1.1:blocked",
			"100.64.0.1:blocked",
			"104.18.32.47:public",
		]);
	});
});
