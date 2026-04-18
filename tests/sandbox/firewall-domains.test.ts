import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
	FIREWALL_WILDCARD_EXPANSIONS,
	getFirewallAllowedDomains,
	renderFirewallAllowedDomainsShellScript,
} from "../../src/sandbox/firewall-domains.js";
import { DEFAULT_ALLOWED_DOMAIN_NAMES } from "../../src/sandbox/domains.js";

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
});
