import { describe, expect, it } from "vitest";
import {
	CURATOR_PRODUCER_SIGNING_PREFIX,
	GOOGLE_APPROVAL_SIGNING_PREFIX,
	isGenericPayloadSigningPrefix,
	TELCLAUDE_MCP_BROWSER_WRITE_APPROVAL_DOMAIN,
	TELCLAUDE_MCP_OUTBOUND_APPROVAL_DOMAIN,
	TELCLAUDE_MCP_PROVIDER_APPROVAL_DOMAIN,
	TELCLAUDE_MCP_SCHEDULED_OUTBOUND_APPROVAL_DOMAIN,
} from "../../src/security/approval-domains.js";

describe("generic payload signing-prefix classification", () => {
	it.each([
		[GOOGLE_APPROVAL_SIGNING_PREFIX, true],
		[CURATOR_PRODUCER_SIGNING_PREFIX, true],
		[TELCLAUDE_MCP_PROVIDER_APPROVAL_DOMAIN, true],
		[TELCLAUDE_MCP_OUTBOUND_APPROVAL_DOMAIN, true],
		[TELCLAUDE_MCP_BROWSER_WRITE_APPROVAL_DOMAIN, true],
		["telclaude.hermes.mcp.side-effect.unknown.approval.v1", false],
	] as const)("keeps the existing classification for %s", (prefix, expected) => {
		expect(isGenericPayloadSigningPrefix(prefix)).toBe(expected);
	});

	it("classifies the dedicated scheduled-outbound domain without reusing an existing domain", () => {
		expect(TELCLAUDE_MCP_SCHEDULED_OUTBOUND_APPROVAL_DOMAIN).toBe(
			"telclaude.hermes.mcp.side-effect.scheduled-outbound.approval.v1",
		);
		expect(isGenericPayloadSigningPrefix(TELCLAUDE_MCP_SCHEDULED_OUTBOUND_APPROVAL_DOMAIN)).toBe(
			true,
		);
		expect(TELCLAUDE_MCP_SCHEDULED_OUTBOUND_APPROVAL_DOMAIN).not.toBe(
			TELCLAUDE_MCP_OUTBOUND_APPROVAL_DOMAIN,
		);
	});
});
