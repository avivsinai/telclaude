export const GOOGLE_APPROVAL_SIGNING_PREFIX = "approval-v1";
export const CURATOR_PRODUCER_SIGNING_PREFIX = "curator-producer-v1";

export const TELCLAUDE_MCP_PROVIDER_APPROVAL_DOMAIN =
	"telclaude.hermes.mcp.side-effect.provider.approval.v1";
export const TELCLAUDE_MCP_OUTBOUND_APPROVAL_DOMAIN =
	"telclaude.hermes.mcp.side-effect.outbound.approval.v1";
export const TELCLAUDE_MCP_BROWSER_WRITE_APPROVAL_DOMAIN =
	"telclaude.hermes.mcp.side-effect.browser-write.approval.v1";

export const GENERIC_PAYLOAD_SIGNING_PREFIXES = [
	GOOGLE_APPROVAL_SIGNING_PREFIX,
	CURATOR_PRODUCER_SIGNING_PREFIX,
	TELCLAUDE_MCP_PROVIDER_APPROVAL_DOMAIN,
	TELCLAUDE_MCP_OUTBOUND_APPROVAL_DOMAIN,
	TELCLAUDE_MCP_BROWSER_WRITE_APPROVAL_DOMAIN,
] as const;

export type GenericPayloadSigningPrefix = (typeof GENERIC_PAYLOAD_SIGNING_PREFIXES)[number];

export function isGenericPayloadSigningPrefix(
	prefix: string,
): prefix is GenericPayloadSigningPrefix {
	return (GENERIC_PAYLOAD_SIGNING_PREFIXES as readonly string[]).includes(prefix);
}
