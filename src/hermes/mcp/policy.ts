export const TELCLAUDE_MCP_TOOL_NAMES = [
	"tc_provider_read",
	"tc_provider_prepare_write",
	"tc_provider_execute_write",
	"tc_memory_search",
	"tc_memory_write",
	"tc_attachment_get",
	"tc_outbound_prepare",
	"tc_outbound_execute",
	"tc_audit_note",
] as const;

export type TelclaudeMcpToolName = (typeof TELCLAUDE_MCP_TOOL_NAMES)[number];

export const TELCLAUDE_MCP_SERVER_POLICY = {
	tools: TELCLAUDE_MCP_TOOL_NAMES,
	resources: [],
	prompts: [],
	roots: [],
	sampling: false,
	env: {},
	cwd: null,
	subprocess: false,
} as const;

export const TELCLAUDE_HERMES_MCP_SERVER_NAME = "telclaudeRelay";
export const TELCLAUDE_HERMES_MCP_URL = "http://telclaude:8793/mcp";
export const TELCLAUDE_HERMES_MCP_RELAY_TOKEN_ENV = "TELCLAUDE_HERMES_MCP_RELAY_TOKEN";
