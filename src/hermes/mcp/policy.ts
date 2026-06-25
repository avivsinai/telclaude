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
	"tc_web_fetch",
	"tc_web_search",
	"tc_image_generate",
	"tc_tts",
	"tc_skill_request",
	"tc_schedule_create",
	"tc_schedule_list",
	"tc_schedule_cancel",
	"tc_browse",
	"tc_browse_act",
	"tc_browse_act_prepare",
	"tc_browse_act_execute",
	"tc_github_list_repos",
	"tc_github_list_refs",
	"tc_github_get_tree",
	"tc_github_read_file",
] as const;

export type TelclaudeMcpToolName = (typeof TELCLAUDE_MCP_TOOL_NAMES)[number];

/**
 * Capability-scoped tools require their scope on the resolved authority's
 * `capabilityScopes`. An authority without the scope (or without any
 * capabilityScopes at all, e.g. the verify-live canary) is denied — fail-closed.
 */
export const TELCLAUDE_MCP_TOOL_CAPABILITY_SCOPES = {
	tc_web_fetch: "web.fetch",
	tc_web_search: "web.search",
	tc_image_generate: "media.image",
	tc_tts: "media.tts",
	tc_skill_request: "skills.request",
	tc_schedule_create: "schedule.write",
	tc_schedule_list: "schedule.read",
	tc_schedule_cancel: "schedule.write",
	tc_browse: "browse.use",
	// Interactive browser acts (fill/type inline on cookie-less pages, plus the
	// committing two-phase prepare/execute for everything else) require a SEPARATE,
	// stronger scope
	// than read-only browsing — an authority granted browse.use is not implicitly
	// allowed to drive interactive writes. Fail-closed: no browse.act, no act.
	tc_browse_act: "browse.act",
	tc_browse_act_prepare: "browse.act",
	tc_browse_act_execute: "browse.act",
	// Read-only GitHub repository access via the relay-owned App installation token.
	// One scope for the whole read family; fail-closed without it.
	tc_github_list_repos: "github.read",
	tc_github_list_refs: "github.read",
	tc_github_get_tree: "github.read",
	tc_github_read_file: "github.read",
} as const satisfies Partial<Record<TelclaudeMcpToolName, string>>;

export type TelclaudeMcpCapabilityScope =
	(typeof TELCLAUDE_MCP_TOOL_CAPABILITY_SCOPES)[keyof typeof TELCLAUDE_MCP_TOOL_CAPABILITY_SCOPES];

export const TELCLAUDE_MCP_ALL_CAPABILITY_SCOPES: readonly TelclaudeMcpCapabilityScope[] =
	Object.values(TELCLAUDE_MCP_TOOL_CAPABILITY_SCOPES);

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
