import { z } from "zod";

export const SERVED_MCP_CONTAINMENT_SCHEMA_VERSION = "telclaude.hermes.served-mcp-containment.v1";

export const SERVED_MCP_REQUIRED_PROPERTY_NAMES = [
	"positive_initialize_tools_only",
	"positive_tools_list_exact",
	"positive_resources_empty",
	"positive_prompts_empty",
	"positive_roots_empty",
	"sampling_disabled",
	"handle_forgery_denied",
	"wrong_connection_denied",
	"off_domain_peer_denied",
	"cross_domain_memory_denied",
	"out_of_scope_provider_denied",
	"out_of_scope_outbound_denied",
	"provider_execute_without_ledger_denied",
	"outbound_execute_without_ledger_denied",
	"malformed_json_denied",
	"unauthenticated_denied",
	"batch_denied",
	"prototype_key_denied",
	"artifact_redacted",
] as const;

export type ServedMcpPropertyName = (typeof SERVED_MCP_REQUIRED_PROPERTY_NAMES)[number];

const NonEmptyString = z.string().trim().min(1);
const ServedMcpPropertyNameSchema = z.enum(SERVED_MCP_REQUIRED_PROPERTY_NAMES);

const ServedMcpPropertiesSchema = z
	.object({
		positive_initialize_tools_only: z.boolean().optional(),
		positive_tools_list_exact: z.boolean().optional(),
		positive_resources_empty: z.boolean().optional(),
		positive_prompts_empty: z.boolean().optional(),
		positive_roots_empty: z.boolean().optional(),
		sampling_disabled: z.boolean().optional(),
		handle_forgery_denied: z.boolean().optional(),
		wrong_connection_denied: z.boolean().optional(),
		off_domain_peer_denied: z.boolean().optional(),
		cross_domain_memory_denied: z.boolean().optional(),
		out_of_scope_provider_denied: z.boolean().optional(),
		out_of_scope_outbound_denied: z.boolean().optional(),
		provider_execute_without_ledger_denied: z.boolean().optional(),
		outbound_execute_without_ledger_denied: z.boolean().optional(),
		malformed_json_denied: z.boolean().optional(),
		unauthenticated_denied: z.boolean().optional(),
		batch_denied: z.boolean().optional(),
		prototype_key_denied: z.boolean().optional(),
		artifact_redacted: z.boolean().optional(),
	})
	.strict();

const ServedMcpCheckSchema = z
	.object({
		name: ServedMcpPropertyNameSchema,
		status: z.enum(["pass", "fail"]),
		detail: NonEmptyString,
		httpStatus: z.number().int().nonnegative().optional(),
		rpcErrorCode: z.number().int().optional(),
		rpcErrorMessage: NonEmptyString.optional(),
	})
	.strict();

const ServedMcpOriginSchema = z
	.object({
		kind: z.enum(["contained-peer", "relay-self-smoke", "unknown"]),
		containerName: NonEmptyString.optional(),
		observedPeerAddress: NonEmptyString.optional(),
		observedPeerSource: z.literal("server-peer-echo").optional(),
		expectedPeerAddress: NonEmptyString.optional(),
		expectedPeerSource: z.literal("configured-contained-ip").optional(),
		detail: NonEmptyString,
	})
	.strict();

const ServedMcpNegativeControlsSchema = z
	.object({
		forgedAuthorityDenied: z.boolean().optional(),
		wrongConnectionDenied: z.boolean().optional(),
		offDomainPeerDenied: z.boolean().optional(),
	})
	.strict();

export const ServedMcpContainmentEvidenceSchema = z
	.object({
		schemaVersion: z.literal(SERVED_MCP_CONTAINMENT_SCHEMA_VERSION),
		probeId: z.literal("execution.served_mcp_containment"),
		status: z.enum(["pass", "fail", "pending"]),
		ran: z.boolean(),
		generatedAt: NonEmptyString,
		summary: NonEmptyString,
		endpoint: z
			.object({
				transport: z.literal("http"),
				target: z.literal("redacted-http-mcp-endpoint"),
			})
			.strict(),
		placement: z
			.object({
				loadBearing: z.literal(false),
				detail: NonEmptyString,
			})
			.strict(),
		origin: ServedMcpOriginSchema,
		negativeControls: ServedMcpNegativeControlsSchema,
		properties: ServedMcpPropertiesSchema,
		checks: z.array(ServedMcpCheckSchema),
	})
	.strict();

export type ServedMcpContainmentEvidence = z.infer<typeof ServedMcpContainmentEvidenceSchema>;
export type ServedMcpContainmentCheck = ServedMcpContainmentEvidence["checks"][number];
