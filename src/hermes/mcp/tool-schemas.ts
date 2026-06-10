import type { TelclaudeMcpToolName } from "./policy.js";

export type TelclaudeMcpToolDefinition = {
	readonly name: TelclaudeMcpToolName;
	readonly description: string;
	readonly inputSchema: Record<string, unknown>;
};

const JsonObjectSchema = {
	type: "object",
	additionalProperties: true,
} as const;

const NonEmptyStringSchema = {
	type: "string",
	minLength: 1,
} as const;

const RefSchema = {
	type: "string",
	minLength: 1,
	maxLength: 256,
} as const;

export const TELCLAUDE_MCP_TOOL_DEFINITIONS: readonly TelclaudeMcpToolDefinition[] = [
	{
		name: "tc_provider_read",
		description:
			"Read from a granted Telclaude provider scope through the relay-owned served-provider channel.",
		inputSchema: objectSchema(
			{
				providerId: NonEmptyStringSchema,
				service: NonEmptyStringSchema,
				action: NonEmptyStringSchema,
				params: JsonObjectSchema,
			},
			["service", "action"],
		),
	},
	{
		name: "tc_provider_prepare_write",
		description:
			"Prepare a provider write through the signed Telclaude side-effect ledger before human approval.",
		inputSchema: objectSchema(
			{
				providerId: NonEmptyStringSchema,
				service: NonEmptyStringSchema,
				action: NonEmptyStringSchema,
				params: JsonObjectSchema,
				idempotencyKey: {
					type: "string",
					minLength: 1,
					maxLength: 128,
				},
			},
			["service", "action"],
		),
	},
	{
		name: "tc_provider_execute_write",
		description:
			"Execute a previously prepared and approved provider write by side-effect action reference.",
		inputSchema: objectSchema(
			{
				actionRef: RefSchema,
			},
			["actionRef"],
			false,
		),
	},
	{
		name: "tc_memory_search",
		description:
			"Search memory in the relay-stamped memory source for the current Telclaude authority.",
		inputSchema: objectSchema(
			{
				query: NonEmptyStringSchema,
				filters: JsonObjectSchema,
				limit: {
					type: "integer",
					minimum: 1,
					maximum: 20,
				},
			},
			["query"],
		),
	},
	{
		name: "tc_memory_write",
		description:
			"Write memory to the relay-stamped writable namespace for the current Telclaude authority.",
		inputSchema: objectSchema(
			{
				id: {
					type: "string",
					minLength: 1,
					maxLength: 128,
				},
				category: {
					type: "string",
					enum: ["profile", "interests", "threads", "posts", "meta"],
				},
				content: NonEmptyStringSchema,
				metadata: JsonObjectSchema,
				provenance: JsonObjectSchema,
			},
			["id", "category", "content"],
		),
	},
	{
		name: "tc_attachment_get",
		description:
			"Read a relay-authorized attachment by reference without exposing direct provider or filesystem access.",
		inputSchema: objectSchema(
			{
				ref: RefSchema,
			},
			["ref"],
			false,
		),
	},
	{
		name: "tc_outbound_prepare",
		description:
			"Prepare an outbound reply or message through the relay edge channel before human approval.",
		inputSchema: objectSchema(
			{
				conversationToken: RefSchema,
				replyIntent: {
					oneOf: [
						objectSchema({ kind: { const: "thread" }, threadId: RefSchema }, ["kind", "threadId"]),
						objectSchema({ kind: { const: "actor" }, actorId: RefSchema }, ["kind", "actorId"]),
						objectSchema({ kind: { const: "address" }, addressRef: RefSchema }, [
							"kind",
							"addressRef",
						]),
					],
				},
				body: NonEmptyStringSchema,
				mediaRefs: {
					type: "array",
					items: RefSchema,
					maxItems: 10,
				},
			},
			["conversationToken", "body"],
			false,
		),
	},
	{
		name: "tc_outbound_execute",
		description:
			"Execute a previously prepared and approved outbound delivery by side-effect outbound reference.",
		inputSchema: objectSchema(
			{
				outboundRef: RefSchema,
			},
			["outboundRef"],
			false,
		),
	},
	{
		name: "tc_audit_note",
		description: "Append a relay-side audit note associated with the current Telclaude authority.",
		inputSchema: objectSchema(
			{
				kind: {
					type: "string",
					minLength: 1,
					maxLength: 128,
				},
				payload: JsonObjectSchema,
			},
			["kind"],
		),
	},
] as const;

export function telclaudeMcpToolDefinitions(): readonly TelclaudeMcpToolDefinition[] {
	return TELCLAUDE_MCP_TOOL_DEFINITIONS;
}

function objectSchema(
	properties: Record<string, unknown>,
	required: readonly string[] = [],
	additionalProperties = true,
): Record<string, unknown> {
	return {
		type: "object",
		properties,
		required: [...required],
		additionalProperties,
	};
}
