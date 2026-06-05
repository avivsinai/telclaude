import { z } from "zod";

// Evidence schema for the served-MCP memory parity probe. The probe drives the
// wrapper's tc_memory_search / tc_memory_write tools through the served-MCP bridge
// from the contained peer and records whether memory parity holds: source-scoped
// recall/write, episodic sanitization, private/public air-gap, and fail-closed
// rejection of secret-shaped and instruction-like writes. This file is the schema
// + required-check catalog; served-mcp-memory.ts holds the deterministic evaluator.

export const SERVED_MCP_MEMORY_SCHEMA_VERSION = "telclaude.hermes.served-mcp-memory.v1";

export const SERVED_MCP_MEMORY_REQUIRED_PROPERTY_NAMES = [
	// Positive parity: the wrapper memory tools work for the authorized source.
	"positive_memory_write_validated",
	"positive_memory_recall_returned",
	// The memory source is resolved server-side from the connection's actor/profile,
	// never chosen by the caller.
	"memory_source_resolved_server_side",
	// Recalled episodic text is sanitized (secrets redacted, instruction-like content
	// neutralized) before it reaches the model.
	"episodic_recall_sanitized",
	// Air-gap: a private (telegram) context cannot read social-source memory.
	"cross_source_read_denied",
	// Fail-closed write validation.
	"secret_write_rejected",
	"instruction_like_write_rejected",
	// The evidence artifact bytes carry no unredacted secret-shaped material.
	"artifact_redacted",
] as const;

export type ServedMcpMemoryPropertyName =
	(typeof SERVED_MCP_MEMORY_REQUIRED_PROPERTY_NAMES)[number];

const NonEmptyString = z.string().trim().min(1);
const ServedMcpMemoryPropertyNameSchema = z.enum(SERVED_MCP_MEMORY_REQUIRED_PROPERTY_NAMES);

const ServedMcpMemoryPropertiesSchema = z
	.object({
		positive_memory_write_validated: z.boolean().optional(),
		positive_memory_recall_returned: z.boolean().optional(),
		memory_source_resolved_server_side: z.boolean().optional(),
		episodic_recall_sanitized: z.boolean().optional(),
		cross_source_read_denied: z.boolean().optional(),
		secret_write_rejected: z.boolean().optional(),
		instruction_like_write_rejected: z.boolean().optional(),
		artifact_redacted: z.boolean().optional(),
	})
	.strict();

const ServedMcpMemoryCheckSchema = z
	.object({
		name: ServedMcpMemoryPropertyNameSchema,
		status: z.enum(["pass", "fail"]),
		detail: NonEmptyString,
		// RPC-error denials (secret/instruction write rejection throw from
		// validateMemoryEntryInput) carry an error code + message.
		rpcErrorCode: z.number().int().optional(),
		rpcErrorMessage: NonEmptyString.optional(),
		// Server-scoped denials (cross-source read) are proven by an empty result:
		// a contained telegram-domain search returns zero rows even though a
		// social/sibling sentinel entry exists, with no raw cross-source payload.
		observedResultCount: z.number().int().nonnegative().optional(),
	})
	.strict();

// Server-grounded origin: the memory tools must be exercised from the contained
// peer, proven by the relay's server-echoed peer address (client cannot spoof).
const ServedMcpMemoryOriginSchema = z
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

export const ServedMcpMemoryEvidenceSchema = z
	.object({
		schemaVersion: z.literal(SERVED_MCP_MEMORY_SCHEMA_VERSION),
		probeId: z.literal("served_mcp.memory"),
		status: z.enum(["pass", "fail", "pending"]),
		ran: z.boolean(),
		generatedAt: NonEmptyString,
		summary: NonEmptyString,
		// The source the probe asserts it operated under (private telegram side).
		memorySource: NonEmptyString,
		origin: ServedMcpMemoryOriginSchema,
		properties: ServedMcpMemoryPropertiesSchema,
		checks: z.array(ServedMcpMemoryCheckSchema),
	})
	.strict();

export type ServedMcpMemoryEvidence = z.infer<typeof ServedMcpMemoryEvidenceSchema>;
export type ServedMcpMemoryCheck = ServedMcpMemoryEvidence["checks"][number];
