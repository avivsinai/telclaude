import net from "node:net";
import type { ZodError } from "zod";
import { memorySourceFamily, validateMemorySource } from "../memory/source.js";
import { redactSecrets } from "../security/output-filter.js";
import { type HermesArtifactWriteOptions, writeHermesJsonArtifact } from "./foundation.js";
import { DEFAULT_SERVED_MCP_CONTAINED_CONTAINER_NAME } from "./served-mcp-containment.js";

export {
	SERVED_MCP_MEMORY_REQUIRED_PROPERTY_NAMES,
	SERVED_MCP_MEMORY_SCHEMA_VERSION,
	type ServedMcpMemoryCheck,
	type ServedMcpMemoryEvidence,
	ServedMcpMemoryEvidenceSchema,
	type ServedMcpMemoryPropertyName,
} from "./served-mcp-memory-schema.js";

import {
	SERVED_MCP_MEMORY_REQUIRED_PROPERTY_NAMES,
	type ServedMcpMemoryEvidence,
	ServedMcpMemoryEvidenceSchema,
} from "./served-mcp-memory-schema.js";

export const DEFAULT_SERVED_MCP_MEMORY_EVIDENCE_PATH =
	"artifacts/hermes/probes/served-mcp-memory.json";

export const SERVED_MCP_MEMORY_REPORT_SCHEMA_VERSION =
	"telclaude.hermes.served-mcp-memory-report.v1";

export type ServedMcpMemoryGate = {
	readonly name: string;
	readonly status: "pass" | "fail";
	readonly detail: string;
};

export type ServedMcpMemoryReport = {
	readonly schemaVersion: typeof SERVED_MCP_MEMORY_REPORT_SCHEMA_VERSION;
	readonly status: "pass" | "fail" | "input_error";
	readonly productionEnable: boolean;
	readonly gates: ServedMcpMemoryGate[];
};

// Negative controls denied by an RPC error (validateMemoryEntryInput throws):
// the backing check must carry rpcErrorCode + rpcErrorMessage.
const MEMORY_RPC_DENIAL_PROPERTY_NAMES: ReadonlySet<string> = new Set([
	"secret_write_rejected",
	"instruction_like_write_rejected",
]);
// Negative controls denied by server-side domain scoping (cross-source read): the
// backing check must prove an empty result (observedResultCount === 0), not an
// RPC error — tc_memory_search is stamped from the connection domain, so a
// telegram-domain search simply returns zero social rows.
const MEMORY_EMPTY_RESULT_DENIAL_PROPERTY_NAMES: ReadonlySet<string> = new Set([
	"cross_source_read_denied",
]);

function inputError(detail: string): ServedMcpMemoryReport {
	return {
		schemaVersion: SERVED_MCP_MEMORY_REPORT_SCHEMA_VERSION,
		status: "input_error",
		productionEnable: false,
		gates: [{ name: "memory.evidence", status: "fail", detail }],
	};
}

function originGate(origin: ServedMcpMemoryEvidence["origin"]): ServedMcpMemoryGate {
	if (origin.kind === "relay-self-smoke") {
		return {
			name: "memory.origin",
			status: "fail",
			detail: "memory evidence originated from relay-self smoke and is not production evidence",
		};
	}
	const matchesPeer =
		origin.observedPeerAddress !== undefined &&
		origin.expectedPeerAddress !== undefined &&
		origin.observedPeerSource === "server-peer-echo" &&
		origin.expectedPeerSource === "configured-contained-ip" &&
		net.isIP(origin.observedPeerAddress) !== 0 &&
		net.isIP(origin.expectedPeerAddress) !== 0 &&
		origin.observedPeerAddress === origin.expectedPeerAddress;
	if (
		origin.kind === "contained-peer" &&
		origin.containerName === DEFAULT_SERVED_MCP_CONTAINED_CONTAINER_NAME &&
		matchesPeer
	) {
		return {
			name: "memory.origin",
			status: "pass",
			detail: "memory evidence originated from tc-hermes-contained at the expected peer address",
		};
	}
	return {
		name: "memory.origin",
		status: "fail",
		detail:
			"memory evidence must include a server-observed contained peer IP from tc-hermes-contained matching the configured contained IP",
	};
}

// This surface proves PRIVATE Telegram memory parity (and the private/public
// air-gap). Fail closed unless memorySource is a valid, non-legacy telegram
// source — a social or bare/legacy "telegram" source must not satisfy the row.
function sourceGate(memorySource: string): ServedMcpMemoryGate {
	const validationError = validateMemorySource(memorySource);
	if (validationError !== null) {
		return {
			name: "memory.source",
			status: "fail",
			detail: `memory evidence memorySource is invalid: ${validationError}`,
		};
	}
	if (memorySourceFamily(memorySource) !== "telegram") {
		return {
			name: "memory.source",
			status: "fail",
			detail: `memory evidence memorySource ${memorySource} is not in the private telegram family`,
		};
	}
	return {
		name: "memory.source",
		status: "pass",
		detail: `memory evidence memorySource ${memorySource} is a valid private telegram source`,
	};
}

/**
 * Deterministic evaluator the cutover-check consumes. A property is proven only
 * when its boolean bit is true AND backed by at least one check of the same name
 * whose every occurrence is "pass" — a self-reported property bit without a
 * passing backing check does not count. The producer (which drives tc_memory_*
 * through the served-MCP bridge from the contained peer) runs in the live
 * runtime; this evaluator validates the artifact it emits.
 */
export function evaluateServedMcpMemoryEvidence(
	evidence: unknown,
	options: { missingPath?: string } = {},
): ServedMcpMemoryReport {
	if (evidence === undefined) {
		return inputError(
			`required served-MCP memory evidence is missing: ${options.missingPath ?? DEFAULT_SERVED_MCP_MEMORY_EVIDENCE_PATH}`,
		);
	}
	const parsed = ServedMcpMemoryEvidenceSchema.safeParse(evidence);
	if (!parsed.success) {
		return inputError(flattenZodError(parsed.error));
	}

	const gates: ServedMcpMemoryGate[] = [];
	gates.push(originGate(parsed.data.origin));
	gates.push(sourceGate(parsed.data.memorySource));

	if (parsed.data.status !== "pass") {
		gates.push({
			name: "memory.status",
			status: "fail",
			detail: `memory evidence status is ${parsed.data.status}`,
		});
	}
	if (parsed.data.ran !== true) {
		gates.push({
			name: "memory.ran",
			status: "fail",
			detail: `memory evidence ran is ${String(parsed.data.ran)}`,
		});
	}

	// Index checks by name; a property is only proven if it has at least one check
	// and every check of that name is "pass" (a single failing duplicate poisons it).
	// Negative-control properties additionally require denial EVIDENCE on a passing
	// check (an rpcErrorCode + rpcErrorMessage), not just a self-reported "rejected".
	const checkPass = new Map<string, boolean>();
	const rpcDenialEvidence = new Map<string, boolean>();
	const emptyResultEvidence = new Map<string, boolean>();
	for (const check of parsed.data.checks) {
		const prior = checkPass.get(check.name);
		const thisPass = check.status === "pass";
		checkPass.set(check.name, prior === undefined ? thisPass : prior && thisPass);
		if (
			thisPass &&
			typeof check.rpcErrorCode === "number" &&
			typeof check.rpcErrorMessage === "string"
		) {
			rpcDenialEvidence.set(check.name, true);
		}
		if (thisPass && check.observedResultCount === 0) {
			emptyResultEvidence.set(check.name, true);
		}
	}

	// artifact_redacted is not trusted as a self-reported bit: independently scan the
	// evidence bytes (free-text fields like summary/detail/memorySource are
	// unconstrained) and force the gate to fail on any credential-shaped match.
	const serialized = JSON.stringify(parsed.data);
	const redactionLeak = redactSecrets(serialized) !== serialized;

	for (const property of SERVED_MCP_MEMORY_REQUIRED_PROPERTY_NAMES) {
		const bit = parsed.data.properties[property] === true;
		const backed = checkPass.get(property) === true;
		const leaked = property === "artifact_redacted" && redactionLeak;
		const isRpcDenial = MEMORY_RPC_DENIAL_PROPERTY_NAMES.has(property);
		const isEmptyResultDenial = MEMORY_EMPTY_RESULT_DENIAL_PROPERTY_NAMES.has(property);
		const denialOk =
			(!isRpcDenial || rpcDenialEvidence.get(property) === true) &&
			(!isEmptyResultDenial || emptyResultEvidence.get(property) === true);
		const proven = bit && backed && !leaked && denialOk;
		gates.push({
			name: `memory.${property}`,
			status: proven ? "pass" : "fail",
			detail: leaked
				? "memory evidence bytes contain credential-shaped text; artifact_redacted forced to fail"
				: !bit
					? `memory property ${property} is ${parsed.data.properties[property] === undefined ? "missing" : "false"}`
					: !backed
						? `memory property ${property} bit is set but lacks a passing backing check`
						: !denialOk
							? isEmptyResultDenial
								? `memory denial property ${property} requires a passing check proving an empty result (observedResultCount === 0)`
								: `memory denial property ${property} requires a passing check carrying denial evidence (rpcErrorCode + rpcErrorMessage)`
							: `memory property ${property} is proven and check-backed`,
		});
	}

	const productionEnable = gates.every((gate) => gate.status === "pass");
	return {
		schemaVersion: SERVED_MCP_MEMORY_REPORT_SCHEMA_VERSION,
		status: productionEnable ? "pass" : "fail",
		productionEnable,
		gates,
	};
}

export function writeServedMcpMemoryEvidence(
	evidence: ServedMcpMemoryEvidence,
	filePath: string,
	options: HermesArtifactWriteOptions = {},
): void {
	writeHermesJsonArtifact(filePath, evidence, options);
}

function flattenZodError(error: ZodError): string {
	return error.issues
		.map((issue) => `${issue.path.join(".") || "<root>"}: ${issue.message}`)
		.join("; ");
}
