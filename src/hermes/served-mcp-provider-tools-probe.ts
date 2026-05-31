import crypto from "node:crypto";
import fs from "node:fs";
import { z } from "zod";
import {
	SERVED_MCP_CONTAINMENT_SCHEMA_VERSION,
	type ServedMcpContainmentEvidence,
	ServedMcpContainmentEvidenceSchema,
} from "./served-mcp-containment.js";

export const DEFAULT_SERVED_MCP_PROVIDER_TOOLS_EVIDENCE_PATH =
	"artifacts/hermes/probes/served-mcp-provider-tools.json";
export const DEFAULT_SERVED_MCP_PROVIDER_TOOLS_SOURCE_EVIDENCE_PATH =
	"artifacts/hermes/probes/execution-served-mcp-containment.json";
export const SERVED_MCP_PROVIDER_TOOLS_PROBE_SCHEMA_VERSION =
	"telclaude.hermes.served-mcp-provider-tools-probe.v1";
export const SERVED_MCP_PROVIDER_TOOLS_PROBE_SOURCE =
	"telclaude-served-mcp-provider-tools-from-containment";

const NonEmptyString = z.string().trim().min(1);
const Sha256Digest = z.string().regex(/^sha256:[a-f0-9]{64}$/i);

const ServedMcpProviderToolsCheckSchema = z
	.object({
		name: NonEmptyString,
		status: z.enum(["pass", "fail"]),
		detail: NonEmptyString,
	})
	.strict();

export const ServedMcpProviderToolsProbeEvidenceSchema = z
	.object({
		schemaVersion: z.literal(SERVED_MCP_PROVIDER_TOOLS_PROBE_SCHEMA_VERSION),
		probeId: z.literal("served_mcp.provider-tools"),
		status: z.enum(["pass", "fail"]),
		ran: z.boolean(),
		observedAt: NonEmptyString,
		source: z.literal(SERVED_MCP_PROVIDER_TOOLS_PROBE_SOURCE),
		summary: NonEmptyString,
		sourceEvidence: z
			.object({
				path: NonEmptyString,
				schemaVersion: z.literal(SERVED_MCP_CONTAINMENT_SCHEMA_VERSION),
				probeId: z.literal("execution.served_mcp_containment"),
				sha256: Sha256Digest,
			})
			.strict(),
		checks: z.array(ServedMcpProviderToolsCheckSchema).min(1),
		observations: z
			.object({
				originKind: z.enum(["contained-peer", "relay-self-smoke", "unknown"]),
				containerName: NonEmptyString.optional(),
				providerTools: z.array(NonEmptyString),
			})
			.strict(),
	})
	.strict();

export type ServedMcpProviderToolsProbeEvidence = z.infer<
	typeof ServedMcpProviderToolsProbeEvidenceSchema
>;
type ProbeCheck = z.infer<typeof ServedMcpProviderToolsCheckSchema>;

const REQUIRED_SERVED_MCP_PROVIDER_TOOLS_CHECKS = [
	"served-mcp.provider-tools.source-pass",
	"served-mcp.provider-tools.contained-peer",
	"served-mcp.provider-tools.exact-tools",
	"served-mcp.provider-tools.authority-bound",
	"served-mcp.provider-tools.provider-scope-denied",
	"served-mcp.provider-tools.execute-without-ledger-denied",
	"served-mcp.provider-tools.non-tool-surfaces-denied",
	"served-mcp.provider-tools.artifact-redacted",
] as const;

const PROVIDER_TOOL_NAMES = [
	"tc_provider_read",
	"tc_provider_prepare_write",
	"tc_provider_execute_write",
] as const;

export function buildServedMcpProviderToolsProbeEvidence(input: {
	readonly sourceEvidencePath: string;
	readonly sourceEvidence: unknown;
	readonly observedAt?: string;
}): ServedMcpProviderToolsProbeEvidence {
	const observedAt = input.observedAt ?? new Date().toISOString();
	const parsed = ServedMcpContainmentEvidenceSchema.safeParse(input.sourceEvidence);
	const checks: ProbeCheck[] = [];
	if (!parsed.success) {
		checks.push({
			name: "served-mcp.provider-tools.source-pass",
			status: "fail",
			detail: `source served-MCP containment evidence is invalid: ${flattenZodError(parsed.error)}`,
		});
		return buildEvidence(input, observedAt, checks, undefined);
	}

	const source = parsed.data;
	const props = source.properties;
	pushCheck(
		checks,
		"served-mcp.provider-tools.source-pass",
		source.status === "pass" && source.ran === true,
		"source served-MCP containment evidence passed from a live run",
		`source served-MCP containment evidence status=${source.status} ran=${source.ran}`,
	);
	pushCheck(
		checks,
		"served-mcp.provider-tools.contained-peer",
		source.origin.kind === "contained-peer" &&
			source.origin.observedPeerSource === "server-peer-echo" &&
			source.origin.expectedPeerSource === "configured-contained-ip" &&
			source.origin.observedPeerAddress === source.origin.expectedPeerAddress,
		"source evidence is bound to a server-observed contained Hermes peer",
		"source evidence is not bound to a server-observed contained Hermes peer",
	);
	pushCheck(
		checks,
		"served-mcp.provider-tools.exact-tools",
		props.positive_initialize_tools_only === true && props.positive_tools_list_exact === true,
		"served MCP exposes the exact Telclaude tc_ tool surface including provider tools",
		"served MCP did not prove exact tc_ tool exposure",
	);
	pushCheck(
		checks,
		"served-mcp.provider-tools.authority-bound",
		props.handle_forgery_denied === true &&
			props.wrong_connection_denied === true &&
			props.off_domain_peer_denied === true,
		"provider tools are bound to relay-issued authority handles and contained peer identity",
		"provider tools are missing forged/wrong-connection/off-domain denial evidence",
	);
	pushCheck(
		checks,
		"served-mcp.provider-tools.provider-scope-denied",
		props.out_of_scope_provider_denied === true,
		"out-of-scope provider calls are denied before provider custody",
		"out-of-scope provider denial is unproven",
	);
	pushCheck(
		checks,
		"served-mcp.provider-tools.execute-without-ledger-denied",
		props.provider_execute_without_ledger_denied === true,
		"provider execute calls require a prepared side-effect ledger ref",
		"provider execute without prepared ledger denial is unproven",
	);
	pushCheck(
		checks,
		"served-mcp.provider-tools.non-tool-surfaces-denied",
		props.positive_resources_empty === true &&
			props.positive_prompts_empty === true &&
			props.positive_roots_empty === true &&
			props.sampling_disabled === true,
		"served MCP exposes no provider resources/prompts/roots/sampling side channel",
		"served MCP non-tool side-channel denial is unproven",
	);
	pushCheck(
		checks,
		"served-mcp.provider-tools.artifact-redacted",
		props.artifact_redacted === true,
		"source evidence omits raw handles, headers, tokens, signatures, and endpoint material",
		"source evidence redaction is unproven",
	);

	return buildEvidence(input, observedAt, checks, source);
}

export function servedMcpProviderToolsProbeEvidenceFailure(evidence: unknown): string | null {
	const parsed = ServedMcpProviderToolsProbeEvidenceSchema.safeParse(evidence);
	if (!parsed.success) {
		return `invalid served-MCP provider-tools evidence: ${flattenZodError(parsed.error)}`;
	}
	const data = parsed.data;
	const failures: string[] = [];
	if (data.status !== "pass") failures.push(`status is ${data.status}`);
	if (data.ran !== true) failures.push("harness did not run");
	const checksByName = new Map(data.checks.map((check) => [check.name, check]));
	for (const duplicate of duplicates(data.checks.map((check) => check.name))) {
		failures.push(`duplicate check ${duplicate}`);
	}
	for (const name of REQUIRED_SERVED_MCP_PROVIDER_TOOLS_CHECKS) {
		const check = checksByName.get(name);
		if (!check) {
			failures.push(`check ${name} is missing`);
		} else if (check.status !== "pass") {
			failures.push(`check ${name} is ${check.status}`);
		}
	}
	for (const toolName of PROVIDER_TOOL_NAMES) {
		if (!data.observations.providerTools.includes(toolName)) {
			failures.push(`provider tool ${toolName} is missing from observations`);
		}
	}
	if (data.observations.originKind !== "contained-peer") {
		failures.push(`originKind is ${data.observations.originKind}`);
	}
	return failures.length > 0 ? failures.join("; ") : null;
}

function buildEvidence(
	input: {
		readonly sourceEvidencePath: string;
		readonly sourceEvidence: unknown;
	},
	observedAt: string,
	checks: ProbeCheck[],
	source: ServedMcpContainmentEvidence | undefined,
): ServedMcpProviderToolsProbeEvidence {
	const status =
		checks.length > 0 && checks.every((check) => check.status === "pass") ? "pass" : "fail";
	return {
		schemaVersion: SERVED_MCP_PROVIDER_TOOLS_PROBE_SCHEMA_VERSION,
		probeId: "served_mcp.provider-tools",
		status,
		ran: source?.ran === true,
		observedAt,
		source: SERVED_MCP_PROVIDER_TOOLS_PROBE_SOURCE,
		summary:
			status === "pass"
				? "Served MCP provider-tools probe passed"
				: "Served MCP provider-tools probe failed",
		sourceEvidence: {
			path: input.sourceEvidencePath,
			schemaVersion: SERVED_MCP_CONTAINMENT_SCHEMA_VERSION,
			probeId: "execution.served_mcp_containment",
			sha256: sha256Json(input.sourceEvidence),
		},
		checks,
		observations: {
			originKind: source?.origin.kind ?? "unknown",
			...(source?.origin.containerName ? { containerName: source.origin.containerName } : {}),
			providerTools: [...PROVIDER_TOOL_NAMES],
		},
	};
}

export function readServedMcpProviderToolsSourceEvidence(pathname: string): unknown {
	return JSON.parse(fs.readFileSync(pathname, "utf8"));
}

function pushCheck(
	checks: ProbeCheck[],
	name: ProbeCheck["name"],
	passed: boolean,
	passDetail: string,
	failDetail = passDetail,
): void {
	checks.push({
		name,
		status: passed ? "pass" : "fail",
		detail: passed ? passDetail : failDetail,
	});
}

function sha256Json(value: unknown): string {
	return `sha256:${crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex")}`;
}

function duplicates(values: readonly string[]): string[] {
	const seen = new Set<string>();
	const duplicate = new Set<string>();
	for (const value of values) {
		if (seen.has(value)) duplicate.add(value);
		seen.add(value);
	}
	return [...duplicate].sort((left, right) => left.localeCompare(right));
}

function flattenZodError(error: z.ZodError): string {
	return error.issues
		.map((issue) => `${issue.path.join(".") || "<root>"}: ${issue.message}`)
		.join("; ");
}
