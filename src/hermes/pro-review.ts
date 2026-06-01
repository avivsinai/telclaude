import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { z } from "zod";
import { resolveHermesArtifactPath } from "./foundation.js";
import { readHermesCliHeadlessProbeReport } from "./private-runtime.js";

export const DEFAULT_PRO_REVIEW_REQUEST_PATH = "docs/hermes/pro-review-request.json";
export const DEFAULT_PRO_REVIEW_NATIVE_CANARY_PATH =
	"artifacts/hermes/pro-review-native-canary.json";
export const PRO_REVIEW_REQUEST_SCHEMA_VERSION = "telclaude.hermes.pro-review-request.v1";
export const PRO_REVIEW_NATIVE_CANARY_SCHEMA_VERSION =
	"telclaude.hermes.pro-review-native-canary.v1";
export const REQUIRED_PRO_REVIEW_FILES = [
	"docs/plans/2026-05-29-hermes-wrapper-pristine-spec.md",
	"docs/hermes/local-colima-live-run.md",
	"docs/hermes/decisions.json",
	"src/hermes/pro-review.ts",
	"src/hermes/edge-adapter-contract.ts",
	"src/hermes/edge-adapter-probes.ts",
	"src/hermes/private-runtime.ts",
	"src/hermes/foundation.ts",
	"src/hermes/provider-approval-binding-probe.ts",
	"src/hermes/served-mcp-provider-tools-probe.ts",
	"src/hermes/mcp/side-effect-ledger-probe.ts",
	"src/hermes/mcp/provider-routing.ts",
	"src/hermes/mcp/side-effect-ledger.ts",
	"src/hermes/mcp/approval-token.ts",
	"src/hermes/mcp/ledger-execute.ts",
	"src/hermes/mcp/live-relay-clients.ts",
	"src/hermes/mcp/live-server.ts",
	"src/hermes/mcp/live-runtime.ts",
	"src/commands/hermes.ts",
	"src/relay/provider-proxy.ts",
	"src/relay/openai-codex-proxy.ts",
	"docker/docker-compose.hermes.yml",
	"docker/hermes-contained-entrypoint.sh",
	"scripts/hermes-contained-cli-probe.sh",
	"docs/hermes/feature-probes.json",
	"docs/hermes/fixture-results.json",
	"docs/hermes/hermes-compat.lock.json",
	"artifacts/hermes/probes/edge-whatsapp.json",
	"artifacts/hermes/probes/edge-email.json",
	"artifacts/hermes/probes/edge-agentmail.json",
	"artifacts/hermes/probes/edge-social.json",
	"artifacts/hermes/probes/identity-migration.json",
	"artifacts/hermes/probes/household-scopes.json",
	"artifacts/hermes/probes/attachment-quarantine.json",
	"artifacts/hermes/probes/outbound-policy.json",
	"artifacts/hermes/probes/public-social-isolation.json",
	"artifacts/hermes/probes/providers-approval-binding.json",
	"artifacts/hermes/probes/served-mcp-provider-tools.json",
	"artifacts/hermes/probes/sideeffect-ledger.json",
	"artifacts/hermes/probes/execution-cli-headless.json",
	"artifacts/hermes/pro-review-native-canary.json",
	"tests/hermes/edge-adapter-contract.test.ts",
	"tests/hermes/edge-adapter-probes.test.ts",
	"tests/hermes/provider-approval-binding-probe.test.ts",
	"tests/hermes/served-mcp-provider-tools-probe.test.ts",
	"tests/hermes/pro-review.test.ts",
	"tests/hermes/mcp-side-effect-ledger-probe.test.ts",
	"tests/hermes/mcp-ledger-execute.test.ts",
	"tests/hermes/mcp-live-relay-clients.test.ts",
	"tests/hermes/mcp-live-server.test.ts",
	"tests/commands/hermes.test.ts",
	"tests/relay/provider-proxy.test.ts",
	"tests/hermes/private-runtime.test.ts",
	"tests/sandbox/validate-config.test.ts",
	"tests/relay/openai-codex-proxy.test.ts",
] as const;

type ProReviewGate = {
	readonly name: string;
	readonly status: "pass" | "fail" | "pending";
	readonly detail: string;
};

export type ProReviewCheckReport = {
	readonly schemaVersion: "telclaude.hermes.pro-review-check.v1";
	readonly status: "pass" | "fail" | "pending";
	readonly requestPath: string;
	readonly canaryPath: string;
	readonly gates: readonly ProReviewGate[];
	readonly selectedFiles: readonly string[];
	readonly payloadSha256?: string;
	readonly approval?: {
		readonly required: boolean;
		readonly approved: boolean;
		readonly approvalId?: string;
		readonly operator?: string;
		readonly approvedAt?: string;
	};
};

const Sha256DigestSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const NonEmptyString = z.string().min(1);

const ProReviewRequestSchema = z
	.object({
		schemaVersion: z.literal(PRO_REVIEW_REQUEST_SCHEMA_VERSION),
		status: z.enum(["pending_operator_disclosure_approval", "approved", "sent", "reviewed"]),
		reviewer: NonEmptyString,
		transport: z.literal("chrome-extension-native"),
		model: z.literal("Extended Pro"),
		fallbackAllowed: z.literal(false),
		transportEvidence: NonEmptyString,
		prompt: NonEmptyString,
		privateWorkspaceDisclosure: z
			.object({
				required: z.literal(true),
				approved: z.boolean(),
				approvalReason: NonEmptyString,
				approvalBindingRequired: z.literal(true),
				approvalId: z.string().nullable(),
				operator: z.string().nullable(),
				approvedAt: z.string().nullable(),
				payloadSha256: Sha256DigestSchema.nullable(),
			})
			.strict(),
		payloadBinding: z
			.object({
				digestAlgorithm: z.literal("sha256"),
				canonicalJsonFields: z.tuple([
					z.literal("reviewer"),
					z.literal("transport"),
					z.literal("model"),
					z.literal("fallbackAllowed"),
					z.literal("transportEvidence"),
					z.literal("blockedFallbacks"),
					z.literal("prompt"),
					z.literal("selectedFiles"),
					z.literal("selectedFileContentsSha256"),
					z.literal("transportEvidenceSha256"),
				]),
				payloadSha256: Sha256DigestSchema,
				promptSha256: Sha256DigestSchema,
				selectedFilesSha256: Sha256DigestSchema,
				selectedFileContentsSha256: Sha256DigestSchema,
				transportEvidenceSha256: Sha256DigestSchema,
				notes: NonEmptyString,
			})
			.strict(),
		selectedFiles: z.array(NonEmptyString).min(1),
		blockedFallbacks: z.array(NonEmptyString),
	})
	.strict();

const ProReviewNativeCanarySchema = z
	.object({
		schemaVersion: z.literal(PRO_REVIEW_NATIVE_CANARY_SCHEMA_VERSION),
		status: z.literal("pass"),
		transport: z.literal("chrome-extension-native"),
		recipe: z.literal("chatgpt"),
		modelSelectionStatus: z.literal("selected"),
		modelUsed: z.literal("Extended Pro"),
		live: z.literal(true),
		runId: NonEmptyString,
		conversationId: NonEmptyString,
		conversationUrl: NonEmptyString,
		extensionInstanceId: NonEmptyString,
		extensionVersion: NonEmptyString,
		promptClass: NonEmptyString,
		expectedResponse: z.literal("OK"),
		response: z.literal("OK"),
		warnings: z.array(z.string()),
		observedAt: NonEmptyString,
		reverifiedAt: NonEmptyString,
		dryCanary: z
			.object({
				command: NonEmptyString,
				exitCode: z.literal(0),
				status: z.literal("ok"),
				transport: z.literal("chrome-extension-native"),
				live: z.literal(false),
			})
			.strict(),
		liveCanary: z
			.object({
				command: NonEmptyString,
				exitCode: z.literal(0),
				status: z.literal("ok"),
				transport: z.literal("chrome-extension-native"),
				live: z.literal(true),
				modelUsed: z.literal("Extended Pro"),
				response: z.literal("OK"),
			})
			.strict(),
		nativeStatus: z
			.object({
				command: NonEmptyString,
				exitCode: z.literal(0),
				status: z.literal("connected"),
				detail: NonEmptyString,
				extensionId: NonEmptyString,
				extensionInstanceId: NonEmptyString,
				extensionVersion: NonEmptyString,
				nativeHostName: z.literal("com.yoetz.chatgpt_native"),
				protocolVersion: z.number().int().positive(),
				socketReachable: z.literal(true),
				transport: z.literal("chrome-extension-native"),
			})
			.strict(),
		checks: z.array(
			z
				.object({
					name: NonEmptyString,
					status: z.literal("pass"),
					detail: NonEmptyString,
				})
				.strict(),
		),
	})
	.strict();

type ProReviewRequest = z.infer<typeof ProReviewRequestSchema>;
type ProReviewNativeCanary = z.infer<typeof ProReviewNativeCanarySchema>;

export function evaluateProReviewCheck(
	input: {
		readonly requestPath?: string;
		readonly canaryPath?: string;
		readonly requireApproval?: boolean;
	} = {},
): ProReviewCheckReport {
	const requestPath = input.requestPath ?? DEFAULT_PRO_REVIEW_REQUEST_PATH;
	const canaryPath = input.canaryPath ?? DEFAULT_PRO_REVIEW_NATIVE_CANARY_PATH;
	const gates: ProReviewGate[] = [];
	const request = readRequest(requestPath, gates);
	const canary = readCanary(canaryPath, gates);

	if (request) {
		gates.push(...requestPolicyGates(request, requestPath, canaryPath, input.requireApproval));
	}
	if (request && canary) {
		gates.push(...canaryPolicyGates(canary, request));
	}

	const status = gates.some((gate) => gate.status === "fail")
		? "fail"
		: gates.some((gate) => gate.status === "pending")
			? "pending"
			: "pass";

	return {
		schemaVersion: "telclaude.hermes.pro-review-check.v1",
		status,
		requestPath,
		canaryPath,
		gates,
		selectedFiles: request?.selectedFiles ?? [],
		...(request ? { payloadSha256: request.payloadBinding.payloadSha256 } : {}),
		...(request
			? {
					approval: {
						required: request.privateWorkspaceDisclosure.required,
						approved: request.privateWorkspaceDisclosure.approved,
						...(request.privateWorkspaceDisclosure.approvalId
							? { approvalId: request.privateWorkspaceDisclosure.approvalId }
							: {}),
						...(request.privateWorkspaceDisclosure.operator
							? { operator: request.privateWorkspaceDisclosure.operator }
							: {}),
						...(request.privateWorkspaceDisclosure.approvedAt
							? { approvedAt: request.privateWorkspaceDisclosure.approvedAt }
							: {}),
					},
				}
			: {}),
	};
}

function readRequest(pathname: string, gates: ProReviewGate[]): ProReviewRequest | null {
	const parsed = readAndParse(pathname, ProReviewRequestSchema);
	if (!parsed.ok) {
		gates.push(fail("request.schema", parsed.error));
		return null;
	}
	gates.push(pass("request.schema", "Pro review request schema is valid"));
	return parsed.value;
}

function readCanary(pathname: string, gates: ProReviewGate[]): ProReviewNativeCanary | null {
	const parsed = readAndParse(pathname, ProReviewNativeCanarySchema);
	if (!parsed.ok) {
		gates.push(fail("nativeCanary.schema", parsed.error));
		return null;
	}
	gates.push(pass("nativeCanary.schema", "Yoetz native canary schema is valid"));
	return parsed.value;
}

function requestPolicyGates(
	request: ProReviewRequest,
	requestPath: string,
	canaryPath: string,
	requireApproval: boolean | undefined,
): ProReviewGate[] {
	const gates: ProReviewGate[] = [];
	gates.push(
		request.reviewer === "ChatGPT Pro Extended via Yoetz native extension"
			? pass("request.reviewer", "reviewer is ChatGPT Pro Extended via Yoetz native extension")
			: fail("request.reviewer", `reviewer is ${request.reviewer}`),
	);
	gates.push(pass("request.transport", "transport is chrome-extension-native"));
	gates.push(pass("request.model", "model is Extended Pro"));
	gates.push(pass("request.fallback", "fallbackAllowed is false"));

	const blockedFallbacks = new Set(request.blockedFallbacks);
	const missingFallbacks = [
		"cdp",
		"api-key",
		"manual-browser",
		"claude-substitution",
		"amq-substitution",
	].filter((fallback) => !blockedFallbacks.has(fallback));
	gates.push(
		missingFallbacks.length === 0
			? pass("request.blockedFallbacks", "CDP/API/manual/Claude/AMQ fallbacks are blocked")
			: fail(
					"request.blockedFallbacks",
					`missing blocked fallback(s): ${missingFallbacks.join(", ")}`,
				),
	);

	const expectedCanary = normalizeArtifactPath(canaryPath);
	const declaredCanary = normalizeArtifactPath(request.transportEvidence);
	gates.push(
		declaredCanary === expectedCanary
			? pass("request.transportEvidence", "transport evidence path matches canary path")
			: fail(
					"request.transportEvidence",
					`transport evidence path ${request.transportEvidence} does not match ${canaryPath}`,
				),
	);

	const digestFailures = payloadDigestFailures(request);
	gates.push(
		digestFailures.length === 0
			? pass("request.payloadBinding", "payload digest matches review content and native evidence")
			: fail("request.payloadBinding", digestFailures.join("; ")),
	);

	const missingRequiredFiles = REQUIRED_PRO_REVIEW_FILES.filter(
		(file) => !request.selectedFiles.includes(file),
	);
	gates.push(
		missingRequiredFiles.length === 0
			? pass("request.requiredFiles", "all required Pro review files are selected")
			: fail(
					"request.requiredFiles",
					`required Pro review file(s) missing from selectedFiles: ${missingRequiredFiles.join(", ")}`,
				),
	);

	const missingFiles = request.selectedFiles.filter(
		(file) => !fs.existsSync(resolveHermesArtifactPath(file)),
	);
	gates.push(
		missingFiles.length === 0
			? pass("request.selectedFiles", "all selected Pro review files exist")
			: fail("request.selectedFiles", `selected file(s) missing: ${missingFiles.join(", ")}`),
	);
	gates.push(...semanticEvidenceGates(request));

	const approval = request.privateWorkspaceDisclosure;
	if (approval.approved) {
		const approvalFailures = [];
		if (request.status === "pending_operator_disclosure_approval") {
			approvalFailures.push("request status is still pending disclosure approval");
		}
		if (!approval.approvalId?.trim()) approvalFailures.push("approvalId is missing");
		if (!approval.operator?.trim()) approvalFailures.push("operator is missing");
		if (!approval.approvedAt?.trim()) approvalFailures.push("approvedAt is missing");
		else if (Number.isNaN(Date.parse(approval.approvedAt)))
			approvalFailures.push("approvedAt is invalid");
		if (approval.payloadSha256 !== request.payloadBinding.payloadSha256) {
			approvalFailures.push("approval payloadSha256 does not match payloadBinding.payloadSha256");
		}
		gates.push(
			approvalFailures.length === 0
				? pass("disclosure.approved", "private workspace disclosure approval is payload-bound")
				: fail("disclosure.approved", approvalFailures.join("; ")),
		);
	} else {
		if (approval.payloadSha256 !== null) {
			gates.push(
				fail(
					"disclosure.payloadBinding",
					"unapproved private workspace disclosure must not carry approval payloadSha256",
				),
			);
		}
		gates.push(
			requireApproval
				? fail("disclosure.approved", "private workspace disclosure is not approved")
				: pending("disclosure.approved", "private workspace disclosure is pending exact approval"),
		);
		if (request.status !== "pending_operator_disclosure_approval") {
			gates.push(
				fail(
					"request.status",
					`request status is ${request.status} while disclosure is unapproved`,
				),
			);
		} else {
			gates.push(pass("request.status", "request is pending operator disclosure approval"));
		}
	}

	gates.push(
		path.basename(requestPath) === "pro-review-request.json"
			? pass("request.path", "request path is explicit")
			: pending("request.path", "request path is nonstandard but explicit"),
	);
	return gates;
}

function canaryPolicyGates(
	canary: ProReviewNativeCanary,
	request: ProReviewRequest,
): ProReviewGate[] {
	const gates: ProReviewGate[] = [];
	gates.push(pass("nativeCanary.transport", "live canary transport is chrome-extension-native"));
	gates.push(pass("nativeCanary.model", "live canary selected Extended Pro"));
	gates.push(pass("nativeCanary.response", "live canary returned OK"));
	gates.push(
		canary.nativeStatus.extensionInstanceId === canary.extensionInstanceId
			? pass(
					"nativeCanary.extensionBinding",
					"native status and live canary share extension instance",
				)
			: fail(
					"nativeCanary.extensionBinding",
					"native status extension instance differs from canary",
				),
	);
	gates.push(
		canary.nativeStatus.extensionVersion === canary.extensionVersion
			? pass(
					"nativeCanary.extensionVersion",
					"native status and live canary share extension version",
				)
			: fail(
					"nativeCanary.extensionVersion",
					"native status extension version differs from canary",
				),
	);
	gates.push(
		canary.warnings.length === 0
			? pass("nativeCanary.warnings", "native canary emitted no warnings")
			: fail("nativeCanary.warnings", `native canary emitted ${canary.warnings.length} warning(s)`),
	);
	const requiredCheckFailures = requiredCanaryCheckFailures(canary);
	gates.push(
		requiredCheckFailures.length === 0
			? pass(
					"nativeCanary.requiredChecks",
					"native status, live canary, model, and no-fallback checks passed",
				)
			: fail("nativeCanary.requiredChecks", requiredCheckFailures.join("; ")),
	);
	const observedAtMs = Date.parse(canary.observedAt);
	const reverifiedAtMs = Date.parse(canary.reverifiedAt);
	gates.push(
		!Number.isNaN(observedAtMs) && !Number.isNaN(reverifiedAtMs) && observedAtMs <= reverifiedAtMs
			? pass("nativeCanary.timestamps", "native canary timestamps are parseable and ordered")
			: fail("nativeCanary.timestamps", "native canary timestamps are invalid or out of order"),
	);
	gates.push(
		request.fallbackAllowed === false
			? pass("nativeCanary.noFallback", "canary evidence is compatible with no-fallback request")
			: fail("nativeCanary.noFallback", "request allows fallback"),
	);
	return gates;
}

function payloadDigestFailures(request: ProReviewRequest): string[] {
	const failures = [];
	const selectedFileContentsSha256 = digestSelectedFileContents(request.selectedFiles);
	const transportEvidenceSha256 = digestFile(request.transportEvidence);
	const payload = {
		reviewer: request.reviewer,
		transport: request.transport,
		model: request.model,
		fallbackAllowed: request.fallbackAllowed,
		transportEvidence: request.transportEvidence,
		blockedFallbacks: request.blockedFallbacks,
		prompt: request.prompt,
		selectedFiles: request.selectedFiles,
		selectedFileContentsSha256,
		transportEvidenceSha256,
	};
	const expectedPayload = digestJson(payload);
	const expectedPrompt = digestText(request.prompt);
	const expectedSelectedFiles = digestJson(request.selectedFiles);
	if (request.payloadBinding.payloadSha256 !== expectedPayload) {
		failures.push(
			"payloadSha256 does not match review content, selected files, and native evidence",
		);
	}
	if (request.payloadBinding.promptSha256 !== expectedPrompt) {
		failures.push("promptSha256 does not match prompt");
	}
	if (request.payloadBinding.selectedFilesSha256 !== expectedSelectedFiles) {
		failures.push("selectedFilesSha256 does not match selectedFiles");
	}
	if (request.payloadBinding.selectedFileContentsSha256 !== selectedFileContentsSha256) {
		failures.push("selectedFileContentsSha256 does not match selected file contents");
	}
	if (request.payloadBinding.transportEvidenceSha256 !== transportEvidenceSha256) {
		failures.push("transportEvidenceSha256 does not match transport evidence file");
	}
	return failures;
}

function digestSelectedFileContents(selectedFiles: readonly string[]): string {
	return digestJson(
		selectedFiles.map((file) => {
			const resolved = resolveHermesArtifactPath(file);
			if (!fs.existsSync(resolved)) return { file, missing: true };
			return {
				file,
				sha256: crypto.createHash("sha256").update(fs.readFileSync(resolved)).digest("hex"),
			};
		}),
	);
}

function digestFile(file: string): string {
	const resolved = resolveHermesArtifactPath(file);
	if (!fs.existsSync(resolved)) return digestJson({ file, missing: true });
	return `sha256:${crypto.createHash("sha256").update(fs.readFileSync(resolved)).digest("hex")}`;
}

function semanticEvidenceGates(request: ProReviewRequest): ProReviewGate[] {
	const gates: ProReviewGate[] = [];
	if (request.selectedFiles.includes("artifacts/hermes/probes/execution-cli-headless.json")) {
		gates.push(cliHeadlessEvidenceGate("artifacts/hermes/probes/execution-cli-headless.json"));
	}
	return gates;
}

function cliHeadlessEvidenceGate(reportPath: string): ProReviewGate {
	const resolved = resolveHermesArtifactPath(reportPath);
	let raw: unknown;
	try {
		raw = JSON.parse(fs.readFileSync(resolved, "utf8")) as unknown;
	} catch (error) {
		return fail(
			"request.cliHeadlessEvidence",
			`cli_headless evidence cannot be read: ${
				error instanceof Error ? error.message : String(error)
			}`,
		);
	}
	if (!isRecord(raw)) {
		return fail("request.cliHeadlessEvidence", "cli_headless evidence must be a JSON object");
	}
	if (raw.status === "pass") {
		try {
			readHermesCliHeadlessProbeReport(resolved);
			return pass(
				"request.cliHeadlessEvidence",
				"cli_headless pass evidence passes current semantic validator",
			);
		} catch (error) {
			return fail(
				"request.cliHeadlessEvidence",
				`cli_headless pass evidence is not accepted by the current validator: ${
					error instanceof Error ? error.message : String(error)
				}`,
			);
		}
	}
	const explicitRedFailure = explicitCliHeadlessRedFailure(raw);
	if (explicitRedFailure) {
		return fail("request.cliHeadlessEvidence", explicitRedFailure);
	}
	return pass(
		"request.cliHeadlessEvidence",
		`cli_headless evidence is explicitly red: ${String(raw.summary ?? "readiness failed")}`,
	);
}

function explicitCliHeadlessRedFailure(raw: Record<string, unknown>): string | null {
	if (raw.schemaVersion !== "telclaude.hermes.probe-result.v1") {
		return "cli_headless evidence has an unsupported schemaVersion";
	}
	if (raw.probeId !== "execution.cli_headless") {
		return `cli_headless evidence probeId is ${String(raw.probeId)}`;
	}
	if (raw.status !== "fail") {
		return `cli_headless evidence status is ${String(raw.status)}`;
	}
	if (raw.ran !== false) {
		return "red cli_headless evidence must be a pre-run readiness failure";
	}
	if ("exitCode" in raw || "provenance" in raw) {
		return "pre-run cli_headless readiness failure must not carry run provenance";
	}
	if (!isRecord(raw.readiness)) {
		return "red cli_headless evidence readiness is missing";
	}
	if (raw.readiness.status !== "fail") {
		return "red cli_headless evidence readiness status is not fail";
	}
	if (!Array.isArray(raw.readiness.gates)) {
		return "red cli_headless evidence readiness gates are missing";
	}
	if (!raw.readiness.gates.some((gate) => isRecord(gate) && gate.status === "fail")) {
		return "red cli_headless evidence has no failed readiness gate";
	}
	return null;
}

function requiredCanaryCheckFailures(canary: ProReviewNativeCanary): string[] {
	const checks = new Map(canary.checks.map((check) => [check.name, check]));
	const failures = [
		"native.status",
		"native.liveCanary",
		"model.extendedPro",
		"fallback.disabled",
	].flatMap((name) => {
		const check = checks.get(name);
		return check?.status === "pass" ? [] : [`${name} check is missing or not pass`];
	});
	if (
		canary.nativeStatus.command !==
		"YOETZ_AGENT=1 yoetz browser extension status --chatgpt --format json"
	) {
		failures.push("native status command is not the Yoetz extension status command");
	}
	if (
		canary.dryCanary.command !==
		"YOETZ_AGENT=1 yoetz browser extension canary --chatgpt --format json"
	) {
		failures.push("dry canary command is not the Yoetz extension dry canary command");
	}
	if (
		!canary.liveCanary.command.startsWith(
			"YOETZ_AGENT=1 yoetz browser extension canary --chatgpt --live",
		)
	) {
		failures.push("live canary command is not the Yoetz extension live canary command");
	}
	if (!/\s--extension-instance-id\s+\S+/.test(canary.liveCanary.command)) {
		failures.push("live canary command does not bind an extension instance");
	} else {
		const boundExtensionInstance = flagValue(canary.liveCanary.command, "--extension-instance-id");
		if (boundExtensionInstance !== canary.extensionInstanceId) {
			failures.push(
				`live canary command binds extension instance ${String(
					boundExtensionInstance,
				)}, expected ${canary.extensionInstanceId}`,
			);
		}
	}
	if (!/\s--format\s+json(?:\s|$)/.test(canary.liveCanary.command)) {
		failures.push("live canary command does not request JSON output");
	}
	for (const [label, command] of [
		["native status", canary.nativeStatus.command],
		["dry canary", canary.dryCanary.command],
		["live canary", canary.liveCanary.command],
	] as const) {
		if (containsBlockedFallback(command)) {
			failures.push(`${label} command contains a blocked fallback`);
		}
	}
	return failures;
}

function flagValue(command: string, flag: string): string | null {
	const escapedFlag = flag.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
	const match = command.match(new RegExp(`(?:^|\\s)${escapedFlag}\\s+(\\S+)`));
	return match?.[1] ?? null;
}

function containsBlockedFallback(command: string): boolean {
	return [
		/(?:^|\s)--cdp(?:\s|=|$)/i,
		/(?:^|\s)--api-key(?:\s|=|$)/i,
		/\bbrowser\s+recipe\b/i,
		/\bmanual\b/i,
		/\bclaude\b/i,
		/\bamq\b/i,
	].some((pattern) => pattern.test(command));
}

function readAndParse<T>(
	pathname: string,
	schema: z.ZodType<T>,
): { ok: true; value: T } | { ok: false; error: string } {
	const resolved = resolveHermesArtifactPath(pathname);
	try {
		const raw = JSON.parse(fs.readFileSync(resolved, "utf8")) as unknown;
		const parsed = schema.safeParse(raw);
		if (!parsed.success) {
			return { ok: false, error: flattenZodError(parsed.error) };
		}
		return { ok: true, value: parsed.data };
	} catch (error) {
		return {
			ok: false,
			error: String(error instanceof Error ? error.message : error),
		};
	}
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function digestJson(value: unknown): string {
	return digestText(JSON.stringify(value));
}

function digestText(value: string): string {
	return `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
}

function normalizeArtifactPath(value: string): string {
	return path.relative(process.cwd(), resolveHermesArtifactPath(value));
}

function flattenZodError(error: z.ZodError): string {
	return error.issues
		.map((issue) => {
			const pathLabel = issue.path.length > 0 ? issue.path.join(".") : "<root>";
			return `${pathLabel}: ${issue.message}`;
		})
		.join("; ");
}

function pass(name: string, detail: string): ProReviewGate {
	return { name, status: "pass", detail };
}

function fail(name: string, detail: string): ProReviewGate {
	return { name, status: "fail", detail };
}

function pending(name: string, detail: string): ProReviewGate {
	return { name, status: "pending", detail };
}
