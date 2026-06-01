import { type InternalResponseProof, verifyInternalResponseProof } from "../internal-auth.js";
import {
	relayGetHermesPrivateRuntimeState,
	relaySetHermesPrivateRuntimeMode,
} from "../relay/capabilities-client.js";
import {
	HERMES_ROLLBACK_CONTROL_SURFACE,
	HERMES_ROLLBACK_OBSERVATION_SURFACE,
	type HermesArtifactWriteOptions,
	type RollbackRehearsal,
	writeHermesJsonArtifact,
} from "./foundation.js";
import {
	HERMES_PRIVATE_RUNTIME_FALLBACK_PATH,
	type HermesPrivateRuntimeControlMode,
	type HermesPrivateRuntimeControlSource,
} from "./private-runtime-control.js";

export const DEFAULT_HERMES_ROLLBACK_REHEARSAL_EVIDENCE_PATH =
	"artifacts/hermes/rollback-rehearsal.json";

export type HermesRollbackRelayState = {
	readonly ok: true;
	readonly effectiveMode: HermesPrivateRuntimeControlMode;
	readonly effectiveValue: "1" | "0";
	readonly rolloutAllowed: boolean;
	readonly rolloutEnvValue?: string;
	readonly controlMode: HermesPrivateRuntimeControlMode;
	readonly controlSource: HermesPrivateRuntimeControlSource;
	readonly fallbackPath: string;
	readonly relayProof?: HermesRollbackRelayProof;
};

export type HermesRollbackRelayProof = {
	readonly request: {
		readonly method: string;
		readonly path: string;
		readonly body: string;
	};
	readonly responseBody: string;
	readonly proof: InternalResponseProof;
};

export type HermesRollbackRelayClient = {
	getStatus(): Promise<HermesRollbackRelayState>;
	setMode(mode: HermesPrivateRuntimeControlMode): Promise<HermesRollbackRelayState>;
};

type RollbackCheck = NonNullable<RollbackRehearsal["checks"]>[number];

export async function runHermesRollbackRehearsal(input: {
	readonly allowRun: boolean;
	readonly evidencePath: string;
	readonly relay?: HermesRollbackRelayClient;
	readonly now?: () => string;
}): Promise<RollbackRehearsal> {
	const now = input.now ?? (() => new Date().toISOString());
	const checks: RollbackCheck[] = [];
	if (!input.allowRun) {
		checks.push(fail("rollback.allowed", "rollback rehearsal requires --allow-run"));
		return {
			schemaVersion: 1,
			passed: false,
			evidence_path: input.evidencePath,
			allowedToRun: false,
			observedAt: now(),
			controlSurface: HERMES_ROLLBACK_CONTROL_SURFACE,
			observationSurface: HERMES_ROLLBACK_OBSERVATION_SURFACE,
			checks,
		};
	}

	checks.push(pass("rollback.allowed", "operator allowed a relay-observed rollback rehearsal"));
	const relay = input.relay ?? createHermesRollbackRelayClient();
	let before: HermesRollbackRelayState | undefined;
	let afterControl: HermesRollbackRelayState | undefined;
	let after: HermesRollbackRelayState | undefined;
	try {
		before = await relay.getStatus();
		afterControl = await relay.setMode("legacy");
		after = await relay.getStatus();
	} catch (error) {
		checks.push(
			fail(
				"rollback.controlSurface",
				`relay durable control surface failed: ${error instanceof Error ? error.message : String(error)}`,
			),
		);
		return buildEvidence(input.evidencePath, now(), checks, before, after, afterControl);
	}
	if (!before || !afterControl || !after) {
		checks.push(fail("rollback.controlSurface", "relay control surface returned no state"));
		return buildEvidence(input.evidencePath, now(), checks, before, after, afterControl);
	}

	const relayProofFailures = [
		...relayProofEvidenceFailures("before", before, {
			method: "POST",
			path: "/v1/hermes.private-runtime.status",
			body: "{}",
		}),
		...relayProofEvidenceFailures("afterControl", afterControl, {
			method: "POST",
			path: "/v1/hermes.private-runtime.mode",
			body: JSON.stringify({ mode: "legacy" }),
		}),
		...relayProofEvidenceFailures("after", after, {
			method: "POST",
			path: "/v1/hermes.private-runtime.status",
			body: "{}",
		}),
	];
	checks.push(
		relayProofFailures.length === 0
			? pass("rollback.relayProofs", "relay signed every rollback observation")
			: fail("rollback.relayProofs", relayProofFailures.join("; ")),
	);
	checks.push(
		before.effectiveValue === "1" && before.effectiveMode === "hermes"
			? pass("rollback.flagBefore", "relay observed Hermes private runtime enabled before rollback")
			: fail(
					"rollback.flagBefore",
					`relay observed ${before.effectiveValue}/${before.effectiveMode} before rollback`,
				),
	);
	checks.push(
		after.effectiveValue === "0" && after.effectiveMode === "legacy"
			? pass("rollback.flagAfter", "relay observed Hermes private runtime disabled after rollback")
			: fail(
					"rollback.flagAfter",
					`relay observed ${after.effectiveValue}/${after.effectiveMode} after rollback`,
				),
	);
	checks.push(
		after.fallbackPath === HERMES_PRIVATE_RUNTIME_FALLBACK_PATH
			? pass("rollback.fallbackPath", "pre-Hermes fallback path observed")
			: fail("rollback.fallbackPath", `unexpected fallback path ${after.fallbackPath}`),
	);
	checks.push(
		afterControl.controlMode === "legacy" && afterControl.controlSource === "runtime-config"
			? pass("rollback.controlSurface", "relay durable runtime config accepted legacy mode")
			: fail(
					"rollback.controlSurface",
					`relay control returned ${afterControl.controlMode}/${afterControl.controlSource}`,
				),
	);
	checks.push(
		after.controlSource === "runtime-config"
			? pass(
					"rollback.observedSources",
					"rollback observations came from relay effective-mode status",
				)
			: fail("rollback.observedSources", `after rollback source was ${after.controlSource}`),
	);

	return buildEvidence(input.evidencePath, now(), checks, before, after, afterControl);
}

export function writeHermesRollbackRehearsalEvidence(
	evidence: RollbackRehearsal,
	evidencePath: string = evidence.evidence_path,
	options: HermesArtifactWriteOptions = {},
): boolean {
	if (evidence.allowedToRun !== true || evidence.passed !== true) return false;
	writeHermesJsonArtifact(evidencePath, evidence, { ...options, mode: 0o600 });
	return true;
}

function createHermesRollbackRelayClient(): HermesRollbackRelayClient {
	return {
		getStatus: () => relayGetHermesPrivateRuntimeState(),
		setMode: (mode) => relaySetHermesPrivateRuntimeMode({ mode }),
	};
}

function buildEvidence(
	evidencePath: string,
	observedAt: string,
	checks: RollbackCheck[],
	before?: HermesRollbackRelayState,
	after?: HermesRollbackRelayState,
	afterControl?: HermesRollbackRelayState,
): RollbackRehearsal {
	return {
		schemaVersion: 1,
		passed: checks.length > 0 && checks.every((check) => check.status === "pass"),
		evidence_path: evidencePath,
		allowedToRun: true,
		observedBeforeValue: before?.effectiveValue,
		observedAfterValue: after?.effectiveValue,
		observedFallbackPath: after?.fallbackPath ?? before?.fallbackPath,
		observedAt,
		controlSurface: HERMES_ROLLBACK_CONTROL_SURFACE,
		observationSurface: HERMES_ROLLBACK_OBSERVATION_SURFACE,
		observedBeforeSource: before ? "relay-effective-mode" : undefined,
		observedAfterSource: after ? "relay-effective-mode" : undefined,
		observedAfterControlSource: afterControl?.controlSource,
		signedRelayTranscripts:
			before?.relayProof && afterControl?.relayProof && after?.relayProof
				? {
						before: before.relayProof,
						afterControl: afterControl.relayProof,
						after: after.relayProof,
					}
				: undefined,
		checks,
	};
}

function relayProofEvidenceFailures(
	label: "before" | "afterControl" | "after",
	state: HermesRollbackRelayState | undefined,
	expectedRequest: { method: string; path: string; body: string },
): string[] {
	if (!state) return [`${label} relay state is missing`];
	const proof = state.relayProof;
	if (!proof) return [`${label} relay proof is missing`];
	const failures: string[] = [];
	if (proof.request.method !== expectedRequest.method) {
		failures.push(`${label} relay proof method is ${proof.request.method}`);
	}
	if (proof.request.path !== expectedRequest.path) {
		failures.push(`${label} relay proof path is ${proof.request.path}`);
	}
	if (proof.request.body !== expectedRequest.body) {
		failures.push(`${label} relay proof request body does not match`);
	}
	if (
		!verifyInternalResponseProof(
			proof.proof,
			expectedRequest.method,
			expectedRequest.path,
			expectedRequest.body,
			proof.responseBody,
			{ scope: "operator" },
		)
	) {
		failures.push(`${label} relay proof signature is invalid`);
	}
	const signedState = parseRelayStateBody(proof.responseBody);
	if (!signedState) {
		failures.push(`${label} relay proof response body is invalid`);
		return failures;
	}
	const unsignedState = unsignedRelayState(state);
	for (const key of Object.keys(unsignedState) as Array<
		keyof ReturnType<typeof unsignedRelayState>
	>) {
		if (signedState[key] !== unsignedState[key]) {
			failures.push(`${label} relay proof response ${String(key)} does not match state`);
		}
	}
	return failures;
}

function parseRelayStateBody(
	responseBody: string,
): ReturnType<typeof unsignedRelayState> | undefined {
	try {
		const parsed = JSON.parse(responseBody) as Partial<ReturnType<typeof unsignedRelayState>>;
		if (parsed.ok !== true) return undefined;
		if (parsed.effectiveMode !== "hermes" && parsed.effectiveMode !== "legacy") return undefined;
		if (parsed.effectiveValue !== "1" && parsed.effectiveValue !== "0") return undefined;
		if (typeof parsed.rolloutAllowed !== "boolean") return undefined;
		if (parsed.rolloutEnvValue !== undefined && typeof parsed.rolloutEnvValue !== "string") {
			return undefined;
		}
		if (parsed.controlMode !== "hermes" && parsed.controlMode !== "legacy") return undefined;
		if (
			parsed.controlSource !== "env-disabled" &&
			parsed.controlSource !== "runtime-config" &&
			parsed.controlSource !== "runtime-config-default" &&
			parsed.controlSource !== "runtime-config-invalid"
		) {
			return undefined;
		}
		if (typeof parsed.fallbackPath !== "string" || parsed.fallbackPath.length === 0) {
			return undefined;
		}
		return {
			ok: true,
			effectiveMode: parsed.effectiveMode,
			effectiveValue: parsed.effectiveValue,
			rolloutAllowed: parsed.rolloutAllowed,
			rolloutEnvValue: parsed.rolloutEnvValue,
			controlMode: parsed.controlMode,
			controlSource: parsed.controlSource,
			fallbackPath: parsed.fallbackPath,
		};
	} catch {
		return undefined;
	}
}

function unsignedRelayState(state: HermesRollbackRelayState) {
	return {
		ok: state.ok,
		effectiveMode: state.effectiveMode,
		effectiveValue: state.effectiveValue,
		rolloutAllowed: state.rolloutAllowed,
		rolloutEnvValue: state.rolloutEnvValue,
		controlMode: state.controlMode,
		controlSource: state.controlSource,
		fallbackPath: state.fallbackPath,
	};
}

function pass(name: string, detail: string): RollbackCheck {
	return { name, status: "pass", detail };
}

function fail(name: string, detail: string): RollbackCheck {
	return { name, status: "fail", detail };
}
