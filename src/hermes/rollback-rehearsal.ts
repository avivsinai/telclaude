import crypto from "node:crypto";
import fs from "node:fs";
import {
	type InternalResponseProof,
	internalResponseProofVerificationFailure,
} from "../internal-auth.js";
import {
	relayGetHermesPrivateRuntimeState,
	relaySetHermesPrivateRuntimeMode,
} from "../relay/capabilities-client.js";
import {
	HERMES_ROLLBACK_CONTROL_SURFACE,
	HERMES_ROLLBACK_OBSERVATION_SURFACE,
	HERMES_ROLLBACK_RELAY_PUBLIC_KEY_ENV,
	HERMES_ROLLBACK_RELAY_PUBLIC_KEY_LOCK_ENV,
	HERMES_ROLLBACK_RELAY_PUBLIC_KEY_LOCK_PATH,
	type HermesArtifactWriteOptions,
	type RollbackRehearsal,
	resolveHermesArtifactPath,
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
type RelayPublicKeyProvenance = NonNullable<RollbackRehearsal["relayPublicKey"]>;

export async function runHermesRollbackRehearsal(input: {
	readonly allowRun: boolean;
	readonly evidencePath: string;
	readonly relay?: HermesRollbackRelayClient;
	readonly now?: () => string;
}): Promise<RollbackRehearsal> {
	const now = input.now ?? (() => new Date().toISOString());
	const checks: RollbackCheck[] = [];
	const relayPublicKeyLookup = rollbackRelayPublicKeyFromEnv();
	const relayPublicKey = relayPublicKeyLookup.relayPublicKey;
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
			relayPublicKey,
			checks,
		};
	}

	checks.push(pass("rollback.allowed", "operator allowed a relay-observed rollback rehearsal"));
	if (relayPublicKeyLookup.failure) {
		checks.push(fail("rollback.relayPublicKey", relayPublicKeyLookup.failure));
	} else if (relayPublicKey) {
		checks.push(
			pass(
				"rollback.relayPublicKey",
				"relay public key provenance matched the trusted rollback lockfile",
			),
		);
	}
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
		return buildEvidence(
			input.evidencePath,
			now(),
			checks,
			relayPublicKey,
			before,
			after,
			afterControl,
		);
	}
	if (!before || !afterControl || !after) {
		checks.push(fail("rollback.controlSurface", "relay control surface returned no state"));
		return buildEvidence(
			input.evidencePath,
			now(),
			checks,
			relayPublicKey,
			before,
			after,
			afterControl,
		);
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

	return buildEvidence(
		input.evidencePath,
		now(),
		checks,
		relayPublicKey,
		before,
		after,
		afterControl,
	);
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
	relayPublicKey?: RollbackRehearsal["relayPublicKey"],
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
		relayPublicKey,
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

function rollbackRelayPublicKeyFromEnv():
	| { readonly relayPublicKey?: RelayPublicKeyProvenance; readonly failure?: undefined }
	| { readonly relayPublicKey?: undefined; readonly failure: string } {
	const value = process.env[HERMES_ROLLBACK_RELAY_PUBLIC_KEY_ENV];
	if (!value) return {};
	const sha256 = `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
	const locked = rollbackRelayPublicKeyLockEntry(value, sha256);
	if (!locked.valid) {
		return { failure: locked.failure };
	}
	return {
		relayPublicKey: {
			scope: "operator",
			envKey: HERMES_ROLLBACK_RELAY_PUBLIC_KEY_ENV,
			value,
			sha256,
			source: locked.value.source,
		},
	};
}

function rollbackRelayPublicKeyLockEntry(
	value: string,
	sha256: string,
):
	| { readonly valid: true; readonly value: { readonly source: string } }
	| { readonly valid: false; readonly failure: string } {
	const lockPath =
		process.env[HERMES_ROLLBACK_RELAY_PUBLIC_KEY_LOCK_ENV]?.trim() ||
		HERMES_ROLLBACK_RELAY_PUBLIC_KEY_LOCK_PATH;
	const resolved = resolveHermesArtifactPath(lockPath);
	if (!fs.existsSync(resolved)) {
		return { valid: false, failure: `rollback relay public key lockfile is missing: ${lockPath}` };
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(fs.readFileSync(resolved, "utf8")) as unknown;
	} catch (error) {
		return {
			valid: false,
			failure: `rollback relay public key lockfile is invalid: ${
				error instanceof Error ? error.message : String(error)
			}`,
		};
	}
	if (
		typeof parsed !== "object" ||
		parsed === null ||
		(parsed as { schemaVersion?: unknown }).schemaVersion !==
			"telclaude.hermes.rollback-relay-public-key-lock.v1" ||
		!Array.isArray((parsed as { keys?: unknown }).keys)
	) {
		return { valid: false, failure: "rollback relay public key lockfile is invalid" };
	}
	const locked = (parsed as { keys: Array<Record<string, unknown>> }).keys.find(
		(key) =>
			key.scope === "operator" &&
			key.envKey === HERMES_ROLLBACK_RELAY_PUBLIC_KEY_ENV &&
			key.value === value &&
			key.sha256 === sha256 &&
			typeof key.source === "string" &&
			key.source.trim() &&
			typeof key.sourceSha256 === "string" &&
			/^sha256:[a-f0-9]{64}$/i.test(key.sourceSha256),
	);
	if (!locked) {
		return {
			valid: false,
			failure:
				"rollback relay public key is not pinned by value, sha256, source, and sourceSha256 in the trusted lockfile",
		};
	}
	const source = locked.source as string;
	const sourcePath = resolveHermesArtifactPath(source);
	if (!fs.existsSync(sourcePath)) {
		return {
			valid: false,
			failure: `rollback relay public key source artifact is missing: ${source}`,
		};
	}
	const sourceBytes = fs.readFileSync(sourcePath);
	const sourceSha256 = `sha256:${crypto.createHash("sha256").update(sourceBytes).digest("hex")}`;
	if (sourceSha256 !== locked.sourceSha256) {
		return {
			valid: false,
			failure: "rollback relay public key source artifact sha256 does not match lockfile",
		};
	}
	const sourceFailure = rollbackRelayPublicKeySourceArtifactFailure(sourceBytes.toString("utf8"), {
		source,
		value,
		sha256,
	});
	if (sourceFailure) {
		return { valid: false, failure: sourceFailure };
	}
	return { valid: true, value: { source } };
}

function rollbackRelayPublicKeySourceArtifactFailure(
	sourceText: string,
	locked: { readonly source: string; readonly value: string; readonly sha256: string },
): string | undefined {
	let parsed: unknown;
	try {
		parsed = JSON.parse(sourceText) as unknown;
	} catch (error) {
		return `rollback relay public key source artifact is invalid: ${
			error instanceof Error ? error.message : String(error)
		}`;
	}
	if (
		typeof parsed !== "object" ||
		parsed === null ||
		(parsed as { schemaVersion?: unknown }).schemaVersion !==
			"telclaude.hermes.rollback-relay-public-key-source.v1" ||
		!Array.isArray((parsed as { keys?: unknown }).keys)
	) {
		return "rollback relay public key source artifact is invalid";
	}
	const sourceKey = (parsed as { keys: Array<Record<string, unknown>> }).keys.find(
		(key) =>
			key.scope === "operator" &&
			key.envKey === HERMES_ROLLBACK_RELAY_PUBLIC_KEY_ENV &&
			key.value === locked.value &&
			key.sha256 === locked.sha256,
	);
	if (!sourceKey) {
		return "rollback relay public key source artifact does not contain the pinned key";
	}
	if (
		sourceKey.sha256 !== `sha256:${crypto.createHash("sha256").update(locked.value).digest("hex")}`
	) {
		return "rollback relay public key source artifact sha256 does not match value";
	}
	return undefined;
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
	const proofFailure = internalResponseProofVerificationFailure(
		proof.proof,
		expectedRequest.method,
		expectedRequest.path,
		expectedRequest.body,
		proof.responseBody,
		{ scope: "operator" },
	);
	if (proofFailure) {
		failures.push(`${label} relay proof invalid: ${proofFailure}`);
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
