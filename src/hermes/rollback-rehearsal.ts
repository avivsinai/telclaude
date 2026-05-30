import fs from "node:fs";
import path from "node:path";
import {
	relayGetHermesPrivateRuntimeState,
	relaySetHermesPrivateRuntimeMode,
} from "../relay/capabilities-client.js";
import {
	HERMES_ROLLBACK_CONTROL_SURFACE,
	HERMES_ROLLBACK_OBSERVATION_SURFACE,
	type RollbackRehearsal,
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
): boolean {
	if (evidence.allowedToRun !== true) return false;
	fs.mkdirSync(path.dirname(evidencePath), { recursive: true });
	const tmpPath = `${evidencePath}.tmp.${process.pid}`;
	fs.writeFileSync(tmpPath, `${JSON.stringify(evidence, null, 2)}\n`, {
		encoding: "utf8",
		mode: 0o600,
	});
	fs.renameSync(tmpPath, evidencePath);
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
		checks,
	};
}

function pass(name: string, detail: string): RollbackCheck {
	return { name, status: "pass", detail };
}

function fail(name: string, detail: string): RollbackCheck {
	return { name, status: "fail", detail };
}
