import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
	HERMES_ROLLBACK_CONTROL_SURFACE,
	HERMES_ROLLBACK_OBSERVATION_SURFACE,
	HERMES_ROLLBACK_RELAY_PUBLIC_KEY_ENV,
} from "../../src/hermes/foundation.js";
import {
	type HermesRollbackRelayClient,
	runHermesRollbackRehearsal,
	writeHermesRollbackRehearsalEvidence,
} from "../../src/hermes/rollback-rehearsal.js";
import { buildInternalResponseProof, generateKeyPair } from "../../src/internal-auth.js";

const ORIGINAL_ENV = {
	OPERATOR_RPC_RELAY_PRIVATE_KEY: process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY,
	OPERATOR_RPC_RELAY_PUBLIC_KEY: process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY,
};

describe("Hermes rollback rehearsal producer", () => {
	it("does not contact the relay or write evidence without --allow-run", async () => {
		const calls: string[] = [];
		const client: HermesRollbackRelayClient = {
			getStatus: async () => {
				calls.push("status");
				return hermesStatus();
			},
			setMode: async () => {
				calls.push("set");
				return legacyStatus();
			},
		};
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-rollback-"));
		const evidencePath = path.join(tempDir, "rollback.json");

		const report = await runHermesRollbackRehearsal({
			allowRun: false,
			evidencePath,
			relay: client,
		});
		const written = writeHermesRollbackRehearsalEvidence(report, evidencePath);

		expect(report).toMatchObject({ passed: false, allowedToRun: false });
		expect(report.checks?.find((check) => check.name === "rollback.allowed")).toMatchObject({
			status: "fail",
		});
		expect(calls).toEqual([]);
		expect(written).toBe(false);
		expect(fs.existsSync(evidencePath)).toBe(false);
	});

	it("passes only by observing enabled mode, driving durable legacy mode, then observing disabled mode", async () => {
		installRelayProofKeys();
		const calls: string[] = [];
		const client: HermesRollbackRelayClient = {
			getStatus: async () => {
				calls.push("status");
				return calls.length === 1 ? hermesStatus() : legacyStatusAfterRead();
			},
			setMode: async (mode) => {
				calls.push(`set:${mode}`);
				return legacyStatus();
			},
		};

		const report = await runHermesRollbackRehearsal({
			allowRun: true,
			evidencePath: "artifacts/hermes/rollback-rehearsal.json",
			relay: client,
			now: () => "2026-05-30T14:45:00.000Z",
		});

		expect(calls).toEqual(["status", "set:legacy", "status"]);
		expect(report).toMatchObject({
			schemaVersion: 1,
			passed: true,
			allowedToRun: true,
			observedBeforeValue: "1",
			observedAfterValue: "0",
			observedFallbackPath: "telclaude.private-runtime.legacy",
			observedAt: "2026-05-30T14:45:00.000Z",
			controlSurface: HERMES_ROLLBACK_CONTROL_SURFACE,
			observationSurface: HERMES_ROLLBACK_OBSERVATION_SURFACE,
			observedBeforeSource: "relay-effective-mode",
			observedAfterSource: "relay-effective-mode",
			observedAfterControlSource: "runtime-config",
			relayPublicKey: {
				scope: "operator",
				envKey: HERMES_ROLLBACK_RELAY_PUBLIC_KEY_ENV,
				source: "process-env",
			},
		});
		expect(report.checks?.every((check) => check.status === "pass")).toBe(true);
	});

	it("fails closed when the relay never observes Hermes mode before rollback", async () => {
		installRelayProofKeys();
		const client: HermesRollbackRelayClient = {
			getStatus: async () => legacyStatusAfterRead(),
			setMode: async () => legacyStatus(),
		};

		const report = await runHermesRollbackRehearsal({
			allowRun: true,
			evidencePath: "artifacts/hermes/rollback-rehearsal.json",
			relay: client,
		});

		expect(report.passed).toBe(false);
		expect(report.checks?.find((check) => check.name === "rollback.flagBefore")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("observed 0"),
		});
	});

	it("fails closed when the relay control surface is unreachable", async () => {
		const client: HermesRollbackRelayClient = {
			getStatus: async () => {
				throw new Error("relay offline");
			},
			setMode: async () => legacyStatus(),
		};

		const report = await runHermesRollbackRehearsal({
			allowRun: true,
			evidencePath: "artifacts/hermes/rollback-rehearsal.json",
			relay: client,
		});

		expect(report.passed).toBe(false);
		expect(report.checks?.find((check) => check.name === "rollback.controlSurface")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("relay offline"),
		});
	});
});

afterEach(() => {
	restoreEnv("OPERATOR_RPC_RELAY_PRIVATE_KEY", ORIGINAL_ENV.OPERATOR_RPC_RELAY_PRIVATE_KEY);
	restoreEnv("OPERATOR_RPC_RELAY_PUBLIC_KEY", ORIGINAL_ENV.OPERATOR_RPC_RELAY_PUBLIC_KEY);
});

function hermesStatus() {
	const state = {
		ok: true as const,
		effectiveMode: "hermes" as const,
		effectiveValue: "1" as const,
		rolloutAllowed: true,
		rolloutEnvValue: "1",
		controlMode: "hermes" as const,
		controlSource: "runtime-config" as const,
		fallbackPath: "telclaude.private-runtime.legacy",
	};
	return {
		...state,
		relayProof: signedRelayTranscript("/v1/hermes.private-runtime.status", "{}", state),
	};
}

function legacyStatus() {
	const state = {
		ok: true as const,
		effectiveMode: "legacy" as const,
		effectiveValue: "0" as const,
		rolloutAllowed: true,
		rolloutEnvValue: "1",
		controlMode: "legacy" as const,
		controlSource: "runtime-config" as const,
		fallbackPath: "telclaude.private-runtime.legacy",
	};
	return {
		...state,
		relayProof: signedRelayTranscript(
			"/v1/hermes.private-runtime.mode",
			JSON.stringify({ mode: "legacy" }),
			state,
		),
	};
}

function legacyStatusAfterRead() {
	const state = legacyStatus();
	return {
		...state,
		relayProof: signedRelayTranscript("/v1/hermes.private-runtime.status", "{}", state),
	};
}

function signedRelayTranscript(
	requestPath: string,
	requestBody: string,
	state: Record<string, unknown>,
) {
	const { relayProof: _ignored, ...unsignedState } = state;
	const responseBody = JSON.stringify(unsignedState);
	return {
		request: { method: "POST", path: requestPath, body: requestBody },
		responseBody,
		proof: buildInternalResponseProof("POST", requestPath, requestBody, responseBody, {
			scope: "operator",
		}),
	};
}

function installRelayProofKeys() {
	const keys = generateKeyPair();
	process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = keys.privateKey;
	process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = keys.publicKey;
}

function restoreEnv(key: string, value: string | undefined): void {
	if (value === undefined) {
		delete process.env[key];
	} else {
		process.env[key] = value;
	}
}
