import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
	HERMES_ROLLBACK_CONTROL_SURFACE,
	HERMES_ROLLBACK_OBSERVATION_SURFACE,
	HERMES_ROLLBACK_RELAY_PUBLIC_KEY_ENV,
	HERMES_ROLLBACK_RELAY_PUBLIC_KEY_LOCK_ENV,
} from "../../src/hermes/foundation.js";
import {
	type HermesRollbackRelayClient,
	type HermesRollbackRelayState,
	runHermesRollbackRehearsal,
	writeHermesRollbackRehearsalEvidence,
} from "../../src/hermes/rollback-rehearsal.js";
import { buildInternalResponseProof, generateKeyPair } from "../../src/internal-auth.js";

const ORIGINAL_ENV = {
	OPERATOR_RPC_RELAY_PRIVATE_KEY: process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY,
	OPERATOR_RPC_RELAY_PUBLIC_KEY: process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY,
	TELCLAUDE_HERMES_ROLLBACK_RELAY_PUBLIC_KEY_LOCK:
		process.env.TELCLAUDE_HERMES_ROLLBACK_RELAY_PUBLIC_KEY_LOCK,
};

describe("Hermes rollback rehearsal producer", () => {
	it("does not contact the relay or write evidence without --allow-run", async () => {
		const calls: string[] = [];
		const client: HermesRollbackRelayClient = {
			getStatus: async () => {
				calls.push("status");
				return hermesStatus();
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

	it("passes by observing Hermes before and after without a mutable mode selector", async () => {
		const lockedRelayPublicKey = installLockedRelayProofKeys();
		const calls: string[] = [];
		const client: HermesRollbackRelayClient = {
			getStatus: async () => {
				calls.push("status");
				return hermesStatus();
			},
		};

		const report = await runHermesRollbackRehearsal({
			allowRun: true,
			evidencePath: "artifacts/hermes/rollback-rehearsal.json",
			relay: client,
			now: () => "2026-05-30T14:45:00.000Z",
		});

		expect(calls).toEqual(["status", "status"]);
		expect(report).toMatchObject({
			schemaVersion: 1,
			passed: true,
			allowedToRun: true,
			observedBeforeValue: "1",
			observedAfterValue: "1",
			observedAt: "2026-05-30T14:45:00.000Z",
			controlSurface: HERMES_ROLLBACK_CONTROL_SURFACE,
			observationSurface: HERMES_ROLLBACK_OBSERVATION_SURFACE,
			observedBeforeSource: "relay-effective-mode",
			observedAfterSource: "relay-effective-mode",
			observedAfterControlSource: "hermes-only",
			relayPublicKey: {
				scope: "operator",
				envKey: HERMES_ROLLBACK_RELAY_PUBLIC_KEY_ENV,
				source: lockedRelayPublicKey.sourcePath,
			},
		});
		expect(report.checks?.every((check) => check.status === "pass")).toBe(true);
	});

	it("anchors relay public-key provenance to the trusted lockfile when it matches env", async () => {
		const { sourcePath } = installLockedRelayProofKeys();
		const relayPublicKey = process.env[HERMES_ROLLBACK_RELAY_PUBLIC_KEY_ENV];
		if (!relayPublicKey) throw new Error("expected relay public key");
		const relayPublicKeySha256 = `sha256:${crypto
			.createHash("sha256")
			.update(relayPublicKey)
			.digest("hex")}`;
		const calls: string[] = [];

		const report = await runHermesRollbackRehearsal({
			allowRun: true,
			evidencePath: "artifacts/hermes/rollback-rehearsal.json",
			relay: {
				getStatus: async () => {
					calls.push("status");
					return hermesStatus();
				},
			},
			now: () => "2026-05-30T14:45:00.000Z",
		});

		expect(report.passed).toBe(true);
		expect(calls).toEqual(["status", "status"]);
		expect(report.relayPublicKey).toMatchObject({
			envKey: HERMES_ROLLBACK_RELAY_PUBLIC_KEY_ENV,
			value: relayPublicKey,
			sha256: relayPublicKeySha256,
			source: sourcePath,
		});
	});

	it("fails provenance when the relay public key only comes from process env", async () => {
		installRelayProofKeys();
		const calls: string[] = [];

		const report = await runHermesRollbackRehearsal({
			allowRun: true,
			evidencePath: "artifacts/hermes/rollback-rehearsal.json",
			relay: {
				getStatus: async () => {
					calls.push("status");
					return hermesStatus();
				},
			},
			now: () => "2026-05-30T14:45:00.000Z",
		});

		expect(report.passed).toBe(false);
		expect(report.relayPublicKey).toBeUndefined();
		expect(report.checks?.find((check) => check.name === "rollback.relayPublicKey")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("trusted lockfile"),
		});
	});

	it("fails provenance when the locked source artifact digest changed", async () => {
		const { sourcePath } = installLockedRelayProofKeys();
		writeJson(sourcePath, {
			schemaVersion: "telclaude.hermes.rollback-relay-public-key-source.v1",
			keys: [],
		});
		const calls: string[] = [];

		const report = await runHermesRollbackRehearsal({
			allowRun: true,
			evidencePath: "artifacts/hermes/rollback-rehearsal.json",
			relay: {
				getStatus: async () => {
					calls.push("status");
					return hermesStatus();
				},
			},
		});

		expect(report.passed).toBe(false);
		expect(report.relayPublicKey).toBeUndefined();
		expect(report.checks?.find((check) => check.name === "rollback.relayPublicKey")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("source artifact sha256 does not match lockfile"),
		});
	});

	it("fails provenance when the lock entry has no source artifact digest", async () => {
		installLockedRelayProofKeys();
		const lockPath = process.env[HERMES_ROLLBACK_RELAY_PUBLIC_KEY_LOCK_ENV];
		if (!lockPath) throw new Error("expected lock path");
		const lock = JSON.parse(fs.readFileSync(lockPath, "utf8")) as {
			keys: Array<{ sourceSha256?: string }>;
		};
		if (lock.keys[0]) delete lock.keys[0].sourceSha256;
		writeJson(lockPath, lock);
		const calls: string[] = [];

		const report = await runHermesRollbackRehearsal({
			allowRun: true,
			evidencePath: "artifacts/hermes/rollback-rehearsal.json",
			relay: {
				getStatus: async () => {
					calls.push("status");
					return hermesStatus();
				},
			},
		});

		expect(report.passed).toBe(false);
		expect(report.relayPublicKey).toBeUndefined();
		expect(report.checks?.find((check) => check.name === "rollback.relayPublicKey")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("sourceSha256"),
		});
	});

	it("fails closed when the relay never observes Hermes-only state before rollback", async () => {
		installLockedRelayProofKeys();
		const client: HermesRollbackRelayClient = {
			getStatus: async () => malformedNonHermesStatus(),
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
		installLockedRelayProofKeys();
		const client: HermesRollbackRelayClient = {
			getStatus: async () => {
				throw new Error("relay offline");
			},
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
	restoreEnv(
		HERMES_ROLLBACK_RELAY_PUBLIC_KEY_LOCK_ENV,
		ORIGINAL_ENV.TELCLAUDE_HERMES_ROLLBACK_RELAY_PUBLIC_KEY_LOCK,
	);
});

function hermesStatus(): HermesRollbackRelayState {
	const state = {
		ok: true as const,
		effectiveMode: "hermes" as const,
		effectiveValue: "1" as const,
		controlMode: "hermes" as const,
		controlSource: "hermes-only" as const,
	};
	return {
		...state,
		relayProof: signedRelayTranscript("/v1/hermes.private-runtime.status", "{}", state),
	} as HermesRollbackRelayState;
}

function malformedNonHermesStatus(): HermesRollbackRelayState {
	const state = {
		ok: true as const,
		effectiveMode: "disabled",
		effectiveValue: "0",
		controlMode: "disabled",
		controlSource: "malformed",
	};
	return {
		...state,
		relayProof: signedRelayTranscript("/v1/hermes.private-runtime.status", "{}", state),
	} as unknown as HermesRollbackRelayState;
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
	return keys;
}

function installLockedRelayProofKeys(options: { sourceSha256?: string } = {}): {
	readonly sourcePath: string;
	readonly lockPath: string;
} {
	const keys = installRelayProofKeys();
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-rollback-key-lock-"));
	const sourcePath = path.join(tempDir, "rollback-relay-public-key-source.json");
	const lockPath = path.join(tempDir, "rollback-relay-public-key.lock.json");
	const relayPublicKeySha256 = `sha256:${crypto
		.createHash("sha256")
		.update(keys.publicKey)
		.digest("hex")}`;
	const sourceKey = {
		scope: "operator",
		envKey: HERMES_ROLLBACK_RELAY_PUBLIC_KEY_ENV,
		value: keys.publicKey,
		sha256: relayPublicKeySha256,
	};
	writeJson(sourcePath, {
		schemaVersion: "telclaude.hermes.rollback-relay-public-key-source.v1",
		keys: [sourceKey],
	});
	writeJson(lockPath, {
		schemaVersion: "telclaude.hermes.rollback-relay-public-key-lock.v1",
		keys: [
			{
				...sourceKey,
				source: sourcePath,
				sourceSha256: options.sourceSha256 ?? sha256FileDigest(sourcePath),
			},
		],
	});
	process.env[HERMES_ROLLBACK_RELAY_PUBLIC_KEY_LOCK_ENV] = lockPath;
	return { sourcePath, lockPath };
}

function restoreEnv(key: string, value: string | undefined): void {
	if (value === undefined) {
		delete process.env[key];
	} else {
		process.env[key] = value;
	}
}

function writeJson(pathname: string, value: unknown): void {
	fs.mkdirSync(path.dirname(pathname), { recursive: true });
	fs.writeFileSync(pathname, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function sha256FileDigest(pathname: string): string {
	return `sha256:${crypto.createHash("sha256").update(fs.readFileSync(pathname)).digest("hex")}`;
}
