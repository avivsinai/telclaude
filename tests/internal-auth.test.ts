import { afterEach, describe, expect, it, vi } from "vitest";
import {
	buildInternalResponseProof,
	generateKeyPair,
	internalResponseProofVerificationFailure,
	verifyInternalResponseProof,
} from "../src/internal-auth.js";

const ORIGINAL_OPERATOR_RELAY_PRIVATE_KEY = process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
const ORIGINAL_OPERATOR_RELAY_PUBLIC_KEY = process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;

describe("internal response proof verification", () => {
	afterEach(() => {
		restoreEnv("OPERATOR_RPC_RELAY_PRIVATE_KEY", ORIGINAL_OPERATOR_RELAY_PRIVATE_KEY);
		restoreEnv("OPERATOR_RPC_RELAY_PUBLIC_KEY", ORIGINAL_OPERATOR_RELAY_PUBLIC_KEY);
		vi.useRealTimers();
	});

	it("keeps live response proofs freshness-bound by default", () => {
		installOperatorRelayKeys();
		vi.useFakeTimers();
		vi.setSystemTime(new Date("2000-01-01T00:00:00.000Z"));
		const proof = buildInternalResponseProof("POST", "/v1/probe", "{}", '{"ok":true}', {
			scope: "operator",
		});

		vi.setSystemTime(new Date("2000-01-01T00:10:01.000Z"));

		expect(verifyInternalResponseProof(proof, "POST", "/v1/probe", "{}", '{"ok":true}')).toBe(
			false,
		);
	});

	it("can verify archived response proofs without disabling signature binding", () => {
		installOperatorRelayKeys();
		vi.useFakeTimers();
		vi.setSystemTime(new Date("2000-01-01T00:00:00.000Z"));
		const proof = buildInternalResponseProof("POST", "/v1/probe", "{}", '{"ok":true}', {
			scope: "operator",
		});

		vi.setSystemTime(new Date("2000-01-01T00:10:01.000Z"));

		expect(
			verifyInternalResponseProof(proof, "POST", "/v1/probe", "{}", '{"ok":true}', {
				scope: "operator",
				allowStale: true,
			}),
		).toBe(true);
		expect(
			verifyInternalResponseProof(proof, "POST", "/v1/probe", "{}", '{"ok":false}', {
				scope: "operator",
				allowStale: true,
			}),
		).toBe(false);
	});

	it("widens the freshness window only when maxSkewMs is supplied", () => {
		installOperatorRelayKeys();
		vi.useFakeTimers();
		vi.setSystemTime(new Date("2000-01-01T00:00:00.000Z"));
		const proof = buildInternalResponseProof("POST", "/v1/probe", "{}", '{"ok":true}', {
			scope: "operator",
		});

		vi.setSystemTime(new Date("2000-01-01T00:30:00.000Z"));

		// RPC anti-replay default stays tight: 30-minute-old proofs fail.
		expect(
			verifyInternalResponseProof(proof, "POST", "/v1/probe", "{}", '{"ok":true}', {
				scope: "operator",
			}),
		).toBe(false);
		// Evidence validation passes a wider window explicitly.
		expect(
			verifyInternalResponseProof(proof, "POST", "/v1/probe", "{}", '{"ok":true}', {
				scope: "operator",
				maxSkewMs: 60 * 60 * 1000,
			}),
		).toBe(true);
		// The widened window is still a bound, and signature binding still applies.
		vi.setSystemTime(new Date("2000-01-01T01:00:01.000Z"));
		expect(
			verifyInternalResponseProof(proof, "POST", "/v1/probe", "{}", '{"ok":true}', {
				scope: "operator",
				maxSkewMs: 60 * 60 * 1000,
			}),
		).toBe(false);
		vi.setSystemTime(new Date("2000-01-01T00:30:00.000Z"));
		expect(
			verifyInternalResponseProof(proof, "POST", "/v1/probe", "{}", '{"ok":false}', {
				scope: "operator",
				maxSkewMs: 60 * 60 * 1000,
			}),
		).toBe(false);
		// Non-positive overrides fall back to the tight default instead of widening.
		expect(
			verifyInternalResponseProof(proof, "POST", "/v1/probe", "{}", '{"ok":true}', {
				scope: "operator",
				maxSkewMs: 0,
			}),
		).toBe(false);
	});

	it("reports the missing relay public key when archived proofs cannot be verified", () => {
		const keys = generateKeyPair();
		process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = keys.privateKey;
		delete process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
		const proof = buildInternalResponseProof("POST", "/v1/probe", "{}", '{"ok":true}', {
			scope: "operator",
		});

		expect(
			internalResponseProofVerificationFailure(proof, "POST", "/v1/probe", "{}", '{"ok":true}', {
				scope: "operator",
				allowStale: true,
			}),
		).toBe("missing relay public key env OPERATOR_RPC_RELAY_PUBLIC_KEY");
	});

	it("verifies archived response proofs with an explicitly supplied relay public key", () => {
		const keys = generateKeyPair();
		process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = keys.privateKey;
		delete process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
		const proof = buildInternalResponseProof("POST", "/v1/probe", "{}", '{"ok":true}', {
			scope: "operator",
		});

		expect(
			internalResponseProofVerificationFailure(proof, "POST", "/v1/probe", "{}", '{"ok":true}', {
				scope: "operator",
				allowStale: true,
				relayPublicKey: keys.publicKey,
			}),
		).toBeNull();
	});
});

function installOperatorRelayKeys(): void {
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
