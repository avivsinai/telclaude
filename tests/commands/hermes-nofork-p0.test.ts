import { describe, expect, it } from "vitest";
import { deriveNoForkP0Status } from "../../src/commands/hermes.js";
import type { evaluateCutoverCheck } from "../../src/hermes/foundation.js";

type CutoverCheck = ReturnType<typeof evaluateCutoverCheck>;

function cutoverWithGates(gates: CutoverCheck["gates"]): CutoverCheck {
	return { gates } as CutoverCheck;
}

describe("deriveNoForkP0Status", () => {
	it("classifies missing no-fork runner checks as a bootstrap failure only with missing attestation", () => {
		const status = deriveNoForkP0Status(
			cutoverWithGates([
				{
					name: "nofork.clean",
					status: "fail",
					detail:
						"no-fork evidence runnerAttestation is missing; missing no-fork evidence check runner.attestation; missing no-fork evidence check runner.p0; missing no-fork evidence check runner.noRuntimeSourceReplacement; missing no-fork evidence check runner.noMonkeypatch; missing no-fork evidence check runner.postStatusClean; missing no-fork evidence check runner.postDiffClean; missing no-fork evidence check runner.postIndexClean",
				},
			]),
		);

		expect(status).toBe("pass");
	});

	it("does not classify missing runner-check clauses without an explicit missing-attestation signal", () => {
		const status = deriveNoForkP0Status(
			cutoverWithGates([
				{
					name: "nofork.clean",
					status: "fail",
					detail:
						"missing no-fork evidence check runner.attestation; missing no-fork evidence check runner.p0",
				},
			]),
		);

		expect(status).toBe("fail");
	});

	it("classifies proof-bundle no-fork semantic bootstrap failures", () => {
		const status = deriveNoForkP0Status(
			cutoverWithGates([
				{
					name: "proofBundle.noForkProof.valid",
					status: "fail",
					detail:
						"proof bundle artifact noForkProof invalid: artifact status does not match on-disk semantic evidence; artifact semantic evidence failed: no-fork evidence runnerAttestation is missing; artifact semantic evidence failed: missing no-fork evidence check runner.attestation; artifact semantic evidence failed: missing no-fork evidence check runner.p0",
				},
			]),
		);

		expect(status).toBe("pass");
	});

	it("does not classify proof-bundle no-fork mismatches without semantic bootstrap evidence", () => {
		const status = deriveNoForkP0Status(
			cutoverWithGates([
				{
					name: "proofBundle.noForkProof.valid",
					status: "fail",
					detail:
						"proof bundle artifact noForkProof invalid: artifact status does not match on-disk semantic evidence",
				},
			]),
		);

		expect(status).toBe("fail");
	});

	it("does not classify proof-bundle no-fork bootstrap when artifact bytes also fail", () => {
		const status = deriveNoForkP0Status(
			cutoverWithGates([
				{
					name: "proofBundle.noForkProof.valid",
					status: "fail",
					detail:
						"proof bundle artifact noForkProof invalid: artifact hash does not match on-disk bytes; artifact status does not match on-disk semantic evidence; artifact semantic evidence failed: no-fork evidence runnerAttestation is missing; artifact semantic evidence failed: missing no-fork evidence check runner.attestation",
				},
			]),
		);

		expect(status).toBe("fail");
	});

	it("does not classify signed no-fork invariant failures surfaced through proof-bundle detail", () => {
		const status = deriveNoForkP0Status(
			cutoverWithGates([
				{
					name: "proofBundle.noForkProof.valid",
					status: "fail",
					detail:
						"proof bundle artifact noForkProof invalid: artifact status does not match on-disk semantic evidence; artifact semantic evidence failed: no-fork evidence required check runner.noMonkeypatch is fail: monkeypatch denial was not observed",
				},
			]),
		);

		expect(status).toBe("fail");
	});
});
