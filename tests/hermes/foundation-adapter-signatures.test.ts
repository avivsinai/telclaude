import { describe, expect, it } from "vitest";
import { hermesAdapterSignatureFilesForSurface } from "../../src/hermes/foundation.js";

describe("Hermes adapter signature files", () => {
	it("keeps browser and computer broker signatures scoped to their broker seam", () => {
		expect(hermesAdapterSignatureFilesForSurface("browser.profiles")).toEqual([
			"src/hermes/browser-computer-broker-probes.ts",
			"src/hermes/edge-adapter-contract.ts",
		]);
		expect(hermesAdapterSignatureFilesForSurface("computer.broker")).toEqual([
			"src/hermes/browser-computer-broker-probes.ts",
			"src/hermes/edge-adapter-contract.ts",
		]);
	});

	it("keeps network probe attestation registered only for the egress-broker seam", () => {
		expect(hermesAdapterSignatureFilesForSurface("network.egress-broker")).toEqual(
			expect.arrayContaining([
				"src/hermes/network-probe-attestation.ts",
				"src/hermes/network-probes.ts",
			]),
		);
	});
});
