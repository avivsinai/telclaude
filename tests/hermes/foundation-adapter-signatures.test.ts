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
				"src/hermes/browser-computer-broker-attestation.ts",
				"src/hermes/network-probe-attestation.ts",
				"src/hermes/network-probes.ts",
			]),
		);
	});

	it("binds the household media signature to every M3 custody and execution owner", () => {
		expect(hermesAdapterSignatureFilesForSurface("household.media")).toEqual(
			expect.arrayContaining([
				"src/config/profiles.ts",
				"src/relay/attachment-quarantine-store.ts",
				"src/relay/inbound-media-processor.ts",
				"src/relay/media-action-confirmation-store.ts",
				"src/hermes/mcp/live-relay-clients.ts",
				"src/relay/outbound-delivery-dispatcher.ts",
				"src/relay/whatsapp-edge-channel-connector.ts",
				"src/whatsapp-bridge/contract.ts",
				"src/hermes/household-media-probe.ts",
				"src/hermes/household-media-attestation.ts",
			]),
		);
	});
});
