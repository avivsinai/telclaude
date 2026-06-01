import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
	BROWSER_COMPUTER_BROKER_SURFACE_IDS,
	type BrowserComputerBrokerSurfaceId,
	browserComputerBrokerFixtureEvidenceFailure,
	browserComputerBrokerProbeEvidenceFailure,
	buildBrowserComputerBrokerFixtureEvidenceBundle,
	runTelclaudeBrowserComputerBrokerProbe,
} from "../../src/hermes/browser-computer-broker-probes.js";

describe("Hermes browser/computer broker probes", () => {
	it.each([
		"browser.profiles",
		"computer.broker",
	] as const)("passes %s only after broker controls are observed", (surfaceId) => {
		const evidence = runTelclaudeBrowserComputerBrokerProbe({
			surfaceId,
			allowRun: true,
			observedAt: "2026-06-01T09:00:00.000Z",
		});

		expect(evidence.status).toBe("pass");
		expect(evidence.ran).toBe(true);
		expect(evidence.observations.auditEntryCount).toBeGreaterThan(0);
		expect(browserComputerBrokerProbeEvidenceFailure(surfaceId, evidence)).toBeNull();
	});

	it("keeps network egress broker red until live denial evidence exists", () => {
		const evidence = runTelclaudeBrowserComputerBrokerProbe({
			surfaceId: "network.egress-broker",
			allowRun: true,
			observedAt: "2026-06-01T09:00:00.000Z",
		});

		expect(evidence.status).toBe("fail");
		expect(evidence.ran).toBe(true);
		expect(evidence.observations.egressDenialMatrixHash).toMatch(/^sha256:/);
		expect(evidence.observations.directEgressDenialCount).toBe(0);
		expect(browserComputerBrokerProbeEvidenceFailure("network.egress-broker", evidence)).toContain(
			"status is fail",
		);
		expect(evidence.checks).toEqual(
			expect.arrayContaining([
				expect.objectContaining({
					name: "egress.direct-provider-denied",
					status: "fail",
				}),
				expect.objectContaining({
					name: "egress.dns-doh-dot-denied",
					status: "fail",
				}),
				expect.objectContaining({
					name: "egress.computer-covert-denied",
					status: "fail",
				}),
			]),
		);
	});

	it("proves browser profile isolation, quarantine, and browser denials", () => {
		const evidence = runTelclaudeBrowserComputerBrokerProbe({
			surfaceId: "browser.profiles",
			allowRun: true,
			observedAt: "2026-06-01T09:00:00.000Z",
		});

		expect(evidence.observations.allowedResearchAuditHash).toMatch(/^sha256:/);
		expect(evidence.observations.profileIsolationHash).toMatch(/^sha256:/);
		expect(evidence.observations.cookieIsolationHash).toMatch(/^sha256:/);
		expect(evidence.observations.browserQuarantineHash).toMatch(/^sha256:/);
		expect(evidence.observations.browserDeniedTargetHash).toMatch(/^sha256:/);
		expect(evidence.checks).toEqual(
			expect.arrayContaining([
				expect.objectContaining({
					name: "browser.allowed-public-research",
					status: "pass",
				}),
				expect.objectContaining({
					name: "browser.cross-domain-denied",
					status: "pass",
				}),
				expect.objectContaining({
					name: "browser.cookie-leak-denied",
					status: "pass",
				}),
			]),
		);
	});

	it("proves computer target policy, approval, display isolation, and quarantine", () => {
		const evidence = runTelclaudeBrowserComputerBrokerProbe({
			surfaceId: "computer.broker",
			allowRun: true,
			observedAt: "2026-06-01T09:00:00.000Z",
		});

		expect(evidence.observations.computerAllowedAuditHash).toMatch(/^sha256:/);
		expect(evidence.observations.computerUnauthorizedDenialHash).toMatch(/^sha256:/);
		expect(evidence.observations.computerSessionIsolationHash).toMatch(/^sha256:/);
		expect(evidence.observations.computerQuarantineHash).toMatch(/^sha256:/);
		expect(evidence.observations.computerApprovalHash).toMatch(/^sha256:/);
		expect(evidence.checks).toEqual(
			expect.arrayContaining([
				expect.objectContaining({
					name: "computer.allowed-target-audited",
					status: "pass",
				}),
				expect.objectContaining({
					name: "computer.unauthorized-target-denied",
					status: "pass",
				}),
				expect.objectContaining({
					name: "computer.sensitive-submit-approval-required",
					status: "pass",
				}),
			]),
		);
	});

	it("rejects evidence produced without --allow-run", () => {
		const evidence = runTelclaudeBrowserComputerBrokerProbe({
			surfaceId: "browser.profiles",
			allowRun: false,
			observedAt: "2026-06-01T09:00:00.000Z",
		});

		expect(evidence.status).toBe("fail");
		expect(browserComputerBrokerProbeEvidenceFailure("browser.profiles", evidence)).toContain(
			"harness did not run",
		);
	});

	it("builds fixture evidence bound to broker probe artifacts", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "browser-computer-fixtures-"));
		const probePaths = writeBrokerProbeArtifacts(tempDir);
		const bundle = buildBrowserComputerBrokerFixtureEvidenceBundle({
			evidenceDir: path.join(tempDir, "fixtures"),
			probePaths,
			observedAt: "2026-06-01T09:10:00.000Z",
		});

		expect(bundle.results).toEqual(
			expect.arrayContaining([
				expect.objectContaining({ id: "fixture.browser.allowed-research", status: "pass" }),
				expect.objectContaining({ id: "fixture.browser.cross-domain-deny", status: "pass" }),
				expect.objectContaining({ id: "fixture.browser.cookie-leak-deny", status: "pass" }),
				expect.objectContaining({ id: "fixture.computer.allowed-target", status: "pass" }),
				expect.objectContaining({
					id: "fixture.computer.unauthorized-target-deny",
					status: "pass",
				}),
			]),
		);
		const browserAllowedEvidence = bundle.evidence.find(
			(evidence) => evidence.id === "fixture.browser.allowed-research",
		);
		expect(
			browserComputerBrokerFixtureEvidenceFailure(
				"fixture.browser.allowed-research",
				browserAllowedEvidence,
			),
		).toBeNull();
	});

	it("rejects fixture evidence when the bound broker artifact changes", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "browser-computer-fixtures-"));
		const probePaths = writeBrokerProbeArtifacts(tempDir);
		const bundle = buildBrowserComputerBrokerFixtureEvidenceBundle({
			evidenceDir: path.join(tempDir, "fixtures"),
			probePaths,
			observedAt: "2026-06-01T09:10:00.000Z",
		});
		const cookieLeakEvidence = bundle.evidence.find(
			(evidence) => evidence.id === "fixture.browser.cookie-leak-deny",
		);

		fs.writeFileSync(probePaths["browser.profiles"], JSON.stringify({ changed: true }), "utf8");

		expect(
			browserComputerBrokerFixtureEvidenceFailure(
				"fixture.browser.cookie-leak-deny",
				cookieLeakEvidence,
			),
		).toContain("probeSha256 does not match");
	});
});

function writeBrokerProbeArtifacts(
	tempDir: string,
): Record<BrowserComputerBrokerSurfaceId, string> {
	const probePaths = {
		"browser.profiles": path.join(tempDir, "browser-profiles.json"),
		"computer.broker": path.join(tempDir, "computer-broker.json"),
		"network.egress-broker": path.join(tempDir, "network-egress-broker.json"),
	} satisfies Record<BrowserComputerBrokerSurfaceId, string>;
	for (const surfaceId of BROWSER_COMPUTER_BROKER_SURFACE_IDS) {
		const evidence = runTelclaudeBrowserComputerBrokerProbe({
			surfaceId,
			allowRun: true,
			observedAt: "2026-06-01T09:00:00.000Z",
		});
		fs.writeFileSync(probePaths[surfaceId], JSON.stringify(evidence, null, 2), "utf8");
	}
	return probePaths;
}
