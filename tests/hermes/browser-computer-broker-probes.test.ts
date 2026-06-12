import { describe, expect, it } from "vitest";
import {
	browserComputerBrokerProbeEvidenceFailure,
	buildNetworkEgressBrokerProbeEvidenceFromReport,
	NETWORK_EGRESS_BROKER_RUN_REPORT_SCHEMA_VERSION,
	NETWORK_EGRESS_BROKER_RUN_REPORT_SOURCE,
	runTelclaudeBrowserComputerBrokerProbe,
} from "../../src/hermes/browser-computer-broker-probes.js";
import { generateKeyPair } from "../../src/internal-auth.js";

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

	it("promotes complete machine-observed network egress report into signed broker evidence", () => {
		withOperatorRelayKeys(() => {
			const evidence = buildNetworkEgressBrokerProbeEvidenceFromReport(
				completeNetworkEgressBrokerRunReport(),
			);

			expect(evidence.status).toBe("pass");
			expect(evidence.runnerAttestation).toBeDefined();
			expect(evidence.observations.directEgressDenialCount).toBeGreaterThanOrEqual(12);
			expect(
				browserComputerBrokerProbeEvidenceFailure("network.egress-broker", evidence),
			).toBeNull();
		});
	});

	it("keeps imported network egress evidence red when a denial class is missing", () => {
		withOperatorRelayKeys(() => {
			const report = completeNetworkEgressBrokerRunReport();
			const evidence = buildNetworkEgressBrokerProbeEvidenceFromReport({
				...report,
				attempts: report.attempts.filter((attempt) => attempt.kind !== "websocket"),
			});

			expect(evidence.status).toBe("fail");
			expect(
				browserComputerBrokerProbeEvidenceFailure("network.egress-broker", evidence),
			).toContain("status is fail");
			expect(
				evidence.checks.find(
					(check) => check.name === "egress.proxy-tunnel-webrtc-websocket-denied",
				)?.detail,
			).toContain("websocket");
		});
	});

	it("rejects tampered signed network egress broker evidence", () => {
		withOperatorRelayKeys(() => {
			const evidence = buildNetworkEgressBrokerProbeEvidenceFromReport(
				completeNetworkEgressBrokerRunReport(),
			);
			const tampered = {
				...evidence,
				observations: {
					...evidence.observations,
					directEgressDenialCount: evidence.observations.directEgressDenialCount + 1,
				},
			};

			expect(
				browserComputerBrokerProbeEvidenceFailure("network.egress-broker", tampered),
			).toContain("runnerAttestation observationsSha256 mismatch");
		});
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

});

function completeNetworkEgressBrokerRunReport() {
	const observedAt = "2026-06-01T09:00:00.000Z";
	const deniedKinds = [
		"provider",
		"model",
		"vault",
		"metadata",
		"private-network",
		"smtp",
		"imap",
		"whatsapp-bridge",
		"dns-53",
		"doh",
		"dot",
		"connect-proxy",
		"websocket",
		"webrtc",
		"ip-literal",
		"dns-rebinding",
		"localhost-callback",
		"unquarantined-upload",
		"browser-provider-bypass",
		"computer-covert-egress",
	] as const;
	return {
		schemaVersion: NETWORK_EGRESS_BROKER_RUN_REPORT_SCHEMA_VERSION,
		surfaceId: "network.egress-broker",
		ran: true,
		observedAt,
		source: NETWORK_EGRESS_BROKER_RUN_REPORT_SOURCE,
		summary: "machine-observed egress broker denials passed",
		attempts: [
			{
				name: "public-research",
				kind: "public-research",
				target: "https://example.org/research/benign",
				expectation: "allow",
				status: "pass",
				observed: "reachable",
				detail: "allowed public research egress reached the broker",
				route: "telclaude-egress-broker",
				httpStatus: 200,
			},
			...deniedKinds.map((kind) => ({
				name: `${kind}-denied`,
				kind,
				target: `egress-test://${kind}`,
				expectation: "deny",
				status: "pass",
				observed: "denied",
				detail: `${kind} egress was denied by the contained runtime policy`,
				errorCode: "ENETUNREACH",
			})),
		],
	} as const;
}

function withOperatorRelayKeys(run: () => void): void {
	const oldPrivate = process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
	const oldPublic = process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
	const keys = generateKeyPair();
	process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = keys.privateKey;
	process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = keys.publicKey;
	try {
		run();
	} finally {
		if (oldPrivate === undefined) delete process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
		else process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = oldPrivate;
		if (oldPublic === undefined) delete process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
		else process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = oldPublic;
	}
}
