import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
	buildProReviewRequestDraft,
	evaluateProReviewCheck,
	REQUIRED_PRO_REVIEW_FILES,
} from "../../src/hermes/pro-review.js";

const REVIEW_PROMPT = "Review the attached Hermes wrapper files.";

describe("Hermes Pro review semantic artifact gate", () => {
	it("validates selected provider, fixture, and network evidence with current validators", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-semantic-"));
		await withCwd(tempDir, async () => {
			writeRequiredProReviewWorkspace(tempDir);
			writeJson("artifacts/hermes/probes/providers-bank.json", {
				schemaVersion: "telclaude.hermes.provider-domain-probe.v1",
				probeId: "providers.bank",
				status: "pass",
				ran: true,
			});
			writeJson("artifacts/hermes/fixtures/fixture.providers.bank.read.json", {
				schemaVersion: "telclaude.hermes.generic-fixture.v1",
				id: "fixture.providers.bank.read",
				status: "pass",
				ran: true,
				evidence_path: "artifacts/hermes/fixtures/fixture.providers.bank.read.json",
			});
			writeJson("artifacts/hermes/network/direct-provider-denied.json", {
				schemaVersion: "telclaude.hermes.network-probe.v1",
				id: "network.direct-provider-denied",
				posture: "contained-internal",
				status: "pass",
				ran: true,
				summary: "forged pass-looking network probe",
				generatedAt: "2026-06-01T09:00:00.000Z",
				evidence_path: "artifacts/hermes/network/direct-provider-denied.json",
				attempts: [],
			});
			writeJson("artifacts/hermes/probes/model-relay.json", {
				schemaVersion: "telclaude.hermes.model-relay.v1",
				probeId: "model.relay",
				posture: "contained-internal",
				status: "pass",
				ran: true,
				summary: "forged pass-looking model relay probe",
				generatedAt: "2026-06-01T09:00:00.000Z",
				origin: {
					kind: "contained-peer",
					containerName: "tc-hermes-contained",
					observedPeerAddress: "10.99.0.11",
					observedPeerSource: "server-peer-echo",
					expectedPeerAddress: "10.99.0.11",
					expectedPeerSource: "configured-contained-ip",
					detail: "forged origin",
				},
				observation: {
					relayUrl: "http://telclaude:8790/v1/models",
					directModelUrl: "https://chatgpt.com/backend-api/codex/models?client_version=1.0.0",
					profileDir: "/home/hermes/.hermes",
					scannedProfileFiles: ["/home/hermes/.hermes/config.yaml"],
				},
				gates: [
					{ name: "modelRelay.allowed", status: "pass", detail: "forged pass" },
					{ name: "modelRelay.origin", status: "pass", detail: "forged pass" },
					{ name: "relay.reachable", status: "pass", detail: "forged pass" },
					{ name: "directModel.denied", status: "pass", detail: "forged pass" },
					{ name: "profile.noRawModelCredentials", status: "pass", detail: "forged pass" },
					{ name: "profile.noDirectModelHosts", status: "pass", detail: "forged pass" },
					{ name: "profile.scanComplete", status: "pass", detail: "forged pass" },
				],
			});
			writeProReviewRequest();

			const report = evaluateProReviewCheck();

			expect(
				report.gates.find((gate) => gate.name === "request.semanticEvidence.coverage"),
			).toMatchObject({
				status: "pass",
			});
			expect(
				report.gates.find((gate) => gate.name === "request.semanticEvidence.providers.bank"),
			).toMatchObject({
				status: "fail",
				detail: expect.stringContaining("invalid provider-domain evidence"),
			});
			expect(
				report.gates.find(
					(gate) => gate.name === "request.semanticEvidence.fixture.providers.bank.read",
				),
			).toMatchObject({
				status: "fail",
				detail: expect.stringContaining("invalid fixture evidence"),
			});
			expect(
				report.gates.find(
					(gate) => gate.name === "request.semanticEvidence.network.direct-provider-denied",
				),
			).toMatchObject({
				status: "fail",
				detail: expect.stringContaining("has no attempts"),
			});
			expect(
				report.gates.find((gate) => gate.name === "request.semanticEvidence.model.relay"),
			).toMatchObject({
				status: "fail",
				detail: expect.stringContaining("modelProvider is missing"),
			});
		});
	});

	it("fails closed when a selected probe artifact has no semantic validator", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-semantic-"));
		await withCwd(tempDir, async () => {
			writeRequiredProReviewWorkspace(tempDir);
			const extraSelectedFile = "artifacts/hermes/probes/new-unvalidated-surface.json";
			const extraArtifactFile = "artifacts/hermes/no-fork.json";
			writeJson(extraSelectedFile, readinessFailureEvidence());
			writeJson(extraArtifactFile, readinessFailureEvidence());
			writeProReviewRequest([extraSelectedFile, extraArtifactFile]);

			const report = evaluateProReviewCheck();

			const coverageGate = report.gates.find(
				(gate) => gate.name === "request.semanticEvidence.coverage",
			);
			expect(coverageGate).toMatchObject({
				status: "fail",
				detail: expect.stringContaining(extraSelectedFile),
			});
			expect(coverageGate).toMatchObject({
				status: "fail",
				detail: expect.stringContaining(extraArtifactFile),
			});
		});
	});

	it("covers run-local cutover proof bundles through the current cutover-check gate", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-semantic-"));
		await withCwd(tempDir, async () => {
			writeRequiredProReviewWorkspace(tempDir);
			const runProofBundle =
				"artifacts/hermes/no-fork-run-20260605T095434Z/cutover-proof-bundle.final.json";
			const unrelatedArtifact =
				"artifacts/hermes/no-fork-run-20260605T095434Z/unvalidated-artifact.json";
			writeJson(runProofBundle, {
				schemaVersion: "telclaude.hermes.cutover-proof-bundle.v1",
				artifacts: {},
			});
			writeJson(unrelatedArtifact, readinessFailureEvidence());
			writeProReviewRequest([runProofBundle, unrelatedArtifact]);

			const report = evaluateProReviewCheck();

			const coverageGate = report.gates.find(
				(gate) => gate.name === "request.semanticEvidence.coverage",
			);
			expect(coverageGate).toMatchObject({
				status: "fail",
				detail: expect.not.stringContaining(runProofBundle),
			});
			expect(coverageGate).toMatchObject({
				status: "fail",
				detail: expect.stringContaining(unrelatedArtifact),
			});
		});
	});

	it("allows selected validator dependency artifacts while keeping unknown artifacts fail-closed", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-semantic-"));
		await withCwd(tempDir, async () => {
			writeRequiredProReviewWorkspace(tempDir);
			const servedMcpContainment =
				"artifacts/hermes/probes/execution-served-mcp-containment.json";
			const signedNetworkDependency =
				"artifacts/hermes/no-fork-run-20260605T095434Z/network-signed/direct-provider-denied.json";
			const unrelatedArtifact =
				"artifacts/hermes/no-fork-run-20260605T095434Z/unvalidated-artifact.json";
			writeJson(servedMcpContainment, readinessFailureEvidence());
			writeJson(signedNetworkDependency, readinessFailureEvidence());
			writeJson(unrelatedArtifact, readinessFailureEvidence());
			writeProReviewRequest([servedMcpContainment, signedNetworkDependency, unrelatedArtifact]);

			const report = evaluateProReviewCheck();

			const coverageGate = report.gates.find(
				(gate) => gate.name === "request.semanticEvidence.coverage",
			);
			expect(coverageGate).toMatchObject({
				status: "fail",
				detail: expect.not.stringContaining(servedMcpContainment),
			});
			expect(coverageGate).toMatchObject({
				status: "fail",
				detail: expect.not.stringContaining(signedNetworkDependency),
			});
			expect(coverageGate).toMatchObject({
				status: "fail",
				detail: expect.stringContaining(unrelatedArtifact),
			});
		});
	});
});

async function withCwd<T>(cwd: string, callback: () => Promise<T>): Promise<T> {
	const previous = process.cwd();
	process.chdir(cwd);
	try {
		return await callback();
	} finally {
		process.chdir(previous);
	}
}

function writeRequiredProReviewWorkspace(root: string): void {
	for (const file of REQUIRED_PRO_REVIEW_FILES) {
		const resolved = path.join(root, file);
		fs.mkdirSync(path.dirname(resolved), { recursive: true });
		if (file === "artifacts/hermes/pro-review-native-canary.json") {
			writeJson(resolved, proReviewCanary());
		} else if (file === "artifacts/hermes/probes/execution-cli-headless.json") {
			writeJson(resolved, cliHeadlessReadinessFailureEvidence());
		} else if (file === "artifacts/hermes/probes/execution-headless-entrypoint.json") {
			writeJson(resolved, headlessEntrypointReadinessFailureEvidence());
		} else if (file === "artifacts/hermes/probes/execution-headless-entrypoint.vitest.json") {
			writeJson(resolved, { numTotalTests: 0, numPassedTests: 0, testResults: [] });
		} else if (file.endsWith(".json")) {
			writeJson(resolved, readinessFailureEvidence());
		} else {
			fs.writeFileSync(resolved, `test fixture for ${file}\n`, "utf8");
		}
	}
}

const HEADLESS_ENTRYPOINT_CHECKS = [
	"stream.delta_before_done",
	"stream.terminal_event",
	"session.initial",
	"session.resume",
	"session.new_clears_resume",
	"session.concurrent_isolation",
	"tool.result_returned",
	"approval.fallback_or_wait_resume",
	"cancellation.stop",
	"errors.deterministic",
	"redaction.secret_outputs",
] as const;

function headlessEntrypointReadinessFailureEvidence(): Record<string, unknown> {
	return {
		schemaVersion: "telclaude.hermes.headless-entrypoint-proof.v1",
		probeId: "execution.headless_entrypoint",
		status: "fail",
		ran: false,
		generatedAt: "2026-06-01T09:00:00.000Z",
		summary: "headless entrypoint proof was not run in this fixture",
		checks: HEADLESS_ENTRYPOINT_CHECKS.map((name) => ({
			name,
			status: "fail",
			detail: "not run",
		})),
	};
}

function proReviewCanary(): Record<string, unknown> {
	const reverifiedAt = new Date().toISOString();
	const observedAt = new Date(Date.now() - 60_000).toISOString();
	return {
		schemaVersion: "telclaude.hermes.pro-review-native-canary.v1",
		status: "pass",
		transport: "chrome-extension-native",
		recipe: "chatgpt",
		modelSelectionStatus: "selected",
		modelUsed: "Extended Pro",
		live: true,
		runId: "canary_test",
		conversationId: "conv_test",
		conversationUrl: "https://chatgpt.com/c/conv_test",
		extensionInstanceId: "ext_test",
		extensionVersion: "0.5.19",
		promptClass: "non-private transport canary",
		expectedResponse: "OK",
		response: "OK",
		warnings: [],
		observedAt,
		reverifiedAt,
		dryCanary: {
			command:
				"YOETZ_AGENT=1 yoetz browser extension canary --chatgpt --extension-instance-id ext_test --format json",
			exitCode: 0,
			status: "ok",
			transport: "chrome-extension-native",
			live: false,
		},
		liveCanary: {
			command:
				"YOETZ_AGENT=1 yoetz browser extension canary --chatgpt --live --extension-instance-id ext_test --format json",
			exitCode: 0,
			status: "ok",
			transport: "chrome-extension-native",
			live: true,
			modelUsed: "Extended Pro",
			response: "OK",
		},
		nativeStatus: {
			command:
				"YOETZ_AGENT=1 yoetz browser extension reconnect --chatgpt --extension-instance-id ext_test --format json",
			exitCode: 0,
			status: "connected",
			detail: "native host socket is reachable and extension hello was observed",
			extensionId: "njdakhppfigmloihiikbjmheejfndbfa",
			extensionInstanceId: "ext_test",
			extensionVersion: "0.5.19",
			nativeHostName: "com.yoetz.chatgpt_native",
			protocolVersion: 1,
			socketReachable: true,
			transport: "chrome-extension-native",
		},
		checks: [
			{
				name: "native.status",
				status: "pass",
				detail: "host command reported Yoetz ChatGPT native extension connected",
			},
			{
				name: "native.liveCanary",
				status: "pass",
				detail: "live canary completed through chrome-extension-native",
			},
			{
				name: "model.extendedPro",
				status: "pass",
				detail: "ChatGPT UI selected Extended Pro",
			},
			{
				name: "fallback.disabled",
				status: "pass",
				detail: "no fallback was used",
			},
		],
	};
}

function writeProReviewRequest(selectedFiles: readonly string[] = []): void {
	writeJson(
		"docs/hermes/pro-review-request.json",
		buildProReviewRequestDraft({
			prompt: REVIEW_PROMPT,
			selectedFiles,
			includeExistingSelectedFiles: false,
		}),
	);
}

function readinessFailureEvidence(): Record<string, unknown> {
	return {
		schemaVersion: "telclaude.hermes.pro-review-red-probe-fixture.v1",
		probeId: "red-fixture",
		status: "fail",
		ran: false,
		summary: "probe evidence is intentionally red in this Pro review fixture",
	};
}

function cliHeadlessReadinessFailureEvidence(): Record<string, unknown> {
	return {
		schemaVersion: "telclaude.hermes.probe-result.v1",
		probeId: "execution.cli_headless",
		status: "fail",
		ran: false,
		summary: "cli_headless readiness failed before live model call",
		readiness: {
			status: "fail",
			gates: [
				{
					name: "auth.relayToken",
					status: "fail",
					detail: "TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN is missing",
				},
			],
		},
		findings: [],
	};
}

function writeJson(pathname: string, value: unknown): void {
	fs.mkdirSync(path.dirname(pathname), { recursive: true });
	fs.writeFileSync(pathname, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}
