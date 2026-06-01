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
		} else if (file.endsWith(".json")) {
			writeJson(resolved, readinessFailureEvidence());
		} else {
			fs.writeFileSync(resolved, `test fixture for ${file}\n`, "utf8");
		}
	}
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
