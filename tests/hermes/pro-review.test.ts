import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { evaluateProReviewCheck, REQUIRED_PRO_REVIEW_FILES } from "../../src/hermes/pro-review.js";

describe("Hermes Pro review gate", () => {
	it("requires edge runtime authorizer files in the native Pro payload", () => {
		expect(REQUIRED_PRO_REVIEW_FILES).toEqual(
			expect.arrayContaining([
				"src/hermes/edge-adapter-runtime.ts",
				"tests/hermes/edge-adapter-runtime.test.ts",
				"src/hermes/browser-computer-broker-probes.ts",
				"tests/hermes/browser-computer-broker-probes.test.ts",
				"src/hermes/network-probe-attestation.ts",
				"src/hermes/network-probes.ts",
				"tests/hermes/network-probes.test.ts",
				"artifacts/hermes/fixtures/fixture.public.whatsapp.basic.json",
				"artifacts/hermes/fixtures/fixture.household.provider.strong-link-read.json",
				"artifacts/hermes/fixtures/fixture.providers.bank.direct-provider-deny.json",
				"artifacts/hermes/fixtures/fixture.providers.google.direct-provider-deny.json",
				"src/hermes/workflow-probes.ts",
				"tests/hermes/workflow-probes.test.ts",
				"src/hermes/mcp/side-effect-human-approval.ts",
				"tests/hermes/mcp-side-effect-human-approval.test.ts",
				"src/relay/openai-codex-relay-proof.ts",
			]),
		);
	});

	it("fails native canary commands that include blocked fallback flags", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-gate-"));
		await withCwd(tempDir, async () => {
			writeRequiredProReviewWorkspace(tempDir);
			const canaryPath = "artifacts/hermes/pro-review-native-canary.json";
			writeJson(
				canaryPath,
				proReviewCanary({
					liveCanary: {
						...proReviewCanary().liveCanary,
						command:
							"YOETZ_AGENT=1 yoetz browser extension canary --chatgpt --live --extension-instance-id ext_test --cdp --format json",
					},
				}),
			);
			writeJson("docs/hermes/pro-review-request.json", proReviewRequest(canaryPath));

			const report = evaluateProReviewCheck();

			expect(report.status).toBe("fail");
			expect(
				report.gates.find((gate) => gate.name === "nativeCanary.requiredChecks"),
			).toMatchObject({
				status: "fail",
				detail: expect.stringContaining("live canary command contains a blocked fallback"),
			});
		});
	});

	it("fails native canary evidence when the live command binds a different extension instance", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-gate-"));
		await withCwd(tempDir, async () => {
			writeRequiredProReviewWorkspace(tempDir);
			const canaryPath = "artifacts/hermes/pro-review-native-canary.json";
			writeJson(
				canaryPath,
				proReviewCanary({
					liveCanary: {
						...proReviewCanary().liveCanary,
						command:
							"YOETZ_AGENT=1 yoetz browser extension canary --chatgpt --live --extension-instance-id ext_other --format json",
					},
				}),
			);
			writeJson("docs/hermes/pro-review-request.json", proReviewRequest(canaryPath));

			const report = evaluateProReviewCheck();

			expect(report.status).toBe("fail");
			expect(
				report.gates.find((gate) => gate.name === "nativeCanary.requiredChecks"),
			).toMatchObject({
				status: "fail",
				detail: expect.stringContaining(
					"live canary command binds extension instance ext_other, expected ext_test",
				),
			});
		});
	});

	it("fails approved private disclosure metadata when request status remains pending", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-gate-"));
		await withCwd(tempDir, async () => {
			writeRequiredProReviewWorkspace(tempDir);
			const canaryPath = "artifacts/hermes/pro-review-native-canary.json";
			const baseRequest = proReviewRequest(canaryPath);
			writeJson(
				"docs/hermes/pro-review-request.json",
				proReviewRequest(canaryPath, {
					privateWorkspaceDisclosure: {
						...(baseRequest.privateWorkspaceDisclosure as Record<string, unknown>),
						approved: true,
						approvalId: "approval-1",
						operator: "aviv",
						approvedAt: "2026-05-31T17:10:00Z",
						payloadSha256: (baseRequest.payloadBinding as Record<string, unknown>).payloadSha256,
					},
				}),
			);

			const report = evaluateProReviewCheck({ requireApproval: true });

			expect(report.status).toBe("fail");
			expect(report.gates.find((gate) => gate.name === "disclosure.approved")).toMatchObject({
				status: "fail",
				detail: expect.stringContaining("request status is still pending disclosure approval"),
			});
		});
	});
});

function proReviewCanary(overrides: Record<string, unknown> = {}): Record<string, unknown> {
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
		observedAt: "2026-05-31T17:00:00.000Z",
		reverifiedAt: "2026-05-31T17:04:51Z",
		dryCanary: {
			command: "YOETZ_AGENT=1 yoetz browser extension canary --chatgpt --format json",
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
			command: "YOETZ_AGENT=1 yoetz browser extension status --chatgpt --format json",
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
		...overrides,
	};
}

function proReviewRequest(
	canaryPath: string,
	overrides: Record<string, unknown> = {},
	selectedFiles: readonly string[] = [...REQUIRED_PRO_REVIEW_FILES],
): Record<string, unknown> {
	const prompt = "Review the attached Hermes wrapper files.";
	const selectedFileContentsSha256 = computeSelectedFileContentsDigest(selectedFiles);
	const transportEvidenceSha256 = computeFileDigest(canaryPath);
	return {
		schemaVersion: "telclaude.hermes.pro-review-request.v1",
		status: "pending_operator_disclosure_approval",
		reviewer: "ChatGPT Pro Extended via Yoetz native extension",
		transport: "chrome-extension-native",
		model: "Extended Pro",
		fallbackAllowed: false,
		transportEvidence: canaryPath,
		prompt,
		privateWorkspaceDisclosure: {
			required: true,
			approved: false,
			approvalReason: "The payload includes private repo code.",
			approvalBindingRequired: true,
			approvalId: null,
			operator: null,
			approvedAt: null,
			payloadSha256: null,
		},
		payloadBinding: {
			digestAlgorithm: "sha256",
			canonicalJsonFields: [
				"reviewer",
				"transport",
				"model",
				"fallbackAllowed",
				"transportEvidence",
				"blockedFallbacks",
				"prompt",
				"selectedFiles",
				"selectedFileContentsSha256",
				"transportEvidenceSha256",
			],
			payloadSha256: computeTextDigest(
				JSON.stringify({
					reviewer: "ChatGPT Pro Extended via Yoetz native extension",
					transport: "chrome-extension-native",
					model: "Extended Pro",
					fallbackAllowed: false,
					transportEvidence: canaryPath,
					blockedFallbacks: [
						"cdp",
						"api-key",
						"manual-browser",
						"claude-substitution",
						"amq-substitution",
					],
					prompt,
					selectedFiles,
					selectedFileContentsSha256,
					transportEvidenceSha256,
				}),
			),
			promptSha256: computeTextDigest(prompt),
			selectedFilesSha256: computeTextDigest(JSON.stringify(selectedFiles)),
			selectedFileContentsSha256,
			transportEvidenceSha256,
			notes: "A future approval is valid only for this exact payload.",
		},
		selectedFiles,
		blockedFallbacks: [
			"cdp",
			"api-key",
			"manual-browser",
			"claude-substitution",
			"amq-substitution",
		],
		...overrides,
	};
}

function writeRequiredProReviewWorkspace(root: string): void {
	for (const file of REQUIRED_PRO_REVIEW_FILES) {
		const resolved = path.join(root, file);
		fs.mkdirSync(path.dirname(resolved), { recursive: true });
		if (file === "artifacts/hermes/probes/execution-cli-headless.json") {
			writeJson(resolved, cliHeadlessReadinessFailureEvidence());
		} else if (file === "artifacts/hermes/pro-review-native-canary.json") {
			writeJson(resolved, proReviewCanary());
		} else {
			fs.writeFileSync(resolved, `test fixture for ${file}\n`, "utf8");
		}
	}
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

async function withCwd<T>(cwd: string, callback: () => Promise<T>): Promise<T> {
	const previous = process.cwd();
	process.chdir(cwd);
	try {
		return await callback();
	} finally {
		process.chdir(previous);
	}
}

function writeJson(pathname: string, value: unknown): void {
	fs.mkdirSync(path.dirname(pathname), { recursive: true });
	fs.writeFileSync(pathname, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function computeTextDigest(value: string): string {
	return `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
}

function computeSelectedFileContentsDigest(selectedFiles: readonly string[]): string {
	return computeTextDigest(
		JSON.stringify(
			selectedFiles.map((file) => {
				const resolved = path.resolve(file);
				if (!fs.existsSync(resolved)) return { file, missing: true };
				return {
					file,
					sha256: crypto.createHash("sha256").update(fs.readFileSync(resolved)).digest("hex"),
				};
			}),
		),
	);
}

function computeFileDigest(file: string): string {
	const resolved = path.resolve(file);
	if (!fs.existsSync(resolved)) return computeTextDigest(JSON.stringify({ file, missing: true }));
	return `sha256:${crypto.createHash("sha256").update(fs.readFileSync(resolved)).digest("hex")}`;
}
