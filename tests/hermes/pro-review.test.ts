import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { buildEdgeAdapterProbeEvidence } from "../../src/hermes/edge-adapter-probes.js";
import { computeHermesArtifactDigest } from "../../src/hermes/foundation.js";
import { runTelclaudeMcpSideEffectLedgerProbe } from "../../src/hermes/mcp/side-effect-ledger-probe.js";
import {
	buildProReviewNativeYoetzEnv,
	buildProReviewRequestDraft,
	buildProReviewShardPlan,
	buildProReviewYoetzCommand,
	evaluateProReviewCheck,
	PRO_REVIEW_NATIVE_CANARY_MAX_AGE_MS,
	type ProReviewNativeCanary,
	REQUIRED_PRO_REVIEW_FILES,
	validateProReviewYoetzInspectCompletedResponseOutput,
	validateProReviewYoetzInspectOutput,
	validateProReviewYoetzSendOutput,
} from "../../src/hermes/pro-review.js";
import { runTelclaudeProviderApprovalBindingProbe } from "../../src/hermes/provider-approval-binding-probe.js";
import { runHermesWorkflowProbe } from "../../src/hermes/workflow-probes.js";
import { generateKeyPair } from "../../src/internal-auth.js";

const CLI_HEADLESS_TEST_RELAY_IP = "10.99.0.10";
const CLI_HEADLESS_TEST_CONTAINED_IP = "10.99.0.11";

describe("Hermes Pro review gate", () => {
	it("requires edge runtime authorizer files in the native Pro payload", () => {
		expect(REQUIRED_PRO_REVIEW_FILES).toEqual(
			expect.arrayContaining([
				"src/hermes/edge-adapter-runtime.ts",
				"tests/hermes/edge-adapter-runtime.test.ts",
				"src/hermes/browser-computer-broker-probes.ts",
				"tests/hermes/browser-computer-broker-probes.test.ts",
				"src/hermes/model-relay.ts",
				"tests/hermes/model-relay.test.ts",
				"artifacts/hermes/probes/model-relay.json",
				"src/hermes/edge-adapter-attestation.ts",
				"src/hermes/network-probe-attestation.ts",
				"src/hermes/no-fork-attestation.ts",
				"src/hermes/network-probes.ts",
				"tests/hermes/network-probes.test.ts",
				"src/hermes/private-telegram-fixture-attestation.ts",
				"src/hermes/provider-approval-binding-attestation.ts",
				"src/hermes/mcp/authority-registry.ts",
				"src/hermes/mcp/bridge.ts",
				"src/hermes/mcp/policy.ts",
				"src/hermes/mcp/side-effect-ledger-attestation.ts",
				"src/hermes/mcp/live-admin.ts",
				"src/hermes/mcp/live-connection-resolver.ts",
				"src/hermes/mcp/live-listen.ts",
				"src/hermes/mcp/live-probe-tokens.ts",
				"src/providers/catalog.json",
				"src/providers/catalog.ts",
				"src/providers/external-provider.ts",
				"src/google-services/server.ts",
				"src/google-services/approval.ts",
				"src/google-services/types.ts",
				"src/cron/scheduler.ts",
				"src/cron/store.ts",
				"src/background/runner.ts",
				"src/background/jobs.ts",
				"src/relay/provider-approval.ts",
				"tests/hermes/foundation-network-evidence.test.ts",
				"tests/hermes/mcp-authority-registry.test.ts",
				"tests/hermes/mcp-bridge.test.ts",
				"tests/hermes/mcp-live-runtime.test.ts",
				"tests/providers/provider-runtime-sync.integration.test.ts",
				"tests/google-services/server.test.ts",
				"tests/google-services/approval.test.ts",
				"tests/cron/store.test.ts",
				"tests/background/runner.test.ts",
				"tests/background/jobs.test.ts",
				"tests/relay/provider-approval.test.ts",
				"tests/integration/telegram-control-plane.replay.test.ts",
				"tests/telegram/command-gating.test.ts",
				"artifacts/hermes/fixtures/fixture.public.whatsapp.basic.json",
				"artifacts/hermes/fixtures/fixture.household.provider.strong-link-read.json",
				"artifacts/hermes/fixtures/fixture.providers.bank.direct-provider-deny.json",
				"artifacts/hermes/fixtures/fixture.providers.google.direct-provider-deny.json",
				"src/hermes/workflow-probes.ts",
				"tests/hermes/workflow-probes.test.ts",
				"src/hermes/workflow-run-ledger-attestation.ts",
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

	it("fails native canary commands that smuggle a non-native transport", async () => {
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
							"YOETZ_AGENT=1 yoetz browser extension canary --chatgpt --live --extension-instance-id ext_test --format json --transport dev-browser",
					},
				}),
			);
			writeJson("docs/hermes/pro-review-request.json", proReviewRequest(canaryPath));

			const report = evaluateProReviewCheck();
			const detail = report.gates.find(
				(gate) => gate.name === "nativeCanary.requiredChecks",
			)?.detail;

			expect(report.status).toBe("fail");
			expect(detail).toContain("live canary command includes unexpected token --transport");
			expect(detail).toContain("live canary command contains a blocked fallback");
		});
	});

	it("fails native canary commands with duplicate extension bindings", async () => {
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
							"YOETZ_AGENT=1 yoetz browser extension canary --chatgpt --live --extension-instance-id ext_test --extension-instance-id ext_test --format json",
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
					"live canary command includes multiple --extension-instance-id flags",
				),
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

	it("fails native canary evidence when dry canary commands are not extension-bound", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-gate-"));
		await withCwd(tempDir, async () => {
			writeRequiredProReviewWorkspace(tempDir);
			const canaryPath = "artifacts/hermes/pro-review-native-canary.json";
			const baseCanary = proReviewCanary();
			writeJson(
				canaryPath,
				proReviewCanary({
					dryCanary: {
						...(baseCanary.dryCanary as Record<string, unknown>),
						command: "YOETZ_AGENT=1 yoetz browser extension canary --chatgpt --format json",
					},
					nativeStatus: {
						...(baseCanary.nativeStatus as Record<string, unknown>),
						command: "YOETZ_AGENT=1 yoetz browser extension status --chatgpt --format json",
					},
				}),
			);
			writeJson("docs/hermes/pro-review-request.json", proReviewRequest(canaryPath));

			const report = evaluateProReviewCheck();
			const detail = report.gates.find(
				(gate) => gate.name === "nativeCanary.requiredChecks",
			)?.detail;

			expect(report.status).toBe("fail");
			expect(detail).not.toContain("native status command does not bind an extension instance");
			expect(detail).toContain("dry canary command does not bind an extension instance");
		});
	});

	it("accepts current Yoetz native status commands without extension-instance flag", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-gate-"));
		await withCwd(tempDir, async () => {
			writeRequiredProReviewWorkspace(tempDir);
			const canaryPath = "artifacts/hermes/pro-review-native-canary.json";
			const baseCanary = proReviewCanary();
			writeJson(
				canaryPath,
				proReviewCanary({
					nativeStatus: {
						...(baseCanary.nativeStatus as Record<string, unknown>),
						command: "YOETZ_AGENT=1 yoetz browser extension status --chatgpt --format json",
					},
				}),
			);
			writeJson("docs/hermes/pro-review-request.json", proReviewRequest(canaryPath));

			const report = evaluateProReviewCheck();

			expect(
				report.gates.find((gate) => gate.name === "nativeCanary.requiredChecks"),
			).toMatchObject({
				status: "pass",
			});
		});
	});

	it("accepts instance-bound native reconnect and dry canary evidence", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-gate-"));
		await withCwd(tempDir, async () => {
			writeRequiredProReviewWorkspace(tempDir);
			const canaryPath = "artifacts/hermes/pro-review-native-canary.json";
			const baseCanary = proReviewCanary();
			writeJson(
				canaryPath,
				proReviewCanary({
					dryCanary: {
						...(baseCanary.dryCanary as Record<string, unknown>),
						command:
							"YOETZ_AGENT=1 yoetz browser extension canary --chatgpt --extension-instance-id ext_test --format json",
					},
					nativeStatus: {
						...(baseCanary.nativeStatus as Record<string, unknown>),
						command:
							"YOETZ_AGENT=1 yoetz browser extension reconnect --chatgpt --extension-instance-id ext_test --format json",
					},
				}),
			);
			writeJson("docs/hermes/pro-review-request.json", proReviewRequest(canaryPath));

			const report = evaluateProReviewCheck();

			expect(
				report.gates.find((gate) => gate.name === "nativeCanary.requiredChecks"),
			).toMatchObject({
				status: "pass",
			});
		});
	});

	it("fails instance-bound native reconnect and dry canary commands for the wrong extension", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-gate-"));
		await withCwd(tempDir, async () => {
			writeRequiredProReviewWorkspace(tempDir);
			const canaryPath = "artifacts/hermes/pro-review-native-canary.json";
			const baseCanary = proReviewCanary();
			writeJson(
				canaryPath,
				proReviewCanary({
					dryCanary: {
						...(baseCanary.dryCanary as Record<string, unknown>),
						command:
							"YOETZ_AGENT=1 yoetz browser extension canary --chatgpt --extension-instance-id ext_other --format json",
					},
					nativeStatus: {
						...(baseCanary.nativeStatus as Record<string, unknown>),
						command:
							"YOETZ_AGENT=1 yoetz browser extension reconnect --chatgpt --extension-instance-id ext_other --format json",
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
					"native status command binds extension instance ext_other, expected ext_test",
				),
			});
			expect(
				report.gates.find((gate) => gate.name === "nativeCanary.requiredChecks")?.detail,
			).toContain("dry canary command binds extension instance ext_other, expected ext_test");
		});
	});

	it("builds final Pro review sends against the validated native extension instance", () => {
		const payloadSha256 = computeTextDigest("approved payload");
		const bundleSha256 = computeTextDigest("exact bundle");
		const command = buildProReviewYoetzCommand({
			canary: proReviewCanary() as ProReviewNativeCanary,
			bundlePath: "/tmp/pro-review.md",
			payloadSha256,
			bundleSha256,
			runId: "hermes_20260604174011_abcdef12",
			conversation: "https://chatgpt.com/c/6a22c722-7270-83ed-bbc4-3c9f067a376c",
			waitTimeoutMs: 120_000,
		});

		expect(command).toEqual(
			expect.arrayContaining([
				"--transport",
				"chrome-extension-native",
				"--var",
				"extension_instance_id=ext_test",
				"--var",
				`payload_sha256=${payloadSha256}`,
				"--var",
				`bundle_sha256=${bundleSha256}`,
				"--var",
				"run_id=hermes_20260604174011_abcdef12",
				"--var",
				"conversation=https://chatgpt.com/c/6a22c722-7270-83ed-bbc4-3c9f067a376c",
				"--var",
				"wait_timeout_ms=120000",
			]),
		);
		expect(command).toContainEqual(expect.stringContaining(`payloadSha256: ${payloadSha256}`));
		expect(command).toContainEqual(
			expect.stringContaining("one complete full-context, non-sharded source and evidence review"),
		);
		expect(command).toContainEqual(
			expect.stringContaining("retry in the same owned ChatGPT conversation"),
		);
		expect(command).not.toContain("--allow-cdp-fallback");
		expect(command).not.toContain("--cdp");
	});

	it("allowlists only safe native Yoetz env and scans allowed values for secrets", () => {
		const env = buildProReviewNativeYoetzEnv({
			PATH: "/bin",
			HOME: "/home/test",
			USER: "test",
			LOGNAME: "test",
			SHELL: "/bin/zsh",
			LANG: "en_US.UTF-8",
			LC_ALL: "TOKEN=abcdefghijklmnopqrstuvwxyz123456",
			TMPDIR: "/tmp/hermes",
			OPENAI_API_KEY: "raw-openai",
			OPENROUTER_API_KEY: "raw-openrouter",
			ANTHROPIC_API_KEY: "raw-anthropic",
			NPM_TOKEN: "raw-npm-token",
			YOETZ_OPENAI_API_KEY: "raw-yoetz-openai",
			YOETZ_BROWSER_TRANSPORT: "dev-browser",
			YOETZ_CDP_URL: "http://127.0.0.1:9222",
			CHROME_REMOTE_DEBUGGING_PORT: "9222",
			DEV_BROWSER_CDP_URL: "http://127.0.0.1:9222",
			BROWSERLESS_API_KEY: "browserless",
			CI_SAFE_BUT_AMBIENT: "plain-value",
			XDG_CONFIG_HOME: "/tmp/sk-proj-abcdefghijklmnopqrstuvwxyz1234567890",
			YOETZ_DIR: "/home/test/.yoetz",
			YOETZ_HOME: "/home/test/.yoetz",
			YOETZ_CHATGPT_NATIVE_EXTENSION_DIR: "/opt/yoetz/chatgpt-native-extension",
			YOETZ_CHROME_NATIVE_MESSAGING_DIR: "/home/test/chrome-native-messaging",
			YOETZ_CHROME_EXTENSION_NATIVE_SOCKET: "/tmp/yoetz-native.sock",
			YOETZ_AGENT: "0",
		});

		expect(env).toMatchObject({
			PATH: "/bin",
			HOME: "/home/test",
			USER: "test",
			LOGNAME: "test",
			SHELL: "/bin/zsh",
			LANG: "en_US.UTF-8",
			TMPDIR: "/tmp/hermes",
			YOETZ_DIR: "/home/test/.yoetz",
			YOETZ_HOME: "/home/test/.yoetz",
			YOETZ_CHATGPT_NATIVE_EXTENSION_DIR: "/opt/yoetz/chatgpt-native-extension",
			YOETZ_CHROME_NATIVE_MESSAGING_DIR: "/home/test/chrome-native-messaging",
			YOETZ_CHROME_EXTENSION_NATIVE_SOCKET: "/tmp/yoetz-native.sock",
			YOETZ_AGENT: "1",
		});
		expect(env.OPENAI_API_KEY).toBeUndefined();
		expect(env.OPENROUTER_API_KEY).toBeUndefined();
		expect(env.ANTHROPIC_API_KEY).toBeUndefined();
		expect(env.NPM_TOKEN).toBeUndefined();
		expect(env.YOETZ_OPENAI_API_KEY).toBeUndefined();
		expect(env.YOETZ_BROWSER_TRANSPORT).toBeUndefined();
		expect(env.YOETZ_CDP_URL).toBeUndefined();
		expect(env.CHROME_REMOTE_DEBUGGING_PORT).toBeUndefined();
		expect(env.DEV_BROWSER_CDP_URL).toBeUndefined();
		expect(env.BROWSERLESS_API_KEY).toBeUndefined();
		expect(env.CI_SAFE_BUT_AMBIENT).toBeUndefined();
		expect(env.XDG_CONFIG_HOME).toBeUndefined();
		expect(env.LC_ALL).toBeUndefined();
	});

	it("validates Yoetz native final-send JSON before reporting sent", () => {
		const approvedPayloadSha256 = computeTextDigest("approved payload");
		const bundleSha256 = computeTextDigest("exact bundle");
		const bundlePath = "/tmp/pro-review.md";

		expect(
			validateProReviewYoetzSendOutput({
				stdout: JSON.stringify({
					status: "ok",
					transport: "chrome-extension-native",
					model_used: "extended-pro",
					model_selection_status: "selected",
					warnings: [],
					fallback_used: false,
					auto_paste_fallback: false,
					response: [
						`payloadSha256: ${approvedPayloadSha256}`,
						"Findings:",
						"- No P0/P1 findings in this validated fixture.",
						"Residual risk:",
						"- Fixture response only proves validator shape.",
					].join("\n"),
				}),
				expectedExtensionInstanceId: "ext_test",
				expectedBundlePath: bundlePath,
				expectedPayloadSha256: approvedPayloadSha256,
				expectedBundleSha256: bundleSha256,
			}),
		).toMatchObject({ status: "pass" });

		expect(
			validateProReviewYoetzSendOutput({
				stdout: JSON.stringify({
					status: "ok",
					transport: "chrome-extension-native",
					model_used: "extended-pro",
					model_selection_status: "selected",
					warnings: [],
					fallback_used: false,
					auto_paste_fallback: false,
					response:
						"Findings:\n- No P0/P1 findings in this validated fixture.\nResidual risk:\n- Fixture response omits payload binding.",
				}),
				expectedExtensionInstanceId: "ext_test",
				expectedBundlePath: bundlePath,
				expectedPayloadSha256: approvedPayloadSha256,
				expectedBundleSha256: bundleSha256,
			}),
		).toMatchObject({
			status: "fail",
			detail: expect.stringContaining(
				`response does not echo payloadSha256: ${approvedPayloadSha256}`,
			),
		});

		expect(
			validateProReviewYoetzSendOutput({
				stdout: JSON.stringify({
					status: "ok",
					transport: "chrome-extension-native",
					model_used: "extended-pro",
					model_selection_status: "selected",
					warnings: [],
					fallback_used: false,
					auto_paste_fallback: false,
					extension_instance_id: "ext_other",
				}),
				expectedExtensionInstanceId: "ext_test",
				expectedBundlePath: bundlePath,
				expectedPayloadSha256: approvedPayloadSha256,
				expectedBundleSha256: bundleSha256,
			}),
		).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("extension_instance_id is ext_other"),
		});

		expect(
			validateProReviewYoetzSendOutput({
				stdout: JSON.stringify({
					status: "ok",
					transport: "chrome-extension-native",
					model_used: "extended-pro",
					model_selection_status: "selected",
					warnings: [],
					fallback_used: false,
					auto_paste_fallback: false,
					artifacts: {
						bundle_md: "/tmp/other-pro-review.md",
					},
				}),
				expectedExtensionInstanceId: "ext_test",
				expectedBundlePath: bundlePath,
				expectedPayloadSha256: approvedPayloadSha256,
				expectedBundleSha256: bundleSha256,
			}),
		).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("artifacts.bundle_md is /tmp/other-pro-review.md"),
		});

		expect(
			validateProReviewYoetzSendOutput({
				stdout: JSON.stringify({
					status: "ok",
					transport: "dev-browser",
					model_used: "gpt-5",
					model_selection_status: "kept_current",
					warnings: ["fallback"],
					fallback_used: true,
					auto_paste_fallback: true,
					extension_instance_id: "ext_other",
					artifacts: {
						bundle_md: bundlePath,
					},
				}),
				expectedExtensionInstanceId: "ext_test",
				expectedBundlePath: bundlePath,
				expectedPayloadSha256: approvedPayloadSha256,
				expectedBundleSha256: bundleSha256,
			}),
		).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("transport is dev-browser"),
		});
	});

	it("rejects Yoetz final-send output with a truncated one-character review", () => {
		const approvedPayloadSha256 = computeTextDigest("approved payload");
		const bundleSha256 = computeTextDigest("exact bundle");
		const bundlePath = "/tmp/pro-review.md";

		expect(
			validateProReviewYoetzSendOutput({
				stdout: JSON.stringify({
					status: "ok",
					transport: "chrome-extension-native",
					model_used: "extended-pro",
					model_selection_status: "selected",
					warnings: [],
					fallback_used: false,
					auto_paste_fallback: false,
					response: "I",
				}),
				expectedExtensionInstanceId: "ext_test",
				expectedBundlePath: bundlePath,
				expectedPayloadSha256: approvedPayloadSha256,
				expectedBundleSha256: bundleSha256,
			}),
		).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("response is too short"),
		});
	});

	it("fails sharded Pro review checks before validating shard plan contents", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-shard-tamper-"));
		await withCwd(tempDir, async () => {
			writeRequiredProReviewWorkspace(tempDir);
			const canaryPath = "artifacts/hermes/pro-review-native-canary.json";
			writeJson(canaryPath, proReviewCanary());
			const request = legacyShardedProReviewRequest(canaryPath) as {
				shardPlan: { shards: unknown[] };
			};
			const tamperedShardPlan = {
				...request.shardPlan,
				shards: request.shardPlan.shards.slice(1),
			};
			writeJson("docs/hermes/pro-review-request.json", {
				...request,
				shardPlan: tamperedShardPlan,
			});

			const report = evaluateProReviewCheck();
			const gate = report.gates.find((item) => item.name === "request.shardPlan");

			expect(report.status).toBe("fail");
			expect(gate).toMatchObject({
				status: "fail",
				detail: expect.stringContaining("use one complete full-context native bundle"),
			});
		});
	});

	it("fails sharded Pro review checks when a selected shard file disappears", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-shard-stale-"));
		await withCwd(tempDir, async () => {
			writeRequiredProReviewWorkspace(tempDir);
			const canaryPath = "artifacts/hermes/pro-review-native-canary.json";
			writeJson(canaryPath, proReviewCanary());
			const request = legacyShardedProReviewRequest(canaryPath) as {
				selectedFiles: string[];
			};
			writeJson("docs/hermes/pro-review-request.json", request);
			fs.rmSync(path.resolve(request.selectedFiles[0]));

			const report = evaluateProReviewCheck();

			expect(report.status).toBe("fail");
			expect(report.gates.find((item) => item.name === "request.selectedFiles")).toMatchObject({
				status: "fail",
				detail: expect.stringContaining(request.selectedFiles[0]),
			});
			expect(report.gates.find((item) => item.name === "request.shardPlan")).toMatchObject({
				status: "fail",
				detail: expect.stringContaining("use one complete full-context native bundle"),
			});
		});
	});

	it("rejects new sharded Pro review request generation", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-long-line-"));
		await withCwd(tempDir, async () => {
			writeRequiredProReviewWorkspace(tempDir);
			const canaryPath = "artifacts/hermes/pro-review-native-canary.json";
			writeJson(canaryPath, proReviewCanary());
			const longLinePath = "src/hermes/oversized-pro-review-line.ts";
			fs.mkdirSync(path.dirname(path.resolve(longLinePath)), { recursive: true });
			fs.writeFileSync(path.resolve(longLinePath), `${"x".repeat(600)}\n`, "utf8");

			expect(() =>
				buildProReviewRequestDraft({
					canaryPath,
					prompt: "Review the attached Hermes wrapper files.",
					selectedFiles: [longLinePath],
					shardMaxSourceBytes: 500,
				}),
			).toThrow("sharded Pro review request generation is disabled");
			expect(() =>
				buildProReviewShardPlan([...REQUIRED_PRO_REVIEW_FILES, longLinePath], 500),
			).toThrow("exceeding --shard-max-source-bytes 500");
		});
	});

	it("rejects sharded Yoetz command construction", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-shard-echo-"));
		await withCwd(tempDir, async () => {
			writeRequiredProReviewWorkspace(tempDir);
			const canaryPath = "artifacts/hermes/pro-review-native-canary.json";
			writeJson(canaryPath, proReviewCanary());
			const request = legacyShardedProReviewRequest(canaryPath) as {
				payloadBinding: { payloadSha256: string; shardPlanSha256?: string };
				shardPlan: { shards: ReturnType<typeof buildProReviewShardPlan>["shards"] };
			};
			const shard = request.shardPlan.shards[0];
			const shardPlanSha256 = request.payloadBinding.shardPlanSha256;
			if (!shard || !shardPlanSha256) throw new Error("expected sharded test request");
			const bundleSha256 = computeTextDigest("exact shard bundle");

			expect(() =>
				buildProReviewYoetzCommand({
					canary: proReviewCanary() as ProReviewNativeCanary,
					bundlePath: "/tmp/pro-review.shard-001.md",
					payloadSha256: request.payloadBinding.payloadSha256,
					bundleSha256,
					shard,
					shardPlanSha256,
				}),
			).toThrow("sharded Yoetz Pro review sends are disabled");
		});
	});

	it("rejects Yoetz final-send output bound to a different approved payload", () => {
		const approvedPayloadSha256 = computeTextDigest("approved payload");
		const otherPayloadSha256 = computeTextDigest("other payload");
		const bundleSha256 = computeTextDigest("exact bundle");
		const bundlePath = "/tmp/pro-review.md";

		expect(
			validateProReviewYoetzSendOutput({
				stdout: JSON.stringify({
					status: "ok",
					transport: "chrome-extension-native",
					model_used: "extended-pro",
					model_selection_status: "selected",
					warnings: [],
					fallback_used: false,
					auto_paste_fallback: false,
					extension_instance_id: "ext_test",
					artifacts: {
						bundle_md: bundlePath,
					},
					payloadSha256: otherPayloadSha256,
					bundleSha256,
				}),
				expectedExtensionInstanceId: "ext_test",
				expectedBundlePath: bundlePath,
				expectedPayloadSha256: approvedPayloadSha256,
				expectedBundleSha256: bundleSha256,
			}),
		).toMatchObject({
			status: "fail",
			detail: expect.stringContaining(`payloadSha256 is ${otherPayloadSha256}`),
		});
	});

	it("rejects Yoetz final-send output bound to a different bundle", () => {
		const approvedPayloadSha256 = computeTextDigest("approved payload");
		const bundleSha256 = computeTextDigest("exact bundle");
		const otherBundleSha256 = computeTextDigest("other bundle");
		const bundlePath = "/tmp/pro-review.md";

		expect(
			validateProReviewYoetzSendOutput({
				stdout: JSON.stringify({
					status: "ok",
					transport: "chrome-extension-native",
					model_used: "extended-pro",
					model_selection_status: "selected",
					warnings: [],
					fallback_used: false,
					auto_paste_fallback: false,
					extension_instance_id: "ext_test",
					artifacts: {
						bundle_md: bundlePath,
					},
					payloadSha256: approvedPayloadSha256,
					bundleSha256: otherBundleSha256,
				}),
				expectedExtensionInstanceId: "ext_test",
				expectedBundlePath: bundlePath,
				expectedPayloadSha256: approvedPayloadSha256,
				expectedBundleSha256: bundleSha256,
			}),
		).toMatchObject({
			status: "fail",
			detail: expect.stringContaining(`bundleSha256 is ${otherBundleSha256}`),
		});
	});

	it("validates Yoetz native inspect output before reporting a run-bound send", () => {
		expect(
			validateProReviewYoetzInspectOutput({
				stdout: JSON.stringify({
					status: "ok",
					transport: "chrome-extension-native",
					response: {
						run_id: "hermes_20260604174011_abcdef12",
						tabs: [{ tab_id: 123 }],
					},
				}),
				expectedRunId: "hermes_20260604174011_abcdef12",
			}),
		).toMatchObject({ status: "pass" });

		expect(
			validateProReviewYoetzInspectOutput({
				stdout: JSON.stringify({
					status: "ok",
					transport: "chrome-extension-native",
					response: {
						run_id: "hermes_20260604174011_stale123",
						tabs: [{ tab_id: 123 }],
					},
				}),
				expectedRunId: "hermes_20260604174011_abcdef12",
			}),
		).toMatchObject({
			status: "fail",
			detail: expect.stringContaining(
				"runId is hermes_20260604174011_stale123, expected hermes_20260604174011_abcdef12",
			),
		});

		expect(
			validateProReviewYoetzInspectOutput({
				stdout: JSON.stringify({
					status: "ok",
					transport: "chrome-extension-native",
					response: {
						run_id: "hermes_20260604174011_abcdef12",
						tabs: [],
					},
				}),
				expectedRunId: "hermes_20260604174011_abcdef12",
			}),
		).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("response.tabs is missing or empty"),
		});
	});

	it("requires completed single-run inspect recovery to echo the payload digest", () => {
		const payloadSha256 = computeTextDigest("approved payload");
		const responseText = [
			`payloadSha256: ${payloadSha256}`,
			"Findings:",
			"- No P0/P1 findings in this recovered full-context fixture.",
			"Residual risk:",
			"- Fixture response only proves native inspect recovery shape and payload binding.",
		].join("\n");
		const inspectOutput = (text: string) =>
			JSON.stringify({
				status: "ok",
				transport: "chrome-extension-native",
				response: {
					run_id: "hermes_run_full_context",
					tabs: [
						{
							inspection: {
								extraction: {
									text,
									is_generating: false,
								},
								model_selection: {
									current_model_label: "Extended Pro",
								},
								ownership: {
									run_id: "hermes_run_full_context",
								},
								window_name: "yoetz-chatgpt-native:hermes_run_full_context:job_1",
							},
						},
					],
				},
			});

		expect(
			validateProReviewYoetzInspectCompletedResponseOutput({
				stdout: inspectOutput(responseText),
				expectedRunId: "hermes_run_full_context",
				expectedPayloadSha256: payloadSha256,
			}),
		).toMatchObject({ status: "pass" });

		expect(
			validateProReviewYoetzInspectCompletedResponseOutput({
				stdout: inspectOutput(`${responseText}\nExtended Pro\n`).replace(
					'"current_model_label":"Extended Pro"',
					'"current_model_label":"","requested_model":"extended-pro"',
				),
				expectedRunId: "hermes_run_full_context",
				expectedPayloadSha256: payloadSha256,
			}),
		).toMatchObject({ status: "pass" });

		expect(
			validateProReviewYoetzInspectCompletedResponseOutput({
				stdout: inspectOutput(responseText.replace(`payloadSha256: ${payloadSha256}`, "")),
				expectedRunId: "hermes_run_full_context",
				expectedPayloadSha256: payloadSha256,
			}),
		).toMatchObject({
			status: "fail",
			detail: expect.stringContaining(`response does not echo payloadSha256: ${payloadSha256}`),
		});
	});

	it("rejects completed shard review recovery from native inspect output", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-inspect-recover-"));
		await withCwd(tempDir, async () => {
			writeRequiredProReviewWorkspace(tempDir);
			const canaryPath = "artifacts/hermes/pro-review-native-canary.json";
			writeJson(canaryPath, proReviewCanary());
			const request = legacyShardedProReviewRequest(canaryPath) as {
				payloadBinding: { payloadSha256: string; shardPlanSha256?: string };
				shardPlan: { shards: ReturnType<typeof buildProReviewShardPlan>["shards"] };
			};
			const shard = request.shardPlan.shards[0];
			const shardPlanSha256 = request.payloadBinding.shardPlanSha256;
			if (!shard || !shardPlanSha256) throw new Error("expected sharded test request");
			const responseText = [
				`payloadSha256: ${request.payloadBinding.payloadSha256}`,
				`shardPlanSha256: ${shardPlanSha256}`,
				`shardId: ${shard.shardId}`,
				`shardSha256: ${shard.shardSha256}`,
				"Findings:",
				"- No P0/P1 findings in this recovered inspect fixture.",
				"Residual risk:",
				"- Fixture response only proves native inspect recovery shape and binding echoes.",
			].join("\n");

			expect(
				validateProReviewYoetzInspectCompletedResponseOutput({
					stdout: JSON.stringify({
						status: "ok",
						transport: "chrome-extension-native",
						response: {
							run_id: "hermes_run_shard_001",
							tabs: [
								{
									inspection: {
										extraction: {
											text: responseText,
											is_generating: false,
										},
										model_selection: {
											current_model_label: "Extended Pro",
										},
										ownership: {
											run_id: "hermes_run_shard_001",
										},
										window_name: "yoetz-chatgpt-native:hermes_run_shard_001:job_1",
									},
								},
							],
						},
					}),
					expectedRunId: "hermes_run_shard_001",
					expectedPayloadSha256: request.payloadBinding.payloadSha256,
					expectedShard: shard,
					expectedShardPlanSha256: shardPlanSha256,
				}),
			).toMatchObject({
				status: "fail",
				detail: expect.stringContaining("sharded Yoetz Pro review inspect recovery is disabled"),
			});
		});
	});

	it("fails approved Pro review checks with red semantic evidence even without --require-approval", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-gate-"));
		await withCwd(tempDir, async () => {
			writeRequiredProReviewWorkspace(tempDir);
			const canaryPath = "artifacts/hermes/pro-review-native-canary.json";
			writeJson(canaryPath, proReviewCanary());
			const baseRequest = proReviewRequest(canaryPath);
			writeJson("docs/hermes/pro-review-request.json", approvedProReviewRequest(canaryPath));

			const report = evaluateProReviewCheck();

			expect(baseRequest.status).toBe("pending_operator_disclosure_approval");
			expect(report.status).toBe("fail");
			expect(
				report.gates.find((gate) => gate.name === "request.cliHeadlessEvidence"),
			).toMatchObject({
				status: "fail",
				detail: expect.stringContaining("explicitly red and cannot be sent"),
			});
			expect(
				report.gates.find((gate) => gate.name === "request.semanticEvidence.edge.whatsapp"),
			).toMatchObject({
				status: "fail",
				detail: expect.stringContaining("edge.whatsapp evidence is explicitly red"),
			});
		});
	});

	it("fails malformed non-pass signed semantic evidence", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-gate-"));
		await withCwd(tempDir, async () => {
			writeRequiredProReviewWorkspace(tempDir);
			const canaryPath = "artifacts/hermes/pro-review-native-canary.json";
			writeJson(canaryPath, proReviewCanary());
			writeJson("artifacts/hermes/probes/edge-whatsapp.json", {
				schemaVersion: "telclaude.hermes.pro-review-red-probe-fixture.v1",
				probeId: "edge-whatsapp",
				summary: "malformed red fixture",
			});
			writeJson("docs/hermes/pro-review-request.json", proReviewRequest(canaryPath));

			const report = evaluateProReviewCheck();

			expect(report.status).toBe("fail");
			expect(
				report.gates.find((gate) => gate.name === "request.semanticEvidence.edge.whatsapp"),
			).toMatchObject({
				status: "fail",
				detail: "edge.whatsapp evidence status is undefined",
			});
		});
	});

	it("accepts current strict cutover-check reports as honest context", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-cutover-context-"));
		await withCwd(tempDir, async () => {
			writeRequiredProReviewWorkspace(tempDir);
			const canaryPath = "artifacts/hermes/pro-review-native-canary.json";
			const cutoverReportPath = "artifacts/hermes/pro-review-current-cutover-check.json";
			writeJson(canaryPath, proReviewCanary());
			writeJson(cutoverReportPath, currentCutoverCheckReport("safe", undefined, true));
			writeJson("docs/hermes/pro-review-request.json", proReviewRequest(canaryPath));

			const report = evaluateProReviewCheck();

			expect(
				report.gates.find((gate) => gate.name === "request.semanticEvidence.coverage"),
			).toMatchObject({
				status: "pass",
			});
			expect(
				report.gates.find((gate) => gate.name === "request.semanticEvidence.currentCutoverCheck"),
			).toMatchObject({
				status: "pass",
				detail: "current cutover-check report is fresh schema-valid diagnostic context",
			});
		});
	});

	it("rejects malformed current cutover-check context reports", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-cutover-context-"));
		await withCwd(tempDir, async () => {
			writeRequiredProReviewWorkspace(tempDir);
			const canaryPath = "artifacts/hermes/pro-review-native-canary.json";
			const cutoverReportPath = "artifacts/hermes/pro-review-current-cutover-check.json";
			writeJson(canaryPath, proReviewCanary());
			writeJson(cutoverReportPath, {
				status: "fail",
				mode: { strict: false, dryRun: true },
				gates: [],
			});
			writeJson("docs/hermes/pro-review-request.json", proReviewRequest(canaryPath));

			const report = evaluateProReviewCheck();

			expect(report.status).toBe("fail");
			expect(
				report.gates.find((gate) => gate.name === "request.semanticEvidence.currentCutoverCheck"),
			).toMatchObject({
				status: "fail",
				detail: expect.stringContaining("mode.strict must be true"),
			});
		});
	});

	it("rejects stale current cutover-check context reports", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-cutover-context-"));
		await withCwd(tempDir, async () => {
			writeRequiredProReviewWorkspace(tempDir);
			const canaryPath = "artifacts/hermes/pro-review-native-canary.json";
			const cutoverReportPath = "artifacts/hermes/pro-review-current-cutover-check.json";
			writeJson(canaryPath, proReviewCanary());
			writeJson(cutoverReportPath, currentCutoverCheckReport("fail", "2026-06-01T09:00:00.000Z"));
			writeJson("docs/hermes/pro-review-request.json", proReviewRequest(canaryPath));

			const report = evaluateProReviewCheck({ now: new Date("2026-06-01T09:16:00.000Z") });

			expect(report.status).toBe("fail");
			expect(
				report.gates.find((gate) => gate.name === "request.semanticEvidence.currentCutoverCheck"),
			).toMatchObject({
				status: "fail",
				detail: expect.stringContaining("generatedAt is stale"),
			});
		});
	});

	it("rejects pass-looking cli_headless evidence without relay signature and proof token binding", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-gate-"));
		await withCwd(tempDir, async () => {
			writeRequiredProReviewWorkspace(tempDir);
			const canaryPath = "artifacts/hermes/pro-review-native-canary.json";
			writeJson(canaryPath, proReviewCanary());
			writeJson(
				"artifacts/hermes/probes/execution-cli-headless.json",
				cliHeadlessPassLookingUnsignedEvidence(),
			);
			writeJson("docs/hermes/pro-review-request.json", proReviewRequest(canaryPath));

			const report = withHermesRuntimeIpEnv(() => evaluateProReviewCheck());
			const gate = report.gates.find((item) => item.name === "request.cliHeadlessEvidence");

			expect(report.status).toBe("fail");
			expect(gate).toMatchObject({
				status: "fail",
				detail: expect.stringContaining("relay proof"),
			});
			expect(gate?.detail).toContain("signature");
		});
	});

	it("rejects pass-looking signed probe evidence without runner attestations", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-gate-"));
		await withCwd(tempDir, async () => {
			writeRequiredProReviewWorkspace(tempDir);
			const canaryPath = "artifacts/hermes/pro-review-native-canary.json";
			writeJson(canaryPath, proReviewCanary());
			await withOperatorRelayKeys(async () => {
				const { runnerAttestation: _edgeAttestation, ...unsignedEdgeEvidence } =
					await buildEdgeAdapterProbeEvidence({
						surfaceId: "edge.whatsapp",
						allowRun: true,
						observedAt: "2026-06-01T09:00:00.000Z",
					});
				const { runnerAttestation: _ledgerAttestation, ...unsignedLedgerEvidence } =
					await runTelclaudeMcpSideEffectLedgerProbe({
						allowRun: true,
						observedAt: "2026-06-01T09:00:00.000Z",
					});
				const { runnerAttestation: _providerAttestation, ...unsignedProviderEvidence } =
					await runTelclaudeProviderApprovalBindingProbe({
						allowRun: true,
						observedAt: "2026-06-01T09:00:00.000Z",
					});
				const { runnerAttestation: _workflowAttestation, ...unsignedWorkflowEvidence } =
					runHermesWorkflowProbe({
						surfaceId: "workflow.longrun",
						allowRun: true,
						observedAt: "2026-06-01T09:00:00.000Z",
					});

				writeJson("artifacts/hermes/probes/edge-whatsapp.json", unsignedEdgeEvidence);
				writeJson("artifacts/hermes/probes/sideeffect-ledger.json", unsignedLedgerEvidence);
				writeJson(
					"artifacts/hermes/probes/providers-approval-binding.json",
					unsignedProviderEvidence,
				);
				writeJson("artifacts/hermes/probes/workflow-longrun.json", unsignedWorkflowEvidence);
			});
			writeJson("docs/hermes/pro-review-request.json", proReviewRequest(canaryPath));

			const report = evaluateProReviewCheck();

			expect(report.status).toBe("fail");
			expect(
				report.gates.find((gate) => gate.name === "request.semanticEvidence.edge.whatsapp"),
			).toMatchObject({
				status: "fail",
				detail: expect.stringContaining("runnerAttestation is missing"),
			});
			expect(
				report.gates.find((gate) => gate.name === "request.semanticEvidence.sideeffect.ledger"),
			).toMatchObject({
				status: "fail",
				detail: expect.stringContaining("runnerAttestation is missing"),
			});
			expect(
				report.gates.find(
					(gate) => gate.name === "request.semanticEvidence.providers.approval-binding",
				),
			).toMatchObject({
				status: "fail",
				detail: expect.stringContaining("runnerAttestation is missing"),
			});
			expect(
				report.gates.find((gate) => gate.name === "request.semanticEvidence.workflow.longrun"),
			).toMatchObject({
				status: "fail",
				detail: expect.stringContaining("runnerAttestation is missing"),
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

	it("does not leave explicit artifact request paths pending", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-gate-"));
		await withCwd(tempDir, async () => {
			writeRequiredProReviewWorkspace(tempDir);
			const canaryPath = "artifacts/hermes/pro-review-native-canary.json";
			const requestPath = "artifacts/hermes/no-fork-run/live-pro-review-request.json";
			writeJson(canaryPath, proReviewCanary());
			writeJson(requestPath, approvedProReviewRequest(canaryPath));

			const report = evaluateProReviewCheck({ requestPath, requireApproval: true });

			expect(report.gates.find((gate) => gate.name === "request.path")).toMatchObject({
				status: "pass",
				detail: "request path is explicit",
			});
		});
	});

	it("fails approved Pro review sends when the native canary reverification is stale", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-gate-"));
		await withCwd(tempDir, async () => {
			writeRequiredProReviewWorkspace(tempDir);
			const canaryPath = "artifacts/hermes/pro-review-native-canary.json";
			writeJson(
				canaryPath,
				proReviewCanary({
					observedAt: "2026-05-31T16:59:00.000Z",
					reverifiedAt: "2026-05-31T17:00:00.000Z",
				}),
			);
			const baseRequest = proReviewRequest(canaryPath);
			writeJson(
				"docs/hermes/pro-review-request.json",
				proReviewRequest(canaryPath, {
					status: "approved",
					privateWorkspaceDisclosure: {
						...(baseRequest.privateWorkspaceDisclosure as Record<string, unknown>),
						approved: true,
						approvalId: "approval-1",
						operator: "aviv",
						approvedAt: "2026-05-31T17:03:00.000Z",
						payloadSha256: (baseRequest.payloadBinding as Record<string, unknown>).payloadSha256,
					},
				}),
			);

			const report = evaluateProReviewCheck({
				requireApproval: true,
				now: new Date(
					Date.parse("2026-05-31T17:00:00.000Z") + PRO_REVIEW_NATIVE_CANARY_MAX_AGE_MS + 60_000,
				),
			});

			expect(report.status).toBe("fail");
			expect(report.gates.find((gate) => gate.name === "nativeCanary.freshness")).toMatchObject({
				status: "fail",
				detail: expect.stringContaining("stale"),
			});
		});
	});

	it("fails approved Pro review checks when the native canary is stale without --require-approval", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-gate-"));
		await withCwd(tempDir, async () => {
			writeRequiredProReviewWorkspace(tempDir);
			const canaryPath = "artifacts/hermes/pro-review-native-canary.json";
			writeJson(
				canaryPath,
				proReviewCanary({
					observedAt: "2026-05-31T16:59:00.000Z",
					reverifiedAt: "2026-05-31T17:00:00.000Z",
				}),
			);
			writeJson("docs/hermes/pro-review-request.json", approvedProReviewRequest(canaryPath));

			const report = evaluateProReviewCheck({
				now: new Date(
					Date.parse("2026-05-31T17:00:00.000Z") + PRO_REVIEW_NATIVE_CANARY_MAX_AGE_MS + 60_000,
				),
			});

			expect(report.status).toBe("fail");
			expect(report.gates.find((gate) => gate.name === "nativeCanary.freshness")).toMatchObject({
				status: "fail",
				detail: expect.stringContaining("stale"),
			});
		});
	});
});

function proReviewCanary(overrides: Record<string, unknown> = {}): Record<string, unknown> {
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

function legacyShardedProReviewRequest(
	canaryPath: string,
	selectedFiles: readonly string[] = [...REQUIRED_PRO_REVIEW_FILES],
	maxShardSourceBytes = 500,
): Record<string, unknown> {
	const prompt = "Review the attached Hermes wrapper files.";
	const blockedFallbacks = [
		"cdp",
		"api-key",
		"manual-browser",
		"claude-substitution",
		"amq-substitution",
	];
	const selectedFileContentsSha256 = computeSelectedFileContentsDigest(selectedFiles);
	const transportEvidenceSha256 = computeFileDigest(canaryPath);
	const shardPlan = buildProReviewShardPlan(selectedFiles, maxShardSourceBytes);
	const shardPlanSha256 = computeTextDigest(JSON.stringify(shardPlan));
	const payload = {
		reviewer: "ChatGPT Pro Extended via Yoetz native extension",
		transport: "chrome-extension-native",
		model: "Extended Pro",
		fallbackAllowed: false,
		transportEvidence: canaryPath,
		blockedFallbacks,
		prompt,
		selectedFiles,
		selectedFileContentsSha256,
		transportEvidenceSha256,
		reviewMode: "sharded",
		shardPlanSha256,
	};
	return proReviewRequest(
		canaryPath,
		{
			reviewMode: "sharded",
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
					"reviewMode",
					"shardPlanSha256",
				],
				payloadSha256: computeTextDigest(JSON.stringify(payload)),
				promptSha256: computeTextDigest(prompt),
				selectedFilesSha256: computeTextDigest(JSON.stringify(selectedFiles)),
				selectedFileContentsSha256,
				transportEvidenceSha256,
				shardPlanSha256,
				notes: "Legacy sharded fixture; production refresh must not generate this shape.",
			},
			shardPlan,
		},
		selectedFiles,
	);
}

function approvedProReviewRequest(canaryPath: string): Record<string, unknown> {
	const baseRequest = proReviewRequest(canaryPath);
	return proReviewRequest(canaryPath, {
		status: "approved",
		privateWorkspaceDisclosure: {
			...(baseRequest.privateWorkspaceDisclosure as Record<string, unknown>),
			approved: true,
			approvalId: "approval-1",
			operator: "aviv",
			approvedAt: new Date().toISOString(),
			payloadSha256: (baseRequest.payloadBinding as Record<string, unknown>).payloadSha256,
		},
	});
}

function writeRequiredProReviewWorkspace(root: string): void {
	for (const file of REQUIRED_PRO_REVIEW_FILES) {
		const resolved = path.join(root, file);
		fs.mkdirSync(path.dirname(resolved), { recursive: true });
		if (file === "artifacts/hermes/probes/execution-cli-headless.json") {
			writeJson(resolved, cliHeadlessReadinessFailureEvidence());
		} else if (file === "artifacts/hermes/probes/execution-headless-entrypoint.json") {
			writeJson(resolved, headlessEntrypointReadinessFailureEvidence());
		} else if (file === "artifacts/hermes/probes/execution-headless-entrypoint.vitest.json") {
			writeJson(resolved, { numTotalTests: 0, numPassedTests: 0, testResults: [] });
		} else if (file === "artifacts/hermes/probes/model-relay.json") {
			writeJson(resolved, modelRelayReadinessFailureEvidence());
		} else if (file === "artifacts/hermes/pro-review-native-canary.json") {
			writeJson(resolved, proReviewCanary());
		} else if (file === "artifacts/hermes/pro-review-current-cutover-check.json") {
			writeJson(resolved, currentCutoverCheckReport("safe"));
		} else if (isSignedProbeArtifact(file)) {
			writeJson(resolved, signedProbeReadinessFailureEvidence(file));
		} else {
			fs.writeFileSync(resolved, `test fixture for ${file}\n`, "utf8");
		}
	}
}

function currentCutoverCheckReport(
	status: "safe" | "pass" | "fail" | "input_error",
	generatedAt = new Date().toISOString(),
	dryRun = status === "pass" || status === "fail",
): Record<string, unknown> {
	const ok = status === "safe" || status === "pass";
	return {
		generatedAt,
		status,
		exitCode: ok ? 0 : 1,
		mode: {
			strict: true,
			dryRun,
		},
		gates: [
			{
				name: "workflow.scope",
				status: ok ? "pass" : "fail",
				detail: ok ? "included workflows are scoped" : "no included workflows",
			},
		],
		workflowIds: ok ? ["workflow.private.telegram"] : [],
		evidencePaths: [],
		decisionIds: [],
		downgradeNotes: [],
		remediationOwners: [],
	};
}

function isSignedProbeArtifact(file: string): boolean {
	return (
		file.startsWith("artifacts/hermes/probes/edge-") ||
		[
			"artifacts/hermes/probes/identity-migration.json",
			"artifacts/hermes/probes/household-scopes.json",
			"artifacts/hermes/probes/attachment-quarantine.json",
			"artifacts/hermes/probes/outbound-policy.json",
			"artifacts/hermes/probes/public-social-isolation.json",
			"artifacts/hermes/probes/sideeffect-ledger.json",
			"artifacts/hermes/probes/providers-approval-binding.json",
			"artifacts/hermes/probes/workflow-cron.json",
			"artifacts/hermes/probes/workflow-longrun.json",
		].includes(file)
	);
}

function signedProbeReadinessFailureEvidence(file: string): Record<string, unknown> {
	return {
		schemaVersion: "telclaude.hermes.pro-review-red-probe-fixture.v1",
		probeId: path.basename(file, ".json"),
		status: "fail",
		ran: false,
		summary: "probe evidence is intentionally red in this Pro review fixture",
	};
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

function modelRelayReadinessFailureEvidence(): Record<string, unknown> {
	return {
		schemaVersion: "telclaude.hermes.model-relay.v1",
		probeId: "model.relay",
		status: "fail",
		ran: false,
		generatedAt: "2026-06-01T09:00:00.000Z",
		summary: "model.relay readiness failed before live relay probe",
		origin: {
			kind: "unknown",
			detail: "model relay probe did not run",
		},
		observation: {
			directModelUrl: "https://chatgpt.com/backend-api/codex/models?client_version=1.0.0",
		},
		gates: [
			{
				name: "modelRelay.allowed",
				status: "fail",
				detail: "model relay probe was not allowed to run in this fixture",
			},
		],
	};
}

function cliHeadlessPassLookingUnsignedEvidence(): Record<string, unknown> {
	const invocation = {
		command: "scripts/hermes-contained-cli-probe.sh",
		args: ["chat", "-q", "Reply with exactly HERMES_OK_CODEX_SUB"],
		cwd: "/repo",
		envKeys: [
			"HERMES_CODEX_BASE_URL",
			"HERMES_HOME",
			"HERMES_INFERENCE_MODEL",
			"HERMES_INFERENCE_PROVIDER",
			"NO_COLOR",
		],
	};
	const runtime = {
		kind: "contained-docker",
		containerName: "tc-hermes-contained",
		networkName: "telclaude-hermes-relay",
		containerId: "tc-hermes-contained-container-id",
		image:
			"nousresearch/hermes-agent@sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7",
		imageDigest: "sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7",
		hostname: "tc-hermes-contained",
		relayHost: "telclaude",
		relayResolvedAddress: CLI_HEADLESS_TEST_RELAY_IP,
		containerIpAddress: CLI_HEADLESS_TEST_CONTAINED_IP,
		observedPeerAddress: CLI_HEADLESS_TEST_CONTAINED_IP,
		provenanceSource: "docker-inspect-container-dns-and-relay-peer",
	};
	const relayProof = {
		schemaVersion: "telclaude.hermes.cli-headless-relay-proof.v1",
		source: "telclaude-openai-codex-proxy",
		requestId: "codex-proof-unsigned",
		method: "POST",
		path: "/backend-api/codex/responses",
		observedPeerAddress: CLI_HEADLESS_TEST_CONTAINED_IP,
		upstreamStatus: 200,
		model: "gpt-5.3-codex",
		requestBodySha256: `sha256:${"a".repeat(64)}`,
		proofTokenSha256: null,
		observedAt: "2026-05-30T00:00:00.500Z",
	};
	const stdoutPreview = "HERMES_OK_CODEX_SUB\n";
	const stderrPreview = "";
	return {
		schemaVersion: "telclaude.hermes.probe-result.v1",
		probeId: "execution.cli_headless",
		status: "pass",
		ran: true,
		exitCode: 0,
		summary: "Hermes CLI oneshot probe completed successfully",
		invocation,
		modelProvider: {
			provider: "openai-codex",
			baseUrl: "http://telclaude:8790/v1/openai-codex-proxy",
			baseUrlHost: "telclaude",
			model: "gpt-5.3-codex",
			modelSource: "env:HERMES_INFERENCE_MODEL",
			authLocation: "hermes-auth-store:openai-codex",
			authScope: "relay-openai-codex-subscription-proxy",
			tokenScoping: "peer-bound",
			auxiliaryAuthSource: "manual:telclaude-relay",
			auxiliaryBaseUrl: "http://telclaude:8790/v1/openai-codex-proxy",
			auxiliaryBaseUrlHost: "telclaude",
			refreshTokenPolicy: "non-refreshable-placeholder",
		},
		provenance: {
			runner: "telclaude-hermes-cli-probe",
			source: "live-allow-run",
			startedAt: "2026-05-30T00:00:00.000Z",
			endedAt: "2026-05-30T00:00:01.000Z",
			expectedProofToken: "HERMES_OK_CODEX_SUB",
			proofTokenObserved: true,
			invocationSha256: computeHermesArtifactDigest(invocation),
			stdoutSha256: computeTextDigest(stdoutPreview),
			stderrSha256: computeTextDigest(stderrPreview),
			runtimeSha256: computeHermesArtifactDigest(runtime),
			relayProofSha256: computeHermesArtifactDigest(relayProof),
		},
		stdoutPreview,
		stderrPreview,
		runtime,
		relayProof,
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

async function withOperatorRelayKeys<T>(callback: () => Promise<T>): Promise<T> {
	const originalPrivateKey = process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
	const originalPublicKey = process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
	const relayKeys = generateKeyPair();
	process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = relayKeys.privateKey;
	process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = relayKeys.publicKey;
	try {
		return await callback();
	} finally {
		restoreEnv("OPERATOR_RPC_RELAY_PRIVATE_KEY", originalPrivateKey);
		restoreEnv("OPERATOR_RPC_RELAY_PUBLIC_KEY", originalPublicKey);
	}
}

function withHermesRuntimeIpEnv<T>(callback: () => T): T {
	const originalRelayIp = process.env.TELCLAUDE_HERMES_RELAY_IP;
	const originalContainedIp = process.env.TELCLAUDE_HERMES_CONTAINED_IP;
	process.env.TELCLAUDE_HERMES_RELAY_IP = CLI_HEADLESS_TEST_RELAY_IP;
	process.env.TELCLAUDE_HERMES_CONTAINED_IP = CLI_HEADLESS_TEST_CONTAINED_IP;
	try {
		return callback();
	} finally {
		restoreEnv("TELCLAUDE_HERMES_RELAY_IP", originalRelayIp);
		restoreEnv("TELCLAUDE_HERMES_CONTAINED_IP", originalContainedIp);
	}
}

function restoreEnv(name: string, value: string | undefined): void {
	if (value === undefined) {
		delete process.env[name];
	} else {
		process.env[name] = value;
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
