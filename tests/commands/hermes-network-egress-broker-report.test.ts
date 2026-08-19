import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Command } from "commander";
import { describe, expect, it } from "vitest";
import { registerHermesCommand } from "../../src/commands/hermes.js";
import { buildNetworkEgressBrokerProbeEvidenceFromReport } from "../../src/hermes/browser-computer-broker-probes.js";

describe("hermes network-egress-broker-report command", () => {
	it("writes a machine-observed partial report from docker-exec probes", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-egress-report-"));
		const outPath = path.join(tempDir, "network-egress-broker.run-report.json");
		const callsPath = path.join(tempDir, "docker-calls.jsonl");
		const dockerBin = path.join(tempDir, "fake-docker");
		fs.writeFileSync(
			dockerBin,
			`#!/bin/sh
printf '%s\\n' "$*" >> "${callsPath}"
request="$(cat)"
REQUEST_JSON="$request" node <<'NODE'
const request = JSON.parse(process.env.REQUEST_JSON || "{}");
if (request.mode === "mcp-web-fetch") {
  console.log(JSON.stringify({observed: "reachable", detail: "tc_web_fetch returned HTTP 200", httpStatus: 200, durationMs: 5}));
} else if (request.kind === "model") {
  console.log(JSON.stringify({observed: "reachable", detail: "model endpoint was reachable", httpStatus: 200, durationMs: 5}));
} else {
  console.log(JSON.stringify({observed: "denied", detail: request.kind + " denied", errorName: "TypeError", errorCode: "ENETUNREACH", durationMs: 5}));
}
NODE
`,
			{ mode: 0o755 },
		);

		const result = await runHermesCommand([
			"hermes",
			"network-egress-broker-report",
			"--allow-run",
			"--json",
			"--docker-bin",
			dockerBin,
			"--container-name",
			"tc-hermes-contained",
			"--mcp-url",
			"http://telclaude:8793/mcp",
			"--mcp-auth",
			"Authorization: Bearer probe",
			"--provider-url",
			"https://provider.example.invalid/login",
			"--model-url",
			"https://api.openai.com/v1/responses",
			"--vault-url",
			"http://vault:8222/v1/secrets",
			"--metadata-url",
			"http://169.254.169.254/latest/meta-data",
			"--private-network-url",
			"http://10.0.0.12/admin",
			"--doh-url",
			"https://dns.google/dns-query",
			"--out",
			outPath,
		]);
		const report = JSON.parse(result.stdout) as {
			attempts: Array<{ kind: string; status: string; route?: string }>;
		};
		const artifact = JSON.parse(fs.readFileSync(outPath, "utf8")) as typeof report;
		const promoted = buildNetworkEgressBrokerProbeEvidenceFromReport(artifact);

		expect(result.exitCode, result.stdout).toBe(1);
		expect(report.attempts.find((attempt) => attempt.kind === "public-research")).toMatchObject({
			status: "pass",
			route: "telclaude-egress-broker",
		});
		expect(report.attempts.find((attempt) => attempt.kind === "provider")).toMatchObject({
			status: "pass",
		});
		expect(report.attempts.find((attempt) => attempt.kind === "model")).toMatchObject({
			status: "fail",
		});
		expect(artifact).toEqual(report);
		expect(promoted.status).toBe("fail");
		expect(
			promoted.checks.find((check) => check.name === "egress.direct-model-denied"),
		).toMatchObject({
			status: "fail",
		});
		expect(fs.readFileSync(callsPath, "utf8")).toContain("exec -i tc-hermes-contained");
	});
});

async function runHermesCommand(args: string[]): Promise<{ stdout: string; exitCode?: number }> {
	const program = new Command();
	let stdout = "";
	const originalLog = console.log;
	program.exitOverride();
	program.configureOutput({
		writeOut: (chunk: string) => {
			stdout += chunk;
		},
		writeErr: (chunk: string) => {
			stdout += chunk;
		},
	});
	registerHermesCommand(program);
	const originalExitCode = process.exitCode;
	process.exitCode = undefined;
	console.log = (...values: unknown[]) => {
		stdout += `${values.map(String).join(" ")}\n`;
	};
	try {
		await program.parseAsync(["node", "telclaude", ...args], { from: "node" });
		return { stdout, exitCode: process.exitCode };
	} finally {
		console.log = originalLog;
		process.exitCode = originalExitCode;
	}
}
