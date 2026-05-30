import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { Command } from "commander";
import {
	DEFAULT_APPROVAL_CONTINUATION_EVIDENCE_PATH,
	evaluateApprovalContinuationEvidence,
} from "../hermes/approval-continuation.js";
import {
	buildCompatibilityLockfileDraft,
	buildCutoverInputBundleFromArtifacts,
	buildCutoverScopeManifestFromInventory,
	buildHermesDoctorReport,
	buildHermesGenerateDryRun,
	DEFAULT_COMPAT_LOCKFILE_PATH,
	DEFAULT_CUTOVER_SCOPE_PATH,
	DEFAULT_DECISION_LOG_PATH,
	DEFAULT_FEATURE_PROBE_MATRIX_PATH,
	DEFAULT_FIXTURE_RESULTS_PATH,
	DEFAULT_NETWORK_PROBES_PATH,
	DEFAULT_NO_FORK_PROOF_PATH,
	DEFAULT_ROLLBACK_REHEARSAL_PATH,
	evaluateCutoverCheck,
	parseHermesPin,
	readJsonFile,
	readOptionalJsonFile,
	resolveHermesArtifactPath,
} from "../hermes/foundation.js";
import { collectHermesInventory } from "../hermes/inventory.js";
import {
	buildHermesCliProbeInvocation,
	DEFAULT_HERMES_CLI_HEADLESS_EVIDENCE_PATH,
	runHermesCliHeadlessProbe,
	runHermesLaunchInvocation,
} from "../hermes/private-runtime.js";

type JsonOption = {
	json?: boolean;
};

type PinOption = {
	pin?: string;
};

type ProbeOption = JsonOption & {
	allowRun?: boolean;
	cwd?: string;
	evidence: string;
	hermesBin?: string;
	hermesHome?: string;
	out?: string;
	prompt?: string;
	timeoutMs?: string;
};

function printJson(value: unknown): void {
	console.log(JSON.stringify(value, null, 2));
}

function resolvePin(options: PinOption) {
	return parseHermesPin(options.pin ?? process.env.TELCLAUDE_HERMES_PIN);
}

function writeJsonArtifact(filePath: string, value: unknown): void {
	fs.mkdirSync(path.dirname(filePath), { recursive: true });
	const tmpPath = `${filePath}.tmp.${process.pid}`;
	fs.writeFileSync(tmpPath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
	fs.renameSync(tmpPath, filePath);
}

function resolveHermesBin(value: string | undefined): string {
	return value?.trim() || process.env.TELCLAUDE_HERMES_BIN?.trim() || "hermes";
}

function resolveHermesHome(value: string | undefined): string {
	return path.resolve(
		value?.trim() ||
			process.env.TELCLAUDE_HERMES_HOME?.trim() ||
			path.join(os.tmpdir(), "telclaude-hermes-cli-headless"),
	);
}

function parseTimeoutMs(value: string | undefined): number | undefined {
	if (!value?.trim()) return undefined;
	const parsed = Number.parseInt(value, 10);
	if (!Number.isFinite(parsed) || parsed <= 0) {
		throw new Error(`Invalid --timeout-ms value: ${value}`);
	}
	return parsed;
}

function readWrapperPackageVersion(): string {
	const packageJson = readJsonFile(resolveHermesArtifactPath("package.json"));
	if (
		typeof packageJson === "object" &&
		packageJson !== null &&
		"version" in packageJson &&
		typeof packageJson.version === "string"
	) {
		return packageJson.version;
	}
	throw new Error("package.json is missing a string version");
}

export function registerHermesCommand(program: Command): void {
	const hermes = program
		.command("hermes")
		.description("Inspect and generate the no-fork Hermes wrapper foundation");

	hermes
		.command("doctor")
		.description("Check pinned Hermes wrapper readiness")
		.option("--json", "Emit structured JSON")
		.option("--pin <pin>", "Pinned Hermes version, commit, package, or image digest")
		.option(
			"--feature-probes <path>",
			"Feature-probe matrix JSON path",
			DEFAULT_FEATURE_PROBE_MATRIX_PATH,
		)
		.option("--probes", "Require and validate the feature-probe matrix")
		.option("--lockfile <path>", "Compatibility lockfile JSON path", DEFAULT_COMPAT_LOCKFILE_PATH)
		.option("--compat-lock", "Require and validate the compatibility lockfile")
		.action(
			(
				options: JsonOption &
					PinOption & {
						featureProbes: string;
						probes?: boolean;
						lockfile: string;
						compatLock?: boolean;
					},
			) => {
				let featureProbeMatrix: unknown;
				let featureProbeMatrixMissing: string | undefined;
				if (options.probes) {
					const artifactPath = resolveHermesArtifactPath(options.featureProbes);
					featureProbeMatrix = readOptionalJsonFile(artifactPath);
					if (featureProbeMatrix === undefined) {
						featureProbeMatrixMissing = `required feature-probe matrix is missing: ${artifactPath}`;
					}
				}

				let lockfile: unknown;
				let lockfileMissing: string | undefined;
				if (options.compatLock) {
					const artifactPath = resolveHermesArtifactPath(options.lockfile);
					lockfile = readOptionalJsonFile(artifactPath);
					if (lockfile === undefined) {
						lockfileMissing = `required compatibility lockfile is missing: ${artifactPath}`;
					}
				}

				const report = buildHermesDoctorReport({
					pin: resolvePin(options),
					featureProbeMatrix,
					featureProbeMatrixMissing,
					lockfile,
					lockfileMissing,
				});
				if (options.json) {
					printJson(report);
				} else {
					console.log(`Hermes wrapper doctor: ${report.status}`);
					for (const check of report.checks) {
						console.log(`- ${check.status.toUpperCase()} ${check.name}: ${check.detail}`);
					}
				}
				process.exitCode = report.status === "pass" ? 0 : 1;
			},
		);

	hermes
		.command("generate")
		.description("Generate Hermes wrapper profile artifacts")
		.requiredOption("--dry-run", "Preview generated artifacts without writing files")
		.option("--json", "Emit structured JSON")
		.option("--pin <pin>", "Pinned Hermes version, commit, package, or image digest")
		.option("--out <dir>", "Output directory for generated Hermes profiles", "/tmp/tc-hermes")
		.action((options: JsonOption & PinOption & { out: string }) => {
			try {
				const report = buildHermesGenerateDryRun({
					pin: resolvePin(options),
					outDir: options.out,
				});
				if (options.json) {
					printJson(report);
				} else {
					console.log(`Hermes generate dry-run: ${report.outDir}`);
					for (const output of report.outputs) {
						console.log(`- ${output.classification} ${output.path}`);
					}
				}
			} catch (error) {
				console.error(`Error: ${String(error instanceof Error ? error.message : error)}`);
				process.exitCode = 1;
			}
		});

	hermes
		.command("inventory")
		.description("Emit the Phase 0 wrapper inventory")
		.option("--json", "Emit structured JSON")
		.action((options: JsonOption) => {
			const inventory = collectHermesInventory();
			if (options.json) {
				printJson(inventory);
			} else {
				console.log(
					`Hermes inventory: ${inventory.status}, ${inventory.summary.workflows} workflow(s), ${inventory.summary.issues} issue(s)`,
				);
			}
		});

	hermes
		.command("probe")
		.description("Evaluate a single Hermes wrapper feature probe")
		.argument("<surface>", "Feature surface id")
		.option("--json", "Emit structured JSON")
		.option("--allow-run", "Permit the probe to execute a real pinned-Hermes command")
		.option("--hermes-bin <path>", "Hermes executable path for executable probes")
		.option("--hermes-home <dir>", "HERMES_HOME for executable probes")
		.option("--cwd <dir>", "Working directory for executable probes", process.cwd())
		.option("--out <path>", "Write executable probe evidence to this path")
		.option("--prompt <prompt>", "Prompt for execution.cli_headless")
		.option("--timeout-ms <ms>", "Maximum executable probe runtime in milliseconds")
		.option(
			"--evidence <path>",
			"Approval-continuation evidence JSON path",
			DEFAULT_APPROVAL_CONTINUATION_EVIDENCE_PATH,
		)
		.action(async (surface: string, options: ProbeOption) => {
			if (surface === "execution.cli_headless") {
				let report: Awaited<ReturnType<typeof runHermesCliHeadlessProbe>>;
				try {
					const invocation = buildHermesCliProbeInvocation({
						hermesBin: resolveHermesBin(options.hermesBin),
						hermesHome: resolveHermesHome(options.hermesHome),
						cwd: path.resolve(options.cwd ?? process.cwd()),
						prompt: options.prompt,
					});
					const timeoutMs = parseTimeoutMs(options.timeoutMs);
					report = await runHermesCliHeadlessProbe({
						allowRun: options.allowRun === true,
						invocation,
						runProcess: (launch) => runHermesLaunchInvocation(launch, { timeoutMs }),
					});
				} catch (error) {
					report = {
						schemaVersion: "telclaude.hermes.probe-result.v1",
						probeId: "execution.cli_headless",
						status: "fail",
						ran: false,
						summary: error instanceof Error ? error.message : String(error),
						findings: [],
					};
				}

				const outPath =
					options.allowRun === true
						? resolveHermesArtifactPath(options.out ?? DEFAULT_HERMES_CLI_HEADLESS_EVIDENCE_PATH)
						: options.out
							? resolveHermesArtifactPath(options.out)
							: undefined;
				if (outPath && report.status !== "pending") {
					writeJsonArtifact(outPath, report);
				}

				if (options.json) {
					printJson(report);
				} else {
					console.log(`Hermes probe ${surface}: ${report.status}`);
					console.log(`- ${report.status.toUpperCase()} execution.cli_headless: ${report.summary}`);
					if (outPath && report.status !== "pending") console.log(`- evidence: ${outPath}`);
				}
				process.exitCode = report.status === "pass" ? 0 : report.status === "pending" ? 2 : 1;
				return;
			}

			if (surface !== "execution.approval_continuation") {
				const report = {
					schemaVersion: "telclaude.hermes.probe-report.v1",
					status: "input_error",
					surface,
					detail: `Unsupported Hermes probe surface: ${surface}`,
				};
				if (options.json) {
					printJson(report);
				} else {
					console.log(`Hermes probe ${surface}: ${report.status}`);
					console.log(`- FAIL surface: ${report.detail}`);
				}
				process.exitCode = 2;
				return;
			}

			const evidencePath = resolveHermesArtifactPath(options.evidence);
			const report = evaluateApprovalContinuationEvidence(readOptionalJsonFile(evidencePath), {
				missingPath: evidencePath,
			});
			if (options.json) {
				printJson(report);
			} else {
				console.log(`Hermes probe ${surface}: ${report.status}`);
				for (const gate of report.gates) {
					console.log(`- ${gate.status.toUpperCase()} ${gate.name}: ${gate.detail}`);
				}
			}
			process.exitCode = report.status === "pass" ? 0 : report.status === "input_error" ? 2 : 1;
		});

	hermes
		.command("cutover-check")
		.description("Evaluate strict Hermes wrapper cutover evidence")
		.option("--strict", "Fail closed for missing or unsafe evidence")
		.option("--dry-run", "Evaluate evidence without changing runtime state")
		.option("--json", "Emit structured JSON")
		.option(
			"--inventory <path>",
			"Inventory snapshot JSON path; collects live inventory when omitted",
		)
		.option("--scope <path>", "Cutover scope manifest JSON path", DEFAULT_CUTOVER_SCOPE_PATH)
		.option("--decisions <path>", "Decision log JSON path", DEFAULT_DECISION_LOG_PATH)
		.option(
			"--feature-probes <path>",
			"Feature-probe matrix JSON path",
			DEFAULT_FEATURE_PROBE_MATRIX_PATH,
		)
		.option("--lockfile <path>", "Compatibility lockfile JSON path", DEFAULT_COMPAT_LOCKFILE_PATH)
		.option("--fixtures <path>", "Fixture result bundle JSON path", DEFAULT_FIXTURE_RESULTS_PATH)
		.option(
			"--network-probes <path>",
			"Network probe bundle JSON path",
			DEFAULT_NETWORK_PROBES_PATH,
		)
		.option("--nofork <path>", "No-fork proof bundle JSON path", DEFAULT_NO_FORK_PROOF_PATH)
		.option(
			"--rollback <path>",
			"Rollback rehearsal evidence JSON path",
			DEFAULT_ROLLBACK_REHEARSAL_PATH,
		)
		.action(
			(
				options: JsonOption & {
					inventory?: string;
					scope: string;
					decisions: string;
					featureProbes: string;
					lockfile: string;
					fixtures: string;
					networkProbes: string;
					nofork: string;
					rollback: string;
					strict?: boolean;
					dryRun?: boolean;
				},
			) => {
				const strict = options.strict ?? true;
				const dryRun = options.dryRun ?? false;
				let input: unknown;
				try {
					input = buildCutoverInputBundleFromArtifacts({
						inventory: options.inventory
							? readJsonFile(resolveHermesArtifactPath(options.inventory))
							: collectHermesInventory(),
						scopeManifest: readJsonFile(resolveHermesArtifactPath(options.scope)),
						decisionLog: readJsonFile(resolveHermesArtifactPath(options.decisions)),
						lockfile: readJsonFile(resolveHermesArtifactPath(options.lockfile)),
						featureProbeMatrix: readJsonFile(resolveHermesArtifactPath(options.featureProbes)),
						fixtureResults: readJsonFile(resolveHermesArtifactPath(options.fixtures)),
						noForkProof: readJsonFile(resolveHermesArtifactPath(options.nofork)),
						networkProbes: readJsonFile(resolveHermesArtifactPath(options.networkProbes)),
						rollbackRehearsal: readJsonFile(resolveHermesArtifactPath(options.rollback)),
					});
				} catch (error) {
					const report = {
						status: "input_error",
						exitCode: 2,
						mode: { strict, dryRun },
						gates: [
							{
								name: "inputs.readable",
								status: "fail",
								detail: String(error instanceof Error ? error.message : error),
							},
						],
					};
					if (options.json) {
						printJson(report);
					} else {
						console.log(`Hermes cutover-check: ${report.status}`);
						console.log(`- FAIL ${report.gates[0].name}: ${report.gates[0].detail}`);
					}
					process.exitCode = report.exitCode;
					return;
				}

				const report = evaluateCutoverCheck(input, { strict, dryRun });
				if (options.json) {
					printJson(report);
				} else {
					console.log(`Hermes cutover-check: ${report.status}`);
					for (const gate of report.gates) {
						console.log(`- ${gate.status.toUpperCase()} ${gate.name}: ${gate.detail}`);
					}
				}
				process.exitCode = report.exitCode;
			},
		);

	hermes
		.command("cutover-scope")
		.description("Generate a fail-closed cutover scope skeleton from an inventory snapshot")
		.requiredOption("--inventory <path>", "Inventory snapshot JSON path")
		.option("--json", "Emit structured JSON")
		.action((options: JsonOption & { inventory: string }) => {
			try {
				const manifest = buildCutoverScopeManifestFromInventory(
					readJsonFile(resolveHermesArtifactPath(options.inventory)),
				);
				if (options.json) {
					printJson(manifest);
				} else {
					console.log(`Hermes cutover-scope: ${manifest.workflows.length} workflow(s)`);
					for (const workflow of manifest.workflows) {
						console.log(`- ${workflow.status.toUpperCase()} ${workflow.workflow_id}`);
					}
				}
			} catch (error) {
				console.error(`Error: ${String(error instanceof Error ? error.message : error)}`);
				process.exitCode = 1;
			}
		});

	hermes
		.command("compat-lock")
		.description("Generate a Hermes compatibility lockfile draft")
		.requiredOption("--dry-run", "Emit lockfile content without writing files")
		.option("--json", "Emit structured JSON")
		.option("--pin <pin>", "Pinned Hermes version, commit, package, or image digest")
		.option(
			"--feature-probes <path>",
			"Feature-probe matrix JSON path",
			DEFAULT_FEATURE_PROBE_MATRIX_PATH,
		)
		.action((options: JsonOption & PinOption & { featureProbes: string }) => {
			try {
				const lockfile = buildCompatibilityLockfileDraft({
					pin: resolvePin(options),
					featureProbeMatrix: readJsonFile(resolveHermesArtifactPath(options.featureProbes)),
					wrapperPackageVersion: readWrapperPackageVersion(),
				});
				if (options.json) {
					printJson(lockfile);
				} else {
					console.log(`Hermes compat-lock dry-run: ${lockfile.featureProbes.length} probe(s)`);
					for (const probe of lockfile.featureProbes) {
						console.log(`- ${probe.status.toUpperCase()} ${probe.surface_id}`);
					}
				}
			} catch (error) {
				console.error(`Error: ${String(error instanceof Error ? error.message : error)}`);
				process.exitCode = 1;
			}
		});
}
