import type { Command } from "commander";
import {
	buildHermesDoctorReport,
	buildHermesGenerateDryRun,
	DEFAULT_COMPAT_LOCKFILE_PATH,
	DEFAULT_FEATURE_PROBE_MATRIX_PATH,
	evaluateCutoverCheck,
	parseHermesPin,
	readJsonFile,
	readOptionalJsonFile,
	resolveHermesArtifactPath,
} from "../hermes/foundation.js";
import { collectHermesInventory } from "../hermes/inventory.js";

type JsonOption = {
	json?: boolean;
};

type PinOption = {
	pin?: string;
};

function printJson(value: unknown): void {
	console.log(JSON.stringify(value, null, 2));
}

function resolvePin(options: PinOption) {
	return parseHermesPin(options.pin ?? process.env.TELCLAUDE_HERMES_PIN);
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
		.command("cutover-check")
		.description("Evaluate strict Hermes wrapper cutover evidence")
		.option("--strict", "Fail closed for missing or unsafe evidence")
		.option("--dry-run", "Evaluate evidence without changing runtime state")
		.option("--json", "Emit structured JSON")
		.requiredOption("--input <path>", "Cutover input bundle JSON path")
		.action((options: JsonOption & { input: string; strict?: boolean; dryRun?: boolean }) => {
			const strict = options.strict ?? true;
			const dryRun = options.dryRun ?? false;
			let input: unknown;
			try {
				input = readJsonFile(resolveHermesArtifactPath(options.input));
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
		});
}
