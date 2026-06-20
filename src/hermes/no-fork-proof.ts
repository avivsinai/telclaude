import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import path from "node:path";
import type { InternalResponseProof } from "../internal-auth.js";
import {
	type HermesArtifactWriteOptions,
	type NoForkProof,
	resolveHermesArtifactPath,
	writeHermesJsonArtifact,
} from "./foundation.js";
import {
	NO_FORK_RUNNER_ATTESTATION_RUNNER,
	NO_FORK_RUNNER_ATTESTATION_SCHEMA_VERSION,
	NO_FORK_RUNNER_ATTESTATION_SOURCE,
	NO_FORK_WRAPPER_RUN_RUNNER,
	NO_FORK_WRAPPER_RUN_SCHEMA_VERSION,
	NO_FORK_WRAPPER_RUN_SOURCE,
	type NoForkWrapperRunSignedFields,
	noForkProofChecksSha256,
	noForkProofEvidenceSha256,
	noForkWrapperRunAttestationSignatureFailure,
	signNoForkRunnerAttestation,
} from "./no-fork-attestation.js";
import {
	DEFAULT_HERMES_SOURCE_COMMIT,
	DEFAULT_HERMES_UPSTREAM_REF,
	DEFAULT_HERMES_UPSTREAM_VERSION,
} from "./pin.js";

export {
	DEFAULT_HERMES_SOURCE_COMMIT,
	DEFAULT_HERMES_UPSTREAM_REF,
	DEFAULT_HERMES_UPSTREAM_VERSION,
} from "./pin.js";

export const HERMES_UPSTREAM_CHECKOUT_PATH_ENV = "HERMES_CHECKOUT_PATH";
export const DEFAULT_HERMES_UPSTREAM_CHECKOUT_PATH = "hermes-agent";
export const DEFAULT_HERMES_NO_FORK_EVIDENCE_PATH = "artifacts/hermes/no-fork.json";

export type NoForkGitResult = {
	readonly exitCode: number;
	readonly stdout: string;
	readonly stderr: string;
};

export type NoForkGitRunner = (readonlyArgs: readonly string[], cwd: string) => NoForkGitResult;

export type NoForkProofReport = NoForkProof & {
	readonly checkoutPath: string;
	readonly expectedRef: string;
	readonly expectedVersion: string;
	readonly expectedCommit: string;
	readonly head?: string;
	readonly expectedRefCommit?: string;
	readonly currentBranch?: string;
	readonly exactTags: readonly string[];
	readonly statusPorcelain: string;
	readonly diffExitCode?: number;
	readonly cachedDiffExitCode?: number;
	readonly checks: Array<{
		readonly name: string;
		readonly status: "pass" | "fail";
		readonly detail: string;
	}>;
};

export type NoForkWrapperRunEvidence = {
	readonly schemaVersion: typeof NO_FORK_WRAPPER_RUN_SCHEMA_VERSION;
	readonly source: typeof NO_FORK_WRAPPER_RUN_SOURCE;
	readonly runner: typeof NO_FORK_WRAPPER_RUN_RUNNER;
	readonly checkoutPath: string;
	readonly expectedRef: string;
	readonly expectedVersion: string;
	readonly expectedCommit: string;
	readonly head: string;
	readonly expectedRefCommit: string;
	readonly startedAt: string;
	readonly endedAt: string;
	readonly wrapperPackageSha256: `sha256:${string}`;
	readonly profileGenerationSha256: `sha256:${string}`;
	readonly fixtureResultsSha256: `sha256:${string}`;
	readonly transcriptSha256: `sha256:${string}`;
	readonly p0Command: readonly string[];
	readonly p0ExitCode: number;
	readonly p0Status: "pass" | "fail";
	readonly runtimeSourceReplacementDenied: boolean;
	readonly monkeypatchDenied: boolean;
	readonly signature: InternalResponseProof;
};

const SHA256_DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/i;

export function buildNoForkProof(input: {
	readonly checkoutPath?: string;
	readonly expectedRef?: string;
	readonly expectedVersion?: string;
	readonly expectedCommit?: string;
	readonly evidencePath?: string;
	readonly runner?: NoForkGitRunner;
	readonly wrapperRun?: NoForkWrapperRunEvidence;
}): NoForkProofReport {
	const checkoutPath = path.resolve(
		input.checkoutPath ??
			process.env[HERMES_UPSTREAM_CHECKOUT_PATH_ENV] ??
			DEFAULT_HERMES_UPSTREAM_CHECKOUT_PATH,
	);
	const expectedRef = nonEmpty(input.expectedRef, DEFAULT_HERMES_UPSTREAM_REF);
	const expectedVersion = nonEmpty(input.expectedVersion, DEFAULT_HERMES_UPSTREAM_VERSION);
	const expectedCommit = nonEmpty(input.expectedCommit, DEFAULT_HERMES_SOURCE_COMMIT);
	const evidencePath = input.evidencePath ?? DEFAULT_HERMES_NO_FORK_EVIDENCE_PATH;
	const runner = input.runner ?? runGit;
	const checks: NoForkProofReport["checks"] = [];

	const topLevel = runner(["rev-parse", "--show-toplevel"], checkoutPath);
	const checkoutExists = topLevel.exitCode === 0 && topLevel.stdout.trim() === checkoutPath;
	checks.push({
		name: "checkout.present",
		status: checkoutExists ? "pass" : "fail",
		detail: checkoutExists
			? `Hermes checkout found at ${checkoutPath}`
			: cleanGitError(topLevel, `Hermes checkout not found at ${checkoutPath}`),
	});

	const headResult = checkoutExists ? runner(["rev-parse", "HEAD"], checkoutPath) : failedGit();
	const head = headResult.exitCode === 0 ? headResult.stdout.trim() : undefined;
	checks.push({
		name: "checkout.head",
		status: head ? "pass" : "fail",
		detail: head ? `HEAD is ${head}` : cleanGitError(headResult, "HEAD could not be resolved"),
	});

	const expectedResult = checkoutExists
		? runner(["rev-parse", "--verify", `${expectedRef}^{commit}`], checkoutPath)
		: failedGit();
	const expectedRefCommit =
		expectedResult.exitCode === 0 ? expectedResult.stdout.trim() : undefined;
	checks.push({
		name: "checkout.expectedRef",
		status: expectedRefCommit ? "pass" : "fail",
		detail: expectedRefCommit
			? `${expectedRef} resolves to ${expectedRefCommit}`
			: cleanGitError(expectedResult, `${expectedRef} could not be resolved`),
	});

	const headAtExpected = !!head && !!expectedRefCommit && head === expectedRefCommit;
	const refAtExpectedCommit = !!expectedRefCommit && expectedRefCommit === expectedCommit;
	checks.push({
		name: "checkout.pinned",
		status: headAtExpected ? "pass" : "fail",
		detail: headAtExpected
			? `HEAD matches pinned Hermes ref ${expectedRef}`
			: `HEAD ${head ?? "unknown"} does not match ${expectedRef} ${expectedRefCommit ?? "unknown"}`,
	});
	checks.push({
		name: "checkout.expectedCommit",
		status: refAtExpectedCommit ? "pass" : "fail",
		detail: refAtExpectedCommit
			? `${expectedRef} resolves to expected commit ${expectedCommit}`
			: `${expectedRef} resolves to ${expectedRefCommit ?? "unknown"}, expected ${expectedCommit}`,
	});

	const status = checkoutExists ? runner(["status", "--porcelain=v1"], checkoutPath) : failedGit();
	const statusPorcelain = status.exitCode === 0 ? status.stdout.trim() : "";
	checks.push({
		name: "checkout.statusClean",
		status: status.exitCode === 0 && statusPorcelain.length === 0 ? "pass" : "fail",
		detail:
			status.exitCode === 0 && statusPorcelain.length === 0
				? "git status porcelain is clean"
				: status.exitCode === 0
					? `git status porcelain is not clean: ${statusPorcelain}`
					: cleanGitError(status, "git status failed"),
	});

	const diff = checkoutExists ? runner(["diff", "--quiet"], checkoutPath) : failedGit();
	checks.push({
		name: "checkout.diffClean",
		status: diff.exitCode === 0 ? "pass" : "fail",
		detail: diff.exitCode === 0 ? "git diff --quiet is clean" : "working tree diff is not clean",
	});

	const cachedDiff = checkoutExists
		? runner(["diff", "--cached", "--quiet"], checkoutPath)
		: failedGit();
	checks.push({
		name: "checkout.indexClean",
		status: cachedDiff.exitCode === 0 ? "pass" : "fail",
		detail:
			cachedDiff.exitCode === 0 ? "git diff --cached --quiet is clean" : "index diff is not clean",
	});

	const branchResult = checkoutExists
		? runner(["branch", "--show-current"], checkoutPath)
		: failedGit();
	const tagResult = checkoutExists
		? runner(["tag", "--points-at", "HEAD"], checkoutPath)
		: failedGit();
	const exactTags =
		tagResult.exitCode === 0
			? tagResult.stdout
					.split(/\r?\n/)
					.map((tag) => tag.trim())
					.filter((tag) => tag.length > 0)
			: [];

	const postStatus = checkoutExists
		? runner(["status", "--porcelain=v1"], checkoutPath)
		: failedGit();
	const postStatusPorcelain = postStatus.exitCode === 0 ? postStatus.stdout.trim() : "";
	const postDiff = checkoutExists ? runner(["diff", "--quiet"], checkoutPath) : failedGit();
	const postCachedDiff = checkoutExists
		? runner(["diff", "--cached", "--quiet"], checkoutPath)
		: failedGit();
	const wrapperRun = input.wrapperRun;
	const wrapperRunSignatureFailure = wrapperRun
		? noForkWrapperRunAttestationSignatureFailure(wrapperRun, { allowStale: true })
		: "signature is missing";
	const runnerAttestationAvailable =
		!!wrapperRun && !!head && !!expectedRefCommit && wrapperRunSignatureFailure === null;
	const wrapperRunCheckoutBound =
		!!wrapperRun &&
		wrapperRun.checkoutPath === checkoutPath &&
		wrapperRun.expectedRef === expectedRef &&
		wrapperRun.expectedVersion === expectedVersion &&
		wrapperRun.expectedCommit === expectedCommit &&
		wrapperRun.head === head &&
		wrapperRun.expectedRefCommit === expectedRefCommit;
	checks.push({
		name: "runner.attestation",
		status: runnerAttestationAvailable ? "pass" : "fail",
		detail: runnerAttestationAvailable
			? "no-fork wrapper run signature is valid"
			: `no-fork wrapper run signature is invalid: ${wrapperRunSignatureFailure}`,
	});
	checks.push({
		name: "runner.checkoutBinding",
		status: wrapperRunCheckoutBound ? "pass" : "fail",
		detail: wrapperRunCheckoutBound
			? "wrapper run evidence is bound to the proved checkout/head/ref/version"
			: "wrapper run evidence is not bound to the proved checkout/head/ref/version",
	});
	checks.push({
		name: "runner.p0",
		status:
			input.wrapperRun?.p0Status === "pass" && input.wrapperRun.p0ExitCode === 0 ? "pass" : "fail",
		detail:
			input.wrapperRun?.p0Status === "pass" && input.wrapperRun.p0ExitCode === 0
				? "P0 fixture/cutover command passed"
				: "P0 fixture/cutover command did not pass",
	});
	checks.push({
		name: "runner.noRuntimeSourceReplacement",
		status: input.wrapperRun?.runtimeSourceReplacementDenied === true ? "pass" : "fail",
		detail:
			input.wrapperRun?.runtimeSourceReplacementDenied === true
				? "runtime source replacement denial was observed"
				: "runtime source replacement denial was not observed",
	});
	checks.push({
		name: "runner.noMonkeypatch",
		status: input.wrapperRun?.monkeypatchDenied === true ? "pass" : "fail",
		detail:
			input.wrapperRun?.monkeypatchDenied === true
				? "monkeypatch denial was observed"
				: "monkeypatch denial was not observed",
	});
	checks.push({
		name: "runner.postStatusClean",
		status: postStatus.exitCode === 0 && postStatusPorcelain.length === 0 ? "pass" : "fail",
		detail:
			postStatus.exitCode === 0 && postStatusPorcelain.length === 0
				? "post-run git status porcelain is clean"
				: postStatus.exitCode === 0
					? `post-run git status porcelain is not clean: ${postStatusPorcelain}`
					: cleanGitError(postStatus, "post-run git status failed"),
	});
	checks.push({
		name: "runner.postDiffClean",
		status: postDiff.exitCode === 0 ? "pass" : "fail",
		detail:
			postDiff.exitCode === 0 ? "post-run git diff --quiet is clean" : "post-run diff is not clean",
	});
	checks.push({
		name: "runner.postIndexClean",
		status: postCachedDiff.exitCode === 0 ? "pass" : "fail",
		detail:
			postCachedDiff.exitCode === 0
				? "post-run git diff --cached --quiet is clean"
				: "post-run index diff is not clean",
	});

	const hermesCheckoutClean = checks.every((check) => check.status === "pass");
	const unsignedReport: Omit<NoForkProofReport, "runnerAttestation"> = {
		schemaVersion: 1,
		hermesCheckoutClean,
		evidence_path: evidencePath,
		checkoutPath,
		expectedRef,
		expectedVersion,
		expectedCommit,
		...(head ? { head } : {}),
		...(expectedRefCommit ? { expectedRefCommit } : {}),
		...(branchResult.exitCode === 0 && branchResult.stdout.trim()
			? { currentBranch: branchResult.stdout.trim() }
			: {}),
		exactTags,
		statusPorcelain,
		diffExitCode: diff.exitCode,
		cachedDiffExitCode: cachedDiff.exitCode,
		checks,
	};
	const signedRunnerAttestation =
		runnerAttestationAvailable && wrapperRun && head && expectedRefCommit
			? signNoForkRunnerAttestation({
					schemaVersion: NO_FORK_RUNNER_ATTESTATION_SCHEMA_VERSION,
					source: NO_FORK_RUNNER_ATTESTATION_SOURCE,
					runner: NO_FORK_RUNNER_ATTESTATION_RUNNER,
					wrapperRunSchemaVersion: wrapperRun.schemaVersion,
					wrapperRunSource: wrapperRun.source,
					wrapperRunRunner: wrapperRun.runner,
					startedAt: wrapperRun.startedAt,
					endedAt: wrapperRun.endedAt,
					checkoutPath,
					expectedRef,
					expectedVersion,
					expectedCommit,
					head,
					expectedRefCommit,
					wrapperPackageSha256: wrapperRun.wrapperPackageSha256,
					profileGenerationSha256: wrapperRun.profileGenerationSha256,
					fixtureResultsSha256: wrapperRun.fixtureResultsSha256,
					transcriptSha256: wrapperRun.transcriptSha256,
					checksSha256: noForkProofChecksSha256(checks),
					evidenceSha256: noForkProofEvidenceSha256(unsignedReport),
					p0Command: wrapperRun.p0Command,
					p0ExitCode: wrapperRun.p0ExitCode,
					p0Status: wrapperRun.p0Status,
					runtimeSourceReplacementDenied: wrapperRun.runtimeSourceReplacementDenied,
					monkeypatchDenied: wrapperRun.monkeypatchDenied,
					postRunStatusPorcelain: postStatusPorcelain,
					postRunDiffExitCode: postDiff.exitCode,
					postRunCachedDiffExitCode: postCachedDiff.exitCode,
				})
			: undefined;
	const runnerAttestation = signedRunnerAttestation
		? {
				...signedRunnerAttestation,
				p0Command: [...signedRunnerAttestation.p0Command],
			}
		: undefined;
	return {
		...unsignedReport,
		...(runnerAttestation ? { runnerAttestation } : {}),
	};
}

export function writeNoForkProofReport(
	report: NoForkProofReport,
	options: HermesArtifactWriteOptions = {},
): NoForkProofReport {
	const outputPath = resolveHermesArtifactPath(report.evidence_path);
	writeHermesJsonArtifact(outputPath, report, options);
	return report;
}

export function parseNoForkWrapperRunEvidence(value: unknown): NoForkWrapperRunEvidence {
	const errors: string[] = [];
	if (typeof value !== "object" || value === null || Array.isArray(value)) {
		throw new Error("invalid no-fork wrapper-run evidence: expected an object");
	}
	const record = value as Record<string, unknown>;
	const schemaVersion = readRequiredLiteral(
		record,
		"schemaVersion",
		NO_FORK_WRAPPER_RUN_SCHEMA_VERSION,
		errors,
	);
	const source = readRequiredLiteral(record, "source", NO_FORK_WRAPPER_RUN_SOURCE, errors);
	const runner = readRequiredLiteral(record, "runner", NO_FORK_WRAPPER_RUN_RUNNER, errors);
	const checkoutPath = readRequiredString(record, "checkoutPath", errors);
	const expectedRef = readRequiredString(record, "expectedRef", errors);
	const expectedVersion = readRequiredString(record, "expectedVersion", errors);
	const expectedCommit = readRequiredString(record, "expectedCommit", errors);
	const head = readRequiredString(record, "head", errors);
	const expectedRefCommit = readRequiredString(record, "expectedRefCommit", errors);
	const startedAt = readRequiredString(record, "startedAt", errors);
	const endedAt = readRequiredString(record, "endedAt", errors);
	const startedAtMs = readTimestampMs(startedAt, "startedAt", errors);
	const endedAtMs = readTimestampMs(endedAt, "endedAt", errors);
	if (startedAtMs !== undefined && endedAtMs !== undefined && endedAtMs < startedAtMs) {
		errors.push("endedAt must not be before startedAt");
	}
	const wrapperPackageSha256 = readRequiredSha256(record, "wrapperPackageSha256", errors);
	const profileGenerationSha256 = readRequiredSha256(record, "profileGenerationSha256", errors);
	const fixtureResultsSha256 = readRequiredSha256(record, "fixtureResultsSha256", errors);
	const transcriptSha256 = readRequiredSha256(record, "transcriptSha256", errors);
	const p0Command = readRequiredStringArray(record, "p0Command", errors);
	const p0ExitCode = readRequiredInteger(record, "p0ExitCode", errors);
	let p0Status: "pass" | "fail" = "fail";
	if (record.p0Status === "pass" || record.p0Status === "fail") {
		p0Status = record.p0Status;
	} else {
		errors.push("p0Status must be pass or fail");
	}
	const runtimeSourceReplacementDenied = readRequiredBoolean(
		record,
		"runtimeSourceReplacementDenied",
		errors,
	);
	const monkeypatchDenied = readRequiredBoolean(record, "monkeypatchDenied", errors);
	const signature = readInternalResponseProof(record, "signature", errors);
	const candidate: NoForkWrapperRunSignedFields & { signature: InternalResponseProof } = {
		schemaVersion,
		source,
		runner,
		checkoutPath,
		expectedRef,
		expectedVersion,
		expectedCommit,
		head,
		expectedRefCommit,
		startedAt,
		endedAt,
		wrapperPackageSha256,
		profileGenerationSha256,
		fixtureResultsSha256,
		transcriptSha256,
		p0Command,
		p0ExitCode,
		p0Status,
		runtimeSourceReplacementDenied,
		monkeypatchDenied,
		signature,
	};
	const signatureFailure =
		errors.length === 0
			? noForkWrapperRunAttestationSignatureFailure(candidate, { allowStale: true })
			: null;
	if (signatureFailure) {
		errors.push(`signature is invalid: ${signatureFailure}`);
	}
	if (errors.length > 0) {
		throw new Error(`invalid no-fork wrapper-run evidence: ${errors.join("; ")}`);
	}
	return candidate;
}

function runGit(args: readonly string[], cwd: string): NoForkGitResult {
	const result = spawnSync("git", [...args], {
		cwd,
		encoding: "utf8",
		stdio: ["ignore", "pipe", "pipe"],
	});
	return {
		exitCode: result.status ?? 1,
		stdout: result.stdout ?? "",
		stderr: result.stderr ?? "",
	};
}

function failedGit(): NoForkGitResult {
	return { exitCode: 1, stdout: "", stderr: "" };
}

function readRequiredString(
	record: Record<string, unknown>,
	key: string,
	errors: string[],
): string {
	const value = record[key];
	if (typeof value === "string" && value.trim()) return value;
	errors.push(`${key} must be a non-empty string`);
	return "";
}

function readRequiredSha256(
	record: Record<string, unknown>,
	key: string,
	errors: string[],
): `sha256:${string}` {
	const value = readRequiredString(record, key, errors);
	if (value && !SHA256_DIGEST_PATTERN.test(value)) {
		errors.push(`${key} must be a sha256 digest`);
	}
	return value as `sha256:${string}`;
}

function readRequiredLiteral<T extends string>(
	record: Record<string, unknown>,
	key: string,
	expected: T,
	errors: string[],
): T {
	const value = readRequiredString(record, key, errors);
	if (value && value !== expected) {
		errors.push(`${key} must be ${expected}`);
	}
	return expected;
}

function readTimestampMs(value: string, key: string, errors: string[]): number | undefined {
	if (!value) return undefined;
	const timestamp = Date.parse(value);
	if (!Number.isFinite(timestamp)) {
		errors.push(`${key} must be a valid timestamp`);
		return undefined;
	}
	return timestamp;
}

function readRequiredStringArray(
	record: Record<string, unknown>,
	key: string,
	errors: string[],
): string[] {
	const value = record[key];
	if (
		Array.isArray(value) &&
		value.length > 0 &&
		value.every((entry) => typeof entry === "string" && entry.trim())
	) {
		return value;
	}
	errors.push(`${key} must be a non-empty string array`);
	return [];
}

function readRequiredInteger(
	record: Record<string, unknown>,
	key: string,
	errors: string[],
): number {
	const value = record[key];
	if (typeof value === "number" && Number.isInteger(value)) return value;
	errors.push(`${key} must be an integer`);
	return 1;
}

function readRequiredBoolean(
	record: Record<string, unknown>,
	key: string,
	errors: string[],
): boolean {
	const value = record[key];
	if (typeof value === "boolean") return value;
	errors.push(`${key} must be a boolean`);
	return false;
}

function readInternalResponseProof(
	record: Record<string, unknown>,
	key: string,
	errors: string[],
): InternalResponseProof {
	const value = record[key];
	if (typeof value !== "object" || value === null || Array.isArray(value)) {
		errors.push(`${key} must be a response proof object`);
		return emptyInternalResponseProof();
	}
	const proof = value as Record<string, unknown>;
	for (const proofKey of [
		"scope",
		"timestamp",
		"nonce",
		"method",
		"path",
		"requestBodySha256",
		"responseBodySha256",
		"signature",
	]) {
		if (typeof proof[proofKey] !== "string" || !proof[proofKey].trim()) {
			errors.push(`${key}.${proofKey} must be a non-empty string`);
		}
	}
	if (proof.version !== "v1") {
		errors.push(`${key}.version must be v1`);
	}
	return proof as InternalResponseProof;
}

function emptyInternalResponseProof(): InternalResponseProof {
	return {
		version: "v1",
		scope: "",
		timestamp: "",
		nonce: "",
		method: "",
		path: "",
		requestBodySha256: "",
		responseBodySha256: "",
		signature: "",
	};
}

function nonEmpty(value: string | undefined, fallback: string): string {
	const trimmed = value?.trim();
	return trimmed ? trimmed : fallback;
}

function cleanGitError(result: NoForkGitResult, fallback: string): string {
	return (result.stderr || result.stdout || fallback).replace(/\s+/g, " ").trim();
}

export function noForkSha256Digest(value: string): `sha256:${string}` {
	return `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
}
