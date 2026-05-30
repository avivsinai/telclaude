import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { type NoForkProof, resolveHermesArtifactPath } from "./foundation.js";

export const DEFAULT_HERMES_UPSTREAM_CHECKOUT_PATH = "/home/user/MyProjects/hermes-agent";
export const DEFAULT_HERMES_UPSTREAM_REF = "v2026.5.29";
export const DEFAULT_HERMES_UPSTREAM_VERSION = "0.15.1";
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

export function buildNoForkProof(input: {
	readonly checkoutPath?: string;
	readonly expectedRef?: string;
	readonly expectedVersion?: string;
	readonly evidencePath?: string;
	readonly runner?: NoForkGitRunner;
}): NoForkProofReport {
	const checkoutPath = path.resolve(input.checkoutPath ?? DEFAULT_HERMES_UPSTREAM_CHECKOUT_PATH);
	const expectedRef = nonEmpty(input.expectedRef, DEFAULT_HERMES_UPSTREAM_REF);
	const expectedVersion = nonEmpty(input.expectedVersion, DEFAULT_HERMES_UPSTREAM_VERSION);
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
	checks.push({
		name: "checkout.pinned",
		status: headAtExpected ? "pass" : "fail",
		detail: headAtExpected
			? `HEAD matches pinned Hermes ref ${expectedRef}`
			: `HEAD ${head ?? "unknown"} does not match ${expectedRef} ${expectedRefCommit ?? "unknown"}`,
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

	const hermesCheckoutClean = checks.every((check) => check.status === "pass");
	return {
		schemaVersion: 1,
		hermesCheckoutClean,
		evidence_path: evidencePath,
		checkoutPath,
		expectedRef,
		expectedVersion,
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
}

export function writeNoForkProofReport(report: NoForkProofReport): NoForkProofReport {
	const outputPath = resolveHermesArtifactPath(report.evidence_path);
	fs.mkdirSync(path.dirname(outputPath), { recursive: true });
	fs.writeFileSync(`${outputPath}.tmp`, `${JSON.stringify(report, null, 2)}\n`);
	fs.renameSync(`${outputPath}.tmp`, outputPath);
	return report;
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

function nonEmpty(value: string | undefined, fallback: string): string {
	const trimmed = value?.trim();
	return trimmed ? trimmed : fallback;
}

function cleanGitError(result: NoForkGitResult, fallback: string): string {
	return (result.stderr || result.stdout || fallback).replace(/\s+/g, " ").trim();
}
