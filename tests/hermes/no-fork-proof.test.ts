import path from "node:path";
import { describe, expect, it } from "vitest";
import { buildNoForkProof, type NoForkGitRunner } from "../../src/hermes/no-fork-proof.js";

describe("Hermes no-fork proof", () => {
	it("passes only when the checkout is at the pinned ref with a clean tree and index", () => {
		const checkoutPath = path.resolve("/tmp/hermes-agent");
		const runner = fakeGitRunner(checkoutPath, {
			"rev-parse --show-toplevel": { exitCode: 0, stdout: `${checkoutPath}\n` },
			"rev-parse HEAD": { exitCode: 0, stdout: `${HEAD}\n` },
			"rev-parse --verify v2026.5.29^{commit}": { exitCode: 0, stdout: `${HEAD}\n` },
			"status --porcelain=v1": { exitCode: 0, stdout: "" },
			"diff --quiet": { exitCode: 0, stdout: "" },
			"diff --cached --quiet": { exitCode: 0, stdout: "" },
			"branch --show-current": { exitCode: 0, stdout: "" },
			"tag --points-at HEAD": { exitCode: 0, stdout: "v2026.5.29\n" },
		});

		const report = buildNoForkProof({ checkoutPath, runner });

		expect(report).toMatchObject({
			schemaVersion: 1,
			hermesCheckoutClean: true,
			checkoutPath,
			expectedRef: "v2026.5.29",
			expectedVersion: "0.15.1",
			head: HEAD,
			expectedRefCommit: HEAD,
			exactTags: ["v2026.5.29"],
			statusPorcelain: "",
			diffExitCode: 0,
			cachedDiffExitCode: 0,
		});
		expect(report.checks.every((check) => check.status === "pass")).toBe(true);
	});

	it("fails closed when HEAD is clean but not the pinned upstream ref", () => {
		const checkoutPath = path.resolve("/tmp/hermes-agent");
		const pinned = "b".repeat(40);
		const runner = fakeGitRunner(checkoutPath, {
			"rev-parse --show-toplevel": { exitCode: 0, stdout: `${checkoutPath}\n` },
			"rev-parse HEAD": { exitCode: 0, stdout: `${HEAD}\n` },
			"rev-parse --verify v2026.5.29^{commit}": { exitCode: 0, stdout: `${pinned}\n` },
			"status --porcelain=v1": { exitCode: 0, stdout: "" },
			"diff --quiet": { exitCode: 0, stdout: "" },
			"diff --cached --quiet": { exitCode: 0, stdout: "" },
			"branch --show-current": { exitCode: 0, stdout: "main\n" },
			"tag --points-at HEAD": { exitCode: 0, stdout: "" },
		});

		const report = buildNoForkProof({ checkoutPath, runner });

		expect(report.hermesCheckoutClean).toBe(false);
		expect(report.checks.find((check) => check.name === "checkout.pinned")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("does not match"),
		});
	});

	it("fails closed when the pinned upstream ref cannot be resolved", () => {
		const checkoutPath = path.resolve("/tmp/hermes-agent");
		const runner = fakeGitRunner(checkoutPath, {
			"rev-parse --show-toplevel": { exitCode: 0, stdout: `${checkoutPath}\n` },
			"rev-parse HEAD": { exitCode: 0, stdout: `${HEAD}\n` },
			"rev-parse --verify v2026.5.29^{commit}": {
				exitCode: 128,
				stderr: "fatal: Needed a single revision\n",
			},
			"status --porcelain=v1": { exitCode: 0, stdout: "" },
			"diff --quiet": { exitCode: 0, stdout: "" },
			"diff --cached --quiet": { exitCode: 0, stdout: "" },
			"branch --show-current": { exitCode: 0, stdout: "main\n" },
			"tag --points-at HEAD": { exitCode: 0, stdout: "" },
		});

		const report = buildNoForkProof({ checkoutPath, runner });

		expect(report.hermesCheckoutClean).toBe(false);
		expect(report.expectedRefCommit).toBeUndefined();
		expect(report.checks.find((check) => check.name === "checkout.expectedRef")).toMatchObject({
			status: "fail",
			detail: "fatal: Needed a single revision",
		});
	});

	it("fails closed when either the worktree or index is dirty", () => {
		const checkoutPath = path.resolve("/tmp/hermes-agent");
		const runner = fakeGitRunner(checkoutPath, {
			"rev-parse --show-toplevel": { exitCode: 0, stdout: `${checkoutPath}\n` },
			"rev-parse HEAD": { exitCode: 0, stdout: `${HEAD}\n` },
			"rev-parse --verify v2026.5.29^{commit}": { exitCode: 0, stdout: `${HEAD}\n` },
			"status --porcelain=v1": { exitCode: 0, stdout: " M hermes_cli/main.py\n" },
			"diff --quiet": { exitCode: 1, stdout: "" },
			"diff --cached --quiet": { exitCode: 1, stdout: "" },
			"branch --show-current": { exitCode: 0, stdout: "" },
			"tag --points-at HEAD": { exitCode: 0, stdout: "v2026.5.29\n" },
		});

		const report = buildNoForkProof({ checkoutPath, runner });

		expect(report.hermesCheckoutClean).toBe(false);
		expect(report.statusPorcelain).toBe("M hermes_cli/main.py");
		expect(report.checks.find((check) => check.name === "checkout.statusClean")).toMatchObject({
			status: "fail",
		});
		expect(report.checks.find((check) => check.name === "checkout.diffClean")).toMatchObject({
			status: "fail",
		});
		expect(report.checks.find((check) => check.name === "checkout.indexClean")).toMatchObject({
			status: "fail",
		});
	});
});

const HEAD = "a".repeat(40);

function fakeGitRunner(
	expectedCwd: string,
	responses: Record<string, { exitCode: number; stdout?: string; stderr?: string }>,
): NoForkGitRunner {
	return (args, cwd) => {
		expect(cwd).toBe(expectedCwd);
		const response = responses[[...args].join(" ")] ?? {
			exitCode: 1,
			stderr: `unexpected git args: ${[...args].join(" ")}`,
		};
		return {
			exitCode: response.exitCode,
			stdout: response.stdout ?? "",
			stderr: response.stderr ?? "",
		};
	};
}
