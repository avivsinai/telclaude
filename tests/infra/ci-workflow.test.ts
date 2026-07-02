import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const repoRoot = path.resolve(import.meta.dirname, "../..");

function readWorkflow(): string {
	return fs.readFileSync(path.join(repoRoot, ".github/workflows/ci.yml"), "utf8");
}

describe("CI workflow", () => {
	it("allows manual deploy dispatch while keeping deploy verify-gated on main", () => {
		const workflow = readWorkflow();
		const deployStart = workflow.indexOf("  deploy:");
		const deployJob = workflow.slice(deployStart);

		expect(workflow).toContain("  workflow_dispatch:");
		expect(deployJob).toContain("needs: [verify]");
		expect(deployJob).toContain("github.event_name == 'workflow_dispatch'");
		expect(deployJob).toContain("github.ref == 'refs/heads/main'");
		expect(deployJob).toContain("cancel-in-progress: false");
	});
});
