import { beforeEach, describe, expect, it, vi } from "vitest";

const getOctokitMock = vi.hoisted(() => vi.fn());
const getCommitMock = vi.hoisted(() => vi.fn());
const compareCommitsMock = vi.hoisted(() => vi.fn());
const createWorkflowDispatchMock = vi.hoisted(() => vi.fn());
const listWorkflowRunsMock = vi.hoisted(() => vi.fn());
const buildRuntimeSnapshotMock = vi.hoisted(() =>
	vi.fn(() => ({
		version: "1.2.3",
		revision: "abc1234",
		startedAt: "2026-07-02T00:00:00.000Z",
		uptimeMs: 1_000,
		uptimeSeconds: 1,
	})),
);

vi.mock("../../src/services/github-app.js", () => ({
	getOctokit: getOctokitMock,
}));

vi.mock("../../src/system-metadata.js", () => ({
	buildRuntimeSnapshot: (...args: unknown[]) => buildRuntimeSnapshotMock(...args),
}));

vi.mock("../../src/logging.js", () => ({
	getChildLogger: () => ({ debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() }),
}));

import { collectUpdateStatus, dispatchMainDeploy } from "../../src/services/update-deploy.js";

function installOctokit(): void {
	getOctokitMock.mockResolvedValue({
		rest: {
			repos: {
				getCommit: getCommitMock,
				compareCommitsWithBasehead: compareCommitsMock,
			},
			actions: {
				createWorkflowDispatch: createWorkflowDispatchMock,
				listWorkflowRuns: listWorkflowRunsMock,
			},
		},
	});
}

describe("update deploy service", () => {
	beforeEach(() => {
		getOctokitMock.mockReset();
		getCommitMock.mockReset();
		compareCommitsMock.mockReset();
		createWorkflowDispatchMock.mockReset();
		listWorkflowRunsMock.mockReset();
		buildRuntimeSnapshotMock.mockClear();
		installOctokit();
	});

	it("reports missing GitHub App configuration", async () => {
		getOctokitMock.mockResolvedValue(null);

		const result = await collectUpdateStatus();

		expect(result).toMatchObject({
			ok: false,
			code: "not_configured",
			message: "GitHub App is not configured. Run telclaude secrets setup-github-app.",
		});
		expect(getOctokitMock).toHaveBeenCalledWith({
			repository: "avivsinai/telclaude",
			permissions: { contents: "read" },
		});
		expect(getCommitMock).not.toHaveBeenCalled();
	});

	it("compares the running revision to GitHub main", async () => {
		getCommitMock.mockResolvedValue({
			data: { sha: "def5678def5678def5678def5678def5678def5678" },
		});
		compareCommitsMock.mockResolvedValue({ data: { ahead_by: 3 } });

		const result = await collectUpdateStatus();

		expect(getOctokitMock).toHaveBeenCalledWith({
			repository: "avivsinai/telclaude",
			permissions: { contents: "read" },
		});
		expect(getCommitMock).toHaveBeenCalledWith({
			owner: "avivsinai",
			repo: "telclaude",
			ref: "main",
		});
		expect(compareCommitsMock).toHaveBeenCalledWith({
			owner: "avivsinai",
			repo: "telclaude",
			basehead: "abc1234...main",
		});
		expect(result).toMatchObject({
			ok: true,
			mainShortSha: "def5678",
			relation: "behind",
			aheadBy: 3,
		});
	});

	it("dispatches the verify-gated CI workflow on main", async () => {
		createWorkflowDispatchMock.mockResolvedValue({ data: {} });
		listWorkflowRunsMock.mockResolvedValue({
			data: {
				workflow_runs: [
					{
						html_url: "https://github.com/avivsinai/telclaude/actions/runs/123",
						created_at: new Date().toISOString(),
					},
				],
			},
		});

		const result = await dispatchMainDeploy();

		expect(getOctokitMock).toHaveBeenCalledWith({
			repository: "avivsinai/telclaude",
			permissions: { actions: "write" },
		});
		expect(createWorkflowDispatchMock).toHaveBeenCalledWith({
			owner: "avivsinai",
			repo: "telclaude",
			workflow_id: "ci.yml",
			ref: "main",
		});
		expect(listWorkflowRunsMock).toHaveBeenCalledWith({
			owner: "avivsinai",
			repo: "telclaude",
			workflow_id: "ci.yml",
			branch: "main",
			event: "workflow_dispatch",
			per_page: 1,
		});
		expect(result).toEqual({
			ok: true,
			workflowUrl: "https://github.com/avivsinai/telclaude/actions/workflows/ci.yml",
			runUrl: "https://github.com/avivsinai/telclaude/actions/runs/123",
		});
	});

	it("falls back to the workflow page when the listed dispatch run is stale", async () => {
		createWorkflowDispatchMock.mockResolvedValue({ data: {} });
		listWorkflowRunsMock.mockResolvedValue({
			data: {
				workflow_runs: [
					{
						html_url: "https://github.com/avivsinai/telclaude/actions/runs/previous",
						created_at: "2026-01-01T00:00:00.000Z",
					},
				],
			},
		});

		const result = await dispatchMainDeploy();

		expect(result).toEqual({
			ok: true,
			workflowUrl: "https://github.com/avivsinai/telclaude/actions/workflows/ci.yml",
			runUrl: undefined,
		});
	});

	it("explains the Actions write permission fallback on dispatch 403", async () => {
		createWorkflowDispatchMock.mockRejectedValue({ status: 403 });

		const result = await dispatchMainDeploy();

		expect(result).toMatchObject({
			ok: false,
			code: "forbidden",
		});
		if (result.ok) throw new Error("expected dispatch failure");
		expect(result.message).toContain("Actions: write");
		expect(result.message).toContain("gh workflow run ci.yml --ref main");
	});
});
