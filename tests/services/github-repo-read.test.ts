import { beforeEach, describe, expect, it, vi } from "vitest";

const getInstallationTokenMock = vi.hoisted(() => vi.fn());
const listReposMock = vi.hoisted(() => vi.fn());
const listBranchesMock = vi.hoisted(() => vi.fn());
const listTagsMock = vi.hoisted(() => vi.fn());
const getContentMock = vi.hoisted(() => vi.fn());
const octokitCtorMock = vi.hoisted(() => vi.fn());

vi.mock("@octokit/rest", () => ({
	Octokit: octokitCtorMock,
}));

vi.mock("../../src/services/github-app.js", () => ({
	getInstallationToken: getInstallationTokenMock,
}));

vi.mock("../../src/logging.js", () => ({
	getChildLogger: () => ({ debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() }),
}));

import {
	GithubRepoReadError,
	githubGetTree,
	githubListRefs,
	githubListRepos,
	githubReadFile,
} from "../../src/services/github-repo-read.js";

function fileContent(text: string) {
	const buf = Buffer.from(text, "utf-8");
	return {
		type: "file" as const,
		encoding: "base64" as const,
		content: buf.toString("base64"),
		size: buf.byteLength,
		sha: "filesha",
		name: "x",
		path: "x",
	};
}

async function expectCode(p: Promise<unknown>, code: string) {
	await expect(p).rejects.toMatchObject({ code });
}

describe("github-repo-read", () => {
	beforeEach(() => {
		getInstallationTokenMock.mockReset().mockResolvedValue("installation-token");
		listReposMock.mockReset();
		listBranchesMock.mockReset();
		listTagsMock.mockReset();
		getContentMock.mockReset();
		octokitCtorMock.mockReset().mockImplementation(() => ({
			rest: {
				apps: { listReposAccessibleToInstallation: listReposMock },
				repos: {
					listBranches: listBranchesMock,
					listTags: listTagsMock,
					getContent: getContentMock,
				},
			},
		}));
	});

	describe("input validation (fails before any GitHub call)", () => {
		it("rejects a malformed repository", async () => {
			await expectCode(githubListRefs({ repository: "noslash" }), "invalid_repository");
			await expectCode(githubListRefs({ repository: "a/b/c" }), "invalid_repository");
			await expectCode(githubListRefs({ repository: "../etc/passwd" }), "invalid_repository");
			// owner login rules: no trailing or consecutive hyphens
			await expectCode(githubListRefs({ repository: "owner-/repo" }), "invalid_repository");
			await expectCode(githubListRefs({ repository: "ow--ner/repo" }), "invalid_repository");
			expect(getContentMock).not.toHaveBeenCalled();
			expect(listBranchesMock).not.toHaveBeenCalled();
		});

		it("rejects a path-traversal or absolute path", async () => {
			await expectCode(githubReadFile({ repository: "o/r", path: "../secrets" }), "invalid_path");
			await expectCode(githubReadFile({ repository: "o/r", path: "/etc/passwd" }), "invalid_path");
			await expectCode(githubReadFile({ repository: "o/r", path: "a//b" }), "invalid_path");
			expect(getContentMock).not.toHaveBeenCalled();
		});

		it("requires a concrete file path for read_file", async () => {
			await expectCode(githubReadFile({ repository: "o/r", path: "" }), "invalid_path");
		});

		it("rejects an unsafe ref", async () => {
			await expectCode(githubGetTree({ repository: "o/r", ref: "main..evil" }), "invalid_ref");
			await expectCode(githubGetTree({ repository: "o/r", ref: "a b" }), "invalid_ref");
			await expectCode(githubGetTree({ repository: "o/r", ref: "/leading" }), "invalid_ref");
			expect(getContentMock).not.toHaveBeenCalled();
		});
	});

	describe("token scope", () => {
		it("mints a repo-scoped, contents:read token for repo operations", async () => {
			listBranchesMock.mockResolvedValue({ data: [] });
			listTagsMock.mockResolvedValue({ data: [] });
			await githubListRefs({ repository: "avivsinai/telclaude" });
			expect(getInstallationTokenMock).toHaveBeenCalledWith({
				repository: "avivsinai/telclaude",
				contentsPermission: "read",
			});
		});

		it("fails closed when the GitHub App is not configured", async () => {
			getInstallationTokenMock.mockResolvedValue(null);
			await expectCode(githubListRepos(), "not_configured");
		});
	});

	describe("list_repos", () => {
		it("maps fields and flags truncation", async () => {
			listReposMock.mockResolvedValue({
				data: {
					total_count: 7,
					repositories: [
						{ full_name: "o/a", private: true, default_branch: "main" },
						{ full_name: "o/b", private: false, default_branch: "trunk" },
					],
				},
			});
			const result = await githubListRepos();
			expect(result.repositories).toEqual([
				{ fullName: "o/a", private: true, defaultBranch: "main" },
				{ fullName: "o/b", private: false, defaultBranch: "trunk" },
			]);
			expect(result.totalCount).toBe(7);
			expect(result.truncated).toBe(true);
		});
	});

	describe("get_tree", () => {
		it("maps directory entries", async () => {
			getContentMock.mockResolvedValue({
				data: [
					{ path: "src", type: "dir", sha: "d1" },
					{ path: "README.md", type: "file", size: 42, sha: "f1" },
				],
			});
			const result = await githubGetTree({ repository: "o/r", path: "" });
			expect(result.entries).toEqual([
				{ path: "src", type: "dir", sha: "d1" },
				{ path: "README.md", type: "file", size: 42, sha: "f1" },
			]);
		});

		it("throws not_a_directory when the path is a file", async () => {
			getContentMock.mockResolvedValue({ data: fileContent("hi") });
			await expectCode(githubGetTree({ repository: "o/r", path: "README.md" }), "not_a_directory");
		});
	});

	describe("read_file", () => {
		it("returns decoded UTF-8 content for a text file", async () => {
			getContentMock.mockResolvedValue({ data: fileContent("hello world") });
			const result = await githubReadFile({ repository: "o/r", path: "a.txt" });
			expect(result.content).toBe("hello world");
			expect(result.binary).toBe(false);
			expect(result.contentOmitted).toBe(false);
		});

		it("returns empty content for a genuinely empty file (not 'too_large')", async () => {
			getContentMock.mockResolvedValue({
				data: {
					type: "file",
					encoding: "base64",
					content: "",
					size: 0,
					sha: "e",
					name: "x",
					path: "x",
				},
			});
			const result = await githubReadFile({ repository: "o/r", path: "empty.txt" });
			expect(result.content).toBe("");
			expect(result.contentOmitted).toBe(false);
			expect(result.omittedReason).toBeUndefined();
		});

		it("fails closed to metadata for a binary file", async () => {
			const buf = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0x01, 0x02]);
			getContentMock.mockResolvedValue({
				data: {
					type: "file",
					encoding: "base64",
					content: buf.toString("base64"),
					size: buf.byteLength,
					sha: "bin",
					name: "x",
					path: "x",
				},
			});
			const result = await githubReadFile({ repository: "o/r", path: "logo.png" });
			expect(result.binary).toBe(true);
			expect(result.contentOmitted).toBe(true);
			expect(result.omittedReason).toBe("binary");
			expect(result.content).toBeUndefined();
		});

		it("fails closed to metadata for an oversized file", async () => {
			getContentMock.mockResolvedValue({
				data: {
					type: "file",
					encoding: "base64",
					content: "",
					size: 5 * 1024 * 1024,
					sha: "big",
					name: "x",
					path: "x",
				},
			});
			const result = await githubReadFile({ repository: "o/r", path: "big.bin" });
			expect(result.contentOmitted).toBe(true);
			expect(result.omittedReason).toBe("too_large");
			expect(result.content).toBeUndefined();
		});

		it("throws not_a_file when the path is a directory", async () => {
			getContentMock.mockResolvedValue({ data: [{ path: "src", type: "dir", sha: "d" }] });
			await expectCode(githubReadFile({ repository: "o/r", path: "src" }), "not_a_file");
		});

		it("fails closed to metadata when encoding is not base64", async () => {
			getContentMock.mockResolvedValue({
				data: {
					type: "file",
					encoding: "none",
					content: "",
					size: 2000,
					sha: "n",
					name: "x",
					path: "x",
				},
			});
			const result = await githubReadFile({ repository: "o/r", path: "weird" });
			expect(result.contentOmitted).toBe(true);
			expect(result.content).toBeUndefined();
		});
	});

	describe("upstream error mapping", () => {
		it("maps 404 to not_found and 403 to forbidden", async () => {
			getContentMock.mockRejectedValueOnce({ status: 404 });
			await expectCode(githubReadFile({ repository: "o/r", path: "a.txt" }), "not_found");
			getContentMock.mockRejectedValueOnce({ status: 403 });
			await expectCode(githubReadFile({ repository: "o/r", path: "a.txt" }), "forbidden");
		});

		it("redacts unexpected upstream errors", async () => {
			getContentMock.mockRejectedValueOnce({ status: 500, message: "secret leak details" });
			await expect(githubReadFile({ repository: "o/r", path: "a.txt" })).rejects.toMatchObject({
				code: "upstream_error",
				message: "github request failed",
			});
		});
	});

	it("exports a typed error class", () => {
		expect(new GithubRepoReadError("not_found", "x")).toBeInstanceOf(Error);
	});
});
