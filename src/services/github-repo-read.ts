/**
 * GitHub repository read service.
 *
 * Relay-native, read-only repository access backed by the GitHub App installation
 * token (see `github-app.ts`). This is NOT an external provider sidecar and NOT the
 * git proxy — it is a small typed surface (list repos, list refs, list a tree,
 * read a file) that the relay serves to the contained Hermes runtime through the
 * `tc_github_*` MCP tools behind the `github.read` capability scope.
 *
 * Hard rules (enforced here, at the boundary):
 * - Every call uses a repo-scoped installation token with `contents: read` only.
 * - owner/repo, ref, and path are validated before any GitHub call. No shell git,
 *   no URL concatenation — only typed Octokit methods.
 * - Results are capped (entry counts + byte sizes). Binary or oversized files fail
 *   closed to metadata (size/sha) rather than streaming bytes inline.
 * - Raw tokens are never returned or logged; only structured data crosses back.
 *
 * Untrusted-wrapping of the returned names/paths/content happens at the relay MCP
 * client layer (`live-relay-clients.ts`), which treats this data as external
 * untrusted content (repo names, branch names, commit-adjacent metadata, and file
 * bodies are all prompt-injection carriers).
 */

import { Octokit } from "@octokit/rest";

import { getChildLogger } from "../logging.js";
import { getInstallationToken } from "./github-app.js";

const logger = getChildLogger({ module: "github-repo-read" });

// ═══════════════════════════════════════════════════════════════════════════════
// Caps
// ═══════════════════════════════════════════════════════════════════════════════

/** Max repositories returned by list_repos (single page). */
const MAX_REPOS = 100;
/** Max branches and max tags each returned by list_refs. */
const MAX_REFS_PER_KIND = 200;
/** Max entries returned by get_tree for a directory listing. */
const MAX_TREE_ENTRIES = 500;
/** Max file bytes read inline; larger files fail closed to metadata. */
const MAX_FILE_BYTES = 128 * 1024;

// ═══════════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════════

export interface GithubRepoSummary {
	readonly fullName: string;
	readonly private: boolean;
	readonly defaultBranch: string;
}

export interface GithubListReposResult {
	readonly repositories: readonly GithubRepoSummary[];
	readonly totalCount: number;
	readonly truncated: boolean;
}

export interface GithubRef {
	readonly name: string;
	readonly sha: string;
}

export interface GithubListRefsResult {
	readonly repo: string;
	readonly branches: readonly GithubRef[];
	readonly tags: readonly GithubRef[];
	readonly truncated: boolean;
}

export type GithubTreeEntryType = "file" | "dir" | "submodule" | "symlink" | "other";

export interface GithubTreeEntry {
	readonly path: string;
	readonly type: GithubTreeEntryType;
	readonly size?: number;
	readonly sha: string;
}

export interface GithubGetTreeResult {
	readonly repo: string;
	readonly ref: string;
	readonly path: string;
	readonly entries: readonly GithubTreeEntry[];
	readonly truncated: boolean;
}

export interface GithubReadFileResult {
	readonly repo: string;
	readonly ref: string;
	readonly path: string;
	readonly size: number;
	readonly sha: string;
	readonly binary: boolean;
	/** Decoded UTF-8 text. Absent when the file is binary or exceeds the byte cap. */
	readonly content?: string;
	/** True when content was omitted because the file is binary or too large. */
	readonly contentOmitted: boolean;
	readonly omittedReason?: "binary" | "too_large";
}

// ═══════════════════════════════════════════════════════════════════════════════
// Errors
// ═══════════════════════════════════════════════════════════════════════════════

export type GithubRepoReadErrorCode =
	| "not_configured"
	| "invalid_repository"
	| "invalid_ref"
	| "invalid_path"
	| "not_found"
	| "forbidden"
	| "not_a_file"
	| "not_a_directory"
	| "upstream_error";

export class GithubRepoReadError extends Error {
	readonly code: GithubRepoReadErrorCode;

	constructor(code: GithubRepoReadErrorCode, message: string) {
		super(message);
		this.code = code;
		this.name = "GithubRepoReadError";
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Validation
// ═══════════════════════════════════════════════════════════════════════════════

// GitHub owner/org login: 1–39 chars, alphanumeric segments joined by single
// hyphens — may not start or end with a hyphen, nor contain consecutive hyphens.
const SAFE_OWNER = /^[A-Za-z0-9](?:-?[A-Za-z0-9]){0,38}$/;
const SAFE_REPO = /^[A-Za-z0-9_.-]{1,100}$/;

interface ParsedRepo {
	readonly owner: string;
	readonly repo: string;
	readonly fullName: string;
}

function parseRepository(repository: string): ParsedRepo {
	const parts = repository.split("/");
	if (parts.length !== 2) {
		throw new GithubRepoReadError("invalid_repository", "repository must be 'owner/repo'");
	}
	const [owner, repo] = parts;
	if (!owner || !repo || !SAFE_OWNER.test(owner) || !SAFE_REPO.test(repo)) {
		throw new GithubRepoReadError("invalid_repository", "repository owner/name is not valid");
	}
	if (repo === "." || repo === "..") {
		throw new GithubRepoReadError("invalid_repository", "repository name is not valid");
	}
	return { owner, repo, fullName: `${owner}/${repo}` };
}

/** True if the string contains an ASCII control character (C0 range or DEL). */
function hasControlChars(value: string): boolean {
	for (let i = 0; i < value.length; i++) {
		const code = value.charCodeAt(i);
		if (code < 0x20 || code === 0x7f) return true;
	}
	return false;
}

/** Validate an optional git ref (branch, tag, or commit-ish). */
function validateRef(ref: string | undefined): string | undefined {
	if (ref === undefined) return undefined;
	const trimmed = ref.trim();
	if (trimmed.length === 0) {
		throw new GithubRepoReadError("invalid_ref", "ref must not be empty");
	}
	if (trimmed.length > 256) {
		throw new GithubRepoReadError("invalid_ref", "ref is too long");
	}
	if (
		hasControlChars(trimmed) ||
		/\s/.test(trimmed) ||
		trimmed.includes("..") ||
		trimmed.includes("@{") ||
		trimmed.includes("\\") ||
		trimmed.startsWith("/") ||
		trimmed.endsWith("/") ||
		trimmed.endsWith(".lock") ||
		!/^[A-Za-z0-9._/-]+$/.test(trimmed)
	) {
		throw new GithubRepoReadError("invalid_ref", "ref contains invalid characters");
	}
	return trimmed;
}

/**
 * Validate a repository-relative path. `allowEmpty` permits the repository root
 * (used by get_tree); read_file always requires a concrete file path.
 */
function validatePath(rawPath: string | undefined, allowEmpty: boolean): string {
	const value = (rawPath ?? "").trim();
	if (value === "" || value === "/") {
		if (allowEmpty) return "";
		throw new GithubRepoReadError("invalid_path", "path must reference a file");
	}
	if (value.length > 1024) {
		throw new GithubRepoReadError("invalid_path", "path is too long");
	}
	if (
		hasControlChars(value) ||
		value.startsWith("/") ||
		value.includes("\\") ||
		value.includes("//")
	) {
		throw new GithubRepoReadError("invalid_path", "path contains invalid characters");
	}
	for (const segment of value.split("/")) {
		if (segment === "" || segment === "." || segment === "..") {
			throw new GithubRepoReadError("invalid_path", "path contains invalid segments");
		}
	}
	return value;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Octokit
// ═══════════════════════════════════════════════════════════════════════════════

/** Mint a fresh read-only Octokit. Repo-scoped when `repository` is given. */
async function readOctokit(repository?: string): Promise<Octokit> {
	const token = await getInstallationToken({
		...(repository ? { repository } : {}),
		contentsPermission: "read",
	});
	if (!token) {
		throw new GithubRepoReadError(
			"not_configured",
			"GitHub App is not configured — run telclaude secrets setup-github-app",
		);
	}
	return new Octokit({ auth: token });
}

function mapUpstreamError(err: unknown, repo: string): GithubRepoReadError {
	const status = (err as { status?: number })?.status;
	if (status === 404) {
		return new GithubRepoReadError("not_found", `not found in ${repo}`);
	}
	if (status === 403 || status === 401) {
		return new GithubRepoReadError(
			"forbidden",
			`access denied for ${repo} (is the app installed on it?)`,
		);
	}
	logger.warn({ status, repo }, "github repo read upstream error");
	return new GithubRepoReadError("upstream_error", "github request failed");
}

function isBinary(buffer: Buffer): boolean {
	const sample = buffer.subarray(0, Math.min(buffer.length, 8192));
	if (sample.includes(0)) return true;
	try {
		new TextDecoder("utf-8", { fatal: true }).decode(buffer);
		return false;
	} catch {
		return true;
	}
}

function mapTreeEntryType(type: string | undefined): GithubTreeEntryType {
	switch (type) {
		case "file":
			return "file";
		case "dir":
			return "dir";
		case "submodule":
			return "submodule";
		case "symlink":
			return "symlink";
		default:
			return "other";
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Operations
// ═══════════════════════════════════════════════════════════════════════════════

/** List the repositories the GitHub App installation can access. */
export async function githubListRepos(): Promise<GithubListReposResult> {
	const octokit = await readOctokit();
	let data: Awaited<ReturnType<typeof octokit.rest.apps.listReposAccessibleToInstallation>>["data"];
	try {
		({ data } = await octokit.rest.apps.listReposAccessibleToInstallation({
			per_page: MAX_REPOS,
		}));
	} catch (err) {
		throw mapUpstreamError(err, "installation");
	}
	const repositories: GithubRepoSummary[] = data.repositories.slice(0, MAX_REPOS).map((repo) => ({
		fullName: repo.full_name,
		private: repo.private,
		defaultBranch: repo.default_branch,
	}));
	return {
		repositories,
		totalCount: data.total_count,
		truncated: data.total_count > repositories.length,
	};
}

/** List branches and tags for a repository. */
export async function githubListRefs(input: { repository: string }): Promise<GithubListRefsResult> {
	const { owner, repo, fullName } = parseRepository(input.repository);
	const octokit = await readOctokit(fullName);

	let branches: GithubRef[];
	let tags: GithubRef[];
	try {
		const [branchResp, tagResp] = await Promise.all([
			octokit.rest.repos.listBranches({ owner, repo, per_page: MAX_REFS_PER_KIND }),
			octokit.rest.repos.listTags({ owner, repo, per_page: MAX_REFS_PER_KIND }),
		]);
		branches = branchResp.data
			.slice(0, MAX_REFS_PER_KIND)
			.map((b) => ({ name: b.name, sha: b.commit.sha }));
		tags = tagResp.data
			.slice(0, MAX_REFS_PER_KIND)
			.map((t) => ({ name: t.name, sha: t.commit.sha }));
	} catch (err) {
		throw mapUpstreamError(err, fullName);
	}

	return {
		repo: fullName,
		branches,
		tags,
		truncated: branches.length >= MAX_REFS_PER_KIND || tags.length >= MAX_REFS_PER_KIND,
	};
}

/** List the entries of a directory in a repository at an optional ref. */
export async function githubGetTree(input: {
	repository: string;
	ref?: string;
	path?: string;
}): Promise<GithubGetTreeResult> {
	const { owner, repo, fullName } = parseRepository(input.repository);
	const ref = validateRef(input.ref);
	const dirPath = validatePath(input.path, true);
	const octokit = await readOctokit(fullName);

	let payload: Awaited<ReturnType<typeof octokit.rest.repos.getContent>>["data"];
	try {
		({ data: payload } = await octokit.rest.repos.getContent({
			owner,
			repo,
			path: dirPath,
			...(ref ? { ref } : {}),
		}));
	} catch (err) {
		throw mapUpstreamError(err, fullName);
	}

	if (!Array.isArray(payload)) {
		throw new GithubRepoReadError("not_a_directory", `${dirPath || "/"} is not a directory`);
	}

	const entries: GithubTreeEntry[] = payload.slice(0, MAX_TREE_ENTRIES).map((entry) => ({
		path: entry.path,
		type: mapTreeEntryType(entry.type),
		...(typeof entry.size === "number" && entry.type === "file" ? { size: entry.size } : {}),
		sha: entry.sha,
	}));

	return {
		repo: fullName,
		ref: ref ?? "",
		path: dirPath,
		entries,
		truncated: payload.length > entries.length,
	};
}

/** Read a single file from a repository at an optional ref. */
export async function githubReadFile(input: {
	repository: string;
	path: string;
	ref?: string;
}): Promise<GithubReadFileResult> {
	const { owner, repo, fullName } = parseRepository(input.repository);
	const ref = validateRef(input.ref);
	const filePath = validatePath(input.path, false);
	const octokit = await readOctokit(fullName);

	let payload: Awaited<ReturnType<typeof octokit.rest.repos.getContent>>["data"];
	try {
		({ data: payload } = await octokit.rest.repos.getContent({
			owner,
			repo,
			path: filePath,
			...(ref ? { ref } : {}),
		}));
	} catch (err) {
		throw mapUpstreamError(err, fullName);
	}

	if (Array.isArray(payload) || payload.type !== "file") {
		throw new GithubRepoReadError("not_a_file", `${filePath} is not a file`);
	}

	const size = payload.size;
	const sha = payload.sha;
	const base = {
		repo: fullName,
		ref: ref ?? "",
		path: filePath,
		size,
		sha,
	} as const;

	// GitHub declines to inline content for files larger than ~1MB (encoding "none",
	// content ""); our own cap fails closed well before that. Anything that is not
	// base64-encoded inline content is treated as metadata-only, fail-closed.
	if (
		size > MAX_FILE_BYTES ||
		payload.encoding !== "base64" ||
		typeof payload.content !== "string"
	) {
		return { ...base, binary: false, contentOmitted: true, omittedReason: "too_large" };
	}
	// A genuinely empty file (size 0, content "") is NOT too large — it decodes to ""
	// below. GitHub returns "" only for a 0-byte file once encoding is base64.
	if (payload.content === "" && size > 0) {
		return { ...base, binary: false, contentOmitted: true, omittedReason: "too_large" };
	}

	const buffer = Buffer.from(payload.content, "base64");
	if (buffer.byteLength > MAX_FILE_BYTES) {
		return { ...base, binary: false, contentOmitted: true, omittedReason: "too_large" };
	}
	if (isBinary(buffer)) {
		return { ...base, binary: true, contentOmitted: true, omittedReason: "binary" };
	}

	return {
		...base,
		binary: false,
		content: buffer.toString("utf-8"),
		contentOmitted: false,
	};
}
