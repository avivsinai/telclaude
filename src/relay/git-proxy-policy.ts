import type { GitProxyPermission, GitProxyTokenPolicy } from "./git-proxy-auth.js";

export const DEFAULT_GIT_PROXY_TOKEN_POLICY: GitProxyTokenPolicy = {
	repositories: ["*/*"],
	permissions: ["fetch", "push"],
	allowedRefs: ["refs/heads/*"],
	deniedRefs: ["refs/heads/main", "refs/heads/master"],
};

function parseCsvPolicy(value: string | undefined, fallback: string[]): string[] {
	const parsed = (value ?? "")
		.split(",")
		.map((item) => item.trim())
		.filter(Boolean);
	return parsed.length > 0 ? parsed : fallback;
}

function parseGitProxyPermissions(value: string | undefined): GitProxyPermission[] {
	if (value === undefined || value.trim() === "") return DEFAULT_GIT_PROXY_TOKEN_POLICY.permissions;

	const parsed = parseCsvPolicy(value, []);
	if (parsed.length === 0) {
		throw new Error("TELCLAUDE_GIT_PROXY_PERMISSIONS must include fetch or push.");
	}

	const invalid = parsed.filter((item) => item !== "fetch" && item !== "push");
	if (invalid.length > 0) {
		throw new Error(`Invalid TELCLAUDE_GIT_PROXY_PERMISSIONS values: ${invalid.join(", ")}`);
	}

	return parsed as GitProxyPermission[];
}

export function resolveGitProxyTokenPolicy(
	env: Pick<NodeJS.ProcessEnv, string> = process.env,
): GitProxyTokenPolicy {
	return {
		repositories: parseCsvPolicy(
			env.TELCLAUDE_GIT_PROXY_ALLOWED_REPOS,
			DEFAULT_GIT_PROXY_TOKEN_POLICY.repositories,
		),
		permissions: parseGitProxyPermissions(env.TELCLAUDE_GIT_PROXY_PERMISSIONS),
		allowedRefs: parseCsvPolicy(
			env.TELCLAUDE_GIT_PROXY_ALLOWED_PUSH_REFS,
			DEFAULT_GIT_PROXY_TOKEN_POLICY.allowedRefs,
		),
		deniedRefs: parseCsvPolicy(
			env.TELCLAUDE_GIT_PROXY_DENIED_PUSH_REFS,
			DEFAULT_GIT_PROXY_TOKEN_POLICY.deniedRefs,
		),
	};
}
