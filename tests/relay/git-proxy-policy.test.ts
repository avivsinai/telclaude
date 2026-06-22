import { describe, expect, it } from "vitest";

import {
	DEFAULT_GIT_PROXY_TOKEN_POLICY,
	resolveGitProxyTokenPolicy,
} from "../../src/relay/git-proxy-policy.js";

describe("git proxy policy", () => {
	it("uses the default policy when env overrides are absent", () => {
		expect(resolveGitProxyTokenPolicy({})).toEqual(DEFAULT_GIT_PROXY_TOKEN_POLICY);
	});

	it("parses relay-owned repository, permission, and ref policy from env", () => {
		expect(
			resolveGitProxyTokenPolicy({
				TELCLAUDE_GIT_PROXY_ALLOWED_REPOS: "owner/repo,owner2/*",
				TELCLAUDE_GIT_PROXY_PERMISSIONS: "fetch",
				TELCLAUDE_GIT_PROXY_ALLOWED_PUSH_REFS: "refs/heads/codex/*",
				TELCLAUDE_GIT_PROXY_DENIED_PUSH_REFS: "refs/heads/main,refs/tags/*",
			}),
		).toEqual({
			repositories: ["owner/repo", "owner2/*"],
			permissions: ["fetch"],
			allowedRefs: ["refs/heads/codex/*"],
			deniedRefs: ["refs/heads/main", "refs/tags/*"],
		});
	});

	it("fails closed on invalid permission config instead of broadening to defaults", () => {
		expect(() =>
			resolveGitProxyTokenPolicy({
				TELCLAUDE_GIT_PROXY_PERMISSIONS: "read",
			}),
		).toThrow("Invalid TELCLAUDE_GIT_PROXY_PERMISSIONS values: read");
	});
});
