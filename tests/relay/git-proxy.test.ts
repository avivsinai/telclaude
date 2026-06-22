import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
	mintGitProxyToken,
	generateSessionToken,
	verifyGitProxyToken,
	validateSessionToken,
	generateSessionId,
	decodeToken,
} from "../../src/relay/git-proxy-auth.js";
import { redactSecrets } from "../../src/security/output-filter.js";

// Mock environment
beforeEach(() => {
	// Set a stable secret for testing
	process.env.TELCLAUDE_GIT_PROXY_SECRET = "test-secret-for-git-proxy-unit-tests";
});

afterEach(() => {
	vi.restoreAllMocks();
	delete process.env.TELCLAUDE_GIT_PROXY_SECRET;
});

describe("git-proxy-auth", () => {
	describe("generateSessionId", () => {
		it("should generate unique 32-character hex strings", () => {
			const id1 = generateSessionId();
			const id2 = generateSessionId();

			expect(id1).toHaveLength(32);
			expect(id2).toHaveLength(32);
			expect(id1).not.toBe(id2);
			expect(id1).toMatch(/^[a-f0-9]+$/);
		});
	});

	describe("generateSessionToken", () => {
		it("should generate a valid base64-encoded token", () => {
			const sessionId = generateSessionId();
			const token = generateSessionToken(sessionId);

			expect(token).toBeTruthy();
			expect(typeof token).toBe("string");

			// Should be valid base64
			const decoded = Buffer.from(token, "base64").toString("utf-8");
			expect(() => JSON.parse(decoded)).not.toThrow();
		});

		it("should include sessionId, timestamps, and signature in token", () => {
			const sessionId = generateSessionId();
			const token = generateSessionToken(sessionId, 60000); // 1 minute TTL

			const decoded = decodeToken(token);
			expect(decoded).toBeTruthy();
			expect(decoded?.sessionId).toBe(sessionId);
			expect(decoded?.createdAt).toBeTruthy();
			expect(decoded?.expiresAt).toBeTruthy();
			expect(decoded?.signature).toBeTruthy();
			expect(decoded!.expiresAt).toBeGreaterThan(decoded!.createdAt);
		});

		it("should respect custom TTL", () => {
			const sessionId = generateSessionId();
			const ttlMs = 30 * 60 * 1000; // 30 minutes
			const token = generateSessionToken(sessionId, ttlMs);

			const decoded = decodeToken(token);
			expect(decoded).toBeTruthy();

			const actualTtl = decoded!.expiresAt - decoded!.createdAt;
			expect(actualTtl).toBe(ttlMs);
		});
	});

	describe("validateSessionToken", () => {
		it("should validate a freshly generated token", () => {
			const sessionId = generateSessionId();
			const token = generateSessionToken(sessionId, 60000);

			const result = validateSessionToken(token);
			expect(result).toBeTruthy();
			expect(result?.sessionId).toBe(sessionId);
		});

		it("should reject an expired token", () => {
			const sessionId = generateSessionId();
			// Generate token with 1ms TTL, then wait
			const token = generateSessionToken(sessionId, 1);

			// Wait a tiny bit to ensure expiration
			const start = Date.now();
			while (Date.now() - start < 5) {
				// Busy wait for 5ms
			}

			const result = validateSessionToken(token);
			expect(result).toBeNull();
		});

		it("should reject a token with tampered signature", () => {
			const sessionId = generateSessionId();
			const token = generateSessionToken(sessionId, 60000);

			// Decode, tamper, re-encode
			const decoded = JSON.parse(Buffer.from(token, "base64").toString("utf-8"));
			decoded.signature = "tampered-signature";
			const tampered = Buffer.from(JSON.stringify(decoded)).toString("base64");

			const result = validateSessionToken(tampered);
			expect(result).toBeNull();
		});

		it("should reject a token with tampered sessionId", () => {
			const sessionId = generateSessionId();
			const token = generateSessionToken(sessionId, 60000);

			// Decode, tamper sessionId, re-encode (keeping original signature)
			const decoded = JSON.parse(Buffer.from(token, "base64").toString("utf-8"));
			decoded.sessionId = "different-session-id";
			const tampered = Buffer.from(JSON.stringify(decoded)).toString("base64");

			const result = validateSessionToken(tampered);
			expect(result).toBeNull(); // Signature won't match
		});

		it("should reject malformed base64", () => {
			const result = validateSessionToken("not-valid-base64!!!");
			expect(result).toBeNull();
		});

		it("should reject empty string", () => {
			const result = validateSessionToken("");
			expect(result).toBeNull();
		});

		it("should reject token missing required fields", () => {
			const incomplete = Buffer.from(JSON.stringify({ sessionId: "test" })).toString("base64");
			const result = validateSessionToken(incomplete);
			expect(result).toBeNull();
		});
	});

	describe("decodeToken", () => {
		it("should decode a valid token without validation", () => {
			const sessionId = generateSessionId();
			const token = generateSessionToken(sessionId, 60000);

			const decoded = decodeToken(token);
			expect(decoded).toBeTruthy();
			expect(decoded?.sessionId).toBe(sessionId);
		});

		it("should return null for invalid base64", () => {
			const result = decodeToken("not-valid-base64!!!");
			expect(result).toBeNull();
		});

		it("should return null for non-JSON content", () => {
			const notJson = Buffer.from("not json content").toString("base64");
			const result = decodeToken(notJson);
			expect(result).toBeNull();
		});
	});

	describe("security properties", () => {
		it("should produce different tokens for same sessionId at different times", async () => {
			const sessionId = generateSessionId();

			const token1 = generateSessionToken(sessionId, 60000);

			// Wait a tiny bit
			await new Promise((resolve) => setTimeout(resolve, 5));

			const token2 = generateSessionToken(sessionId, 60000);

			// Tokens should be different (different createdAt, expiresAt, signature)
			expect(token1).not.toBe(token2);
		});

		it("should produce different tokens for different sessionIds", () => {
			const token1 = generateSessionToken(generateSessionId(), 60000);
			const token2 = generateSessionToken(generateSessionId(), 60000);

			expect(token1).not.toBe(token2);
		});

		it("should not leak the secret in the token", () => {
			const sessionId = generateSessionId();
			const token = generateSessionToken(sessionId, 60000);

			// Decode and check the secret is not present
			const decoded = Buffer.from(token, "base64").toString("utf-8");
			expect(decoded).not.toContain(process.env.TELCLAUDE_GIT_PROXY_SECRET);
		});
	});
});

describe("git proxy scoped tokens", () => {
	const secret = "git-proxy-token-secret-for-tests";

	it("mints a peer-bound token with repo, operation, and ref policy", () => {
		const token = mintGitProxyToken({
			secret,
			peerAddress: "172.30.92.11",
			sessionId: "session-1",
			repositories: ["avivsinai/telclaude"],
			permissions: ["fetch", "push"],
			allowedRefs: ["refs/heads/codex/*"],
			deniedRefs: ["refs/heads/main"],
			ttlMs: 60_000,
		});

		expect(token).toMatch(/^tc-git-proxy-v1\./);

		const verified = verifyGitProxyToken(token, {
			secret,
			peerAddress: "::ffff:172.30.92.11",
		});

		expect(verified.ok).toBe(true);
		if (verified.ok) {
			expect(verified.sessionId).toBe("session-1");
			expect(verified.repositories).toEqual(["avivsinai/telclaude"]);
			expect(verified.permissions).toEqual(["fetch", "push"]);
			expect(verified.allowedRefs).toEqual(["refs/heads/codex/*"]);
			expect(verified.deniedRefs).toEqual(["refs/heads/main"]);
		}
	});

	it("rejects replay from a different peer address", () => {
		const token = mintGitProxyToken({
			secret,
			peerAddress: "172.30.92.11",
			sessionId: "session-1",
			repositories: ["avivsinai/telclaude"],
			permissions: ["fetch"],
			allowedRefs: ["refs/heads/*"],
			deniedRefs: [],
			ttlMs: 60_000,
		});

		expect(
			verifyGitProxyToken(token, {
				secret,
				peerAddress: "172.30.92.12",
			}),
		).toEqual({ ok: false, reason: "peer address mismatch" });
	});

	it("redacts scoped git proxy tokens from output", () => {
		const token = "tc-git-proxy-v1.eyJzZXNzaW9uSWQiOiIxIn0.signature";
		const redacted = redactSecrets(`token=${token}`);

		expect(redacted).not.toContain(token);
		expect(redacted).toContain("[REDACTED:");
	});
});

describe("git-proxy URL parsing", () => {
	// Import parseGitUrl for testing
	let parseGitUrl: (
		url: string,
	) => { host: string; owner: string; repo: string; path: string; repository: string } | null;
	let parseReceivePackCommands: (buffer: Buffer) => {
		complete: boolean;
		commands: Array<{ oldId: string; newId: string; ref: string }>;
	};
	let parseLfsBatchOperation: (buffer: Buffer) => {
		type: "fetch" | "push";
		ref?: string;
	};
	let describeLfsActionTargetForLog: (href: string) => { lfsActionOrigin: string };
	let authorizeReceivePackCommands: (
		commands: Array<{ oldId: string; newId: string; ref: string }>,
		policy: {
			repositories: string[];
			permissions: Array<"fetch" | "push">;
			allowedRefs: string[];
			deniedRefs: string[];
		},
	) => { ok: true } | { ok: false; reason: string };
	let authorizePushRefs: (
		refs: string[],
		policy: {
			repositories: string[];
			permissions: Array<"fetch" | "push">;
			allowedRefs: string[];
			deniedRefs: string[];
		},
		emptyReason?: string,
	) => { ok: true } | { ok: false; reason: string };
	let getGitOperation: (
		method: string,
		path: string,
		url: string,
	) => { type: "fetch" | "push" | "unknown"; repo: string; service?: string };

	beforeAll(async () => {
		const module = await import("../../src/relay/git-proxy.js");
		parseGitUrl = module.parseGitUrl;
		parseReceivePackCommands = module.parseReceivePackCommands;
		parseLfsBatchOperation = module.parseLfsBatchOperation;
		describeLfsActionTargetForLog = module.describeLfsActionTargetForLog;
		authorizeReceivePackCommands = module.authorizeReceivePackCommands;
		authorizePushRefs = module.authorizePushRefs;
		getGitOperation = module.getGitOperation;
	});

	describe("parseGitUrl", () => {
		it("should parse standard git URLs with .git suffix", () => {
			const result = parseGitUrl("/github.com/owner/repo.git/info/refs");
			expect(result).toEqual({
				host: "github.com",
				owner: "owner",
				repo: "repo",
				path: "/info/refs",
				repository: "owner/repo",
			});
		});

		it("should parse git URLs without .git suffix", () => {
			const result = parseGitUrl("/github.com/owner/repo/info/refs");
			expect(result).toEqual({
				host: "github.com",
				owner: "owner",
				repo: "repo",
				path: "/info/refs",
				repository: "owner/repo",
			});
		});

		it("should preserve query strings", () => {
			const result = parseGitUrl("/github.com/owner/repo.git/info/refs?service=git-upload-pack");
			expect(result).toEqual({
				host: "github.com",
				owner: "owner",
				repo: "repo",
				path: "/info/refs?service=git-upload-pack",
				repository: "owner/repo",
			});
		});

		it("should preserve complete query strings containing question marks", () => {
			const result = parseGitUrl(
				"/github.com/owner/repo.git/info/refs?service=git-upload-pack&x=a?b",
			);
			expect(result?.path).toBe("/info/refs?service=git-upload-pack&x=a?b");
		});

		it("should parse git-upload-pack paths", () => {
			const result = parseGitUrl("/github.com/owner/repo.git/git-upload-pack");
			expect(result?.path).toBe("/git-upload-pack");
		});

		it("should parse git-receive-pack paths", () => {
			const result = parseGitUrl("/github.com/owner/repo.git/git-receive-pack");
			expect(result?.path).toBe("/git-receive-pack");
		});

		it("rejects dot-segment and encoded git routes before upstream URL normalization", () => {
			expect(parseGitUrl("/github.com/owner/repo.git/foo/../git-receive-pack")).toBeNull();
			expect(parseGitUrl("/github.com/owner/repo.git/%2e%2e/git-receive-pack")).toBeNull();
			expect(parseGitUrl("/github.com/owner/repo.git/foo//git-receive-pack")).toBeNull();
		});

		it("rejects literal dot owner and repository segments", () => {
			expect(parseGitUrl("/github.com/./repo.git/info/refs")).toBeNull();
			expect(parseGitUrl("/github.com/../repo.git/info/refs")).toBeNull();
			expect(parseGitUrl("/github.com/owner/..git/info/refs")).toBeNull();
			expect(parseGitUrl("/github.com/owner/..git/git-receive-pack")).toBeNull();
		});

		it("should return null for invalid URLs", () => {
			expect(parseGitUrl("/invalid")).toBeNull();
			expect(parseGitUrl("")).toBeNull();
			expect(parseGitUrl("/")).toBeNull();
		});
	});

	describe("getGitOperation", () => {
		it("treats auxiliary valid git HTTP paths as fetch reads", () => {
			expect(getGitOperation("GET", "/HEAD", "/github.com/owner/repo.git/HEAD")).toEqual({
				type: "fetch",
				repo: "owner/repo",
			});
			expect(
				getGitOperation(
					"GET",
					"/objects/info/packs",
					"/github.com/owner/repo.git/objects/info/packs",
				),
			).toEqual({ type: "fetch", repo: "owner/repo" });
		});

		it("classifies LFS locking mutation endpoints as push operations", () => {
			expect(
				getGitOperation("GET", "/info/lfs/locks", "/github.com/owner/repo.git/info/lfs/locks"),
			).toEqual({ type: "fetch", repo: "owner/repo", service: "lfs-locks" });
			expect(
				getGitOperation("POST", "/info/lfs/locks", "/github.com/owner/repo.git/info/lfs/locks"),
			).toEqual({ type: "push", repo: "owner/repo", service: "lfs-locks" });
			expect(
				getGitOperation(
					"POST",
					"/info/lfs/locks/verify",
					"/github.com/owner/repo.git/info/lfs/locks/verify",
				),
			).toEqual({ type: "push", repo: "owner/repo", service: "lfs-locks" });
			expect(
				getGitOperation(
					"POST",
					"/info/lfs/locks/123/unlock",
					"/github.com/owner/repo.git/info/lfs/locks/123/unlock",
				),
			).toEqual({ type: "push", repo: "owner/repo", service: "lfs-locks" });
		});

		it("rejects unknown POST paths instead of treating them as fetch reads", () => {
			expect(getGitOperation("POST", "/custom", "/github.com/owner/repo.git/custom")).toEqual({
				type: "unknown",
				repo: "owner/repo",
			});
		});

		it("does not classify substring route matches as receive-pack", () => {
			expect(
				getGitOperation(
					"POST",
					"/foo/../git-receive-pack",
					"/github.com/owner/repo.git/foo/../git-receive-pack",
				),
			).toEqual({
				type: "unknown",
				repo: "unknown",
			});
		});
	});

	describe("parseReceivePackCommands", () => {
		const zero = "0".repeat(40);
		const commit = "1".repeat(40);

		function pktLine(payload: string): Buffer {
			const length = Buffer.byteLength(payload) + 4;
			return Buffer.from(`${length.toString(16).padStart(4, "0")}${payload}`, "utf8");
		}

		it("parses receive-pack ref updates before the pack body", () => {
			const body = Buffer.concat([
				pktLine(`${zero} ${commit} refs/heads/codex/full-git-proxy\0 report-status\n`),
				pktLine(`${commit} ${zero} refs/heads/codex/delete-me\n`),
				Buffer.from("0000PACKbinary-data", "utf8"),
			]);

			const result = parseReceivePackCommands(body);

			expect(result.complete).toBe(true);
			expect(result.commands).toEqual([
				{ oldId: zero, newId: commit, ref: "refs/heads/codex/full-git-proxy" },
				{ oldId: commit, newId: zero, ref: "refs/heads/codex/delete-me" },
			]);
		});

		it("reports incomplete command lists without consuming the pack body", () => {
			const body = pktLine(`${zero} ${commit} refs/heads/codex/full-git-proxy\0 report-status\n`);

			const result = parseReceivePackCommands(body);

			expect(result.complete).toBe(false);
			expect(result.commands).toEqual([
				{ oldId: zero, newId: commit, ref: "refs/heads/codex/full-git-proxy" },
			]);
		});

		it("rejects malformed receive-pack refs instead of normalizing them", () => {
			const body = Buffer.concat([
				pktLine(`${zero} ${commit} refs/heads/codex/full-git-proxy extra\n`),
				Buffer.from("0000", "utf8"),
			]);

			expect(() => parseReceivePackCommands(body)).toThrow("invalid receive-pack command");
		});

		it("skips leading shallow lines while authorizing receive-pack commands", () => {
			const body = Buffer.concat([
				pktLine(`shallow ${commit}\n`),
				pktLine(`${zero} ${commit} refs/heads/codex/full-git-proxy\0 report-status\n`),
				Buffer.from("0000PACKbinary-data", "utf8"),
			]);

			const result = parseReceivePackCommands(body);

			expect(result.complete).toBe(true);
			expect(result.commands).toEqual([
				{ oldId: zero, newId: commit, ref: "refs/heads/codex/full-git-proxy" },
			]);
		});

		it("rejects push certificates instead of partially authorizing embedded commands", () => {
			const body = Buffer.concat([
				pktLine("push-cert\0 report-status\n"),
				pktLine("certificate version 0.1\n"),
				pktLine("pusher Test User <test@example.com>\n"),
				pktLine("pushee https://github.com/owner/repo.git\n"),
				pktLine("nonce test-nonce\n"),
				pktLine("\n"),
				pktLine(`${zero} ${commit} refs/heads/codex/full-git-proxy\n`),
				pktLine(`${zero} ${commit} refs/heads/secret@x\n`),
				pktLine("-----BEGIN PGP SIGNATURE-----\n"),
				pktLine("not-a-command\n"),
				pktLine("push-cert-end\n"),
				Buffer.from("0000PACKbinary-data", "utf8"),
			]);

			expect(() => parseReceivePackCommands(body)).toThrow(
				"receive-pack push certificates are not supported",
			);
		});
	});

	describe("parseLfsBatchOperation", () => {
		it("classifies LFS download as fetch", () => {
			const result = parseLfsBatchOperation(
				Buffer.from(
					JSON.stringify({
						operation: "download",
						objects: [{ oid: "a".repeat(64), size: 1 }],
					}),
				),
			);

			expect(result).toEqual({ type: "fetch" });
		});

		it("classifies LFS upload as push and preserves the ref", () => {
			const result = parseLfsBatchOperation(
				Buffer.from(
					JSON.stringify({
						operation: "upload",
						ref: { name: "refs/heads/codex/full-git-proxy" },
						objects: [{ oid: "a".repeat(64), size: 1 }],
					}),
				),
			);

			expect(result).toEqual({
				type: "push",
				ref: "refs/heads/codex/full-git-proxy",
			});
		});

		it("rejects invalid LFS refs", () => {
			expect(() =>
				parseLfsBatchOperation(
					Buffer.from(JSON.stringify({ operation: "upload", ref: { name: "main" } })),
				),
			).toThrow("invalid lfs batch ref");
		});
	});

	describe("describeLfsActionTargetForLog", () => {
		it("redacts signed LFS action URL paths and query strings", () => {
			expect(
				describeLfsActionTargetForLog(
					"https://objects.example.test/private/path?X-Amz-Signature=secret&token=also-secret",
				),
			).toEqual({ lfsActionOrigin: "https://objects.example.test" });
		});
	});

	describe("authorizeReceivePackCommands", () => {
		const zero = "0".repeat(40);
		const commit = "1".repeat(40);

		it("allows branches matched by policy", () => {
			const result = authorizeReceivePackCommands(
				[{ oldId: zero, newId: commit, ref: "refs/heads/codex/full-git-proxy" }],
				{
					repositories: ["avivsinai/telclaude"],
					permissions: ["push"],
					allowedRefs: ["refs/heads/codex/*"],
					deniedRefs: ["refs/heads/main", "refs/heads/master"],
				},
			);

			expect(result).toEqual({ ok: true });
		});

		it("rejects protected branch pushes even when a broad allow pattern matches", () => {
			const result = authorizeReceivePackCommands(
				[{ oldId: zero, newId: commit, ref: "refs/heads/main" }],
				{
					repositories: ["avivsinai/telclaude"],
					permissions: ["push"],
					allowedRefs: ["refs/heads/*"],
					deniedRefs: ["refs/heads/main", "refs/heads/master"],
				},
			);

			expect(result).toEqual({
				ok: false,
				reason: "push ref is denied by git proxy policy",
			});
		});

		it("rejects tag pushes unless explicitly allowed", () => {
			const result = authorizeReceivePackCommands(
				[{ oldId: zero, newId: commit, ref: "refs/tags/v1.0.0" }],
				{
					repositories: ["avivsinai/telclaude"],
					permissions: ["push"],
					allowedRefs: ["refs/heads/*"],
					deniedRefs: [],
				},
			);

			expect(result).toEqual({
				ok: false,
				reason: "push ref is not allowed by git proxy policy",
			});
		});

		it("rejects LFS uploads without a ref because branch policy cannot be enforced", () => {
			const result = authorizePushRefs(
				[],
				{
					repositories: ["avivsinai/telclaude"],
					permissions: ["push"],
					allowedRefs: ["refs/heads/codex/*"],
					deniedRefs: ["refs/heads/main", "refs/heads/master"],
				},
				"lfs upload request did not include a ref",
			);

			expect(result).toEqual({
				ok: false,
				reason: "lfs upload request did not include a ref",
			});
		});
	});
});
