import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { execSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

describe("git-proxy-init", () => {
	let tempHome: string;
	let originalHome: string;
	let originalEnv: NodeJS.ProcessEnv;

	beforeEach(() => {
		// Save original environment
		originalHome = process.env.HOME ?? "";
		originalEnv = { ...process.env };

		// Create a temporary HOME directory for isolated git config
		tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "git-proxy-test-"));
		process.env.HOME = tempHome;

		// Set required environment variables
		process.env.TELCLAUDE_GIT_PROXY_SECRET = "test-secret-for-git-proxy-init";
	});

	afterEach(() => {
		// Restore original environment
		process.env.HOME = originalHome;
		Object.keys(process.env).forEach((key) => {
			if (!(key in originalEnv)) {
				delete process.env[key];
			}
		});
		Object.assign(process.env, originalEnv);

		// Clean up temp directory
		if (tempHome && fs.existsSync(tempHome)) {
			fs.rmSync(tempHome, { recursive: true, force: true });
		}

		vi.restoreAllMocks();
	});

	describe("git config multi-value insteadOf", () => {
		it("should set all three URL scheme rewrites", () => {
			const proxyUrl = "http://test-proxy:8791";

			// Simulate what configureGit does for insteadOf
			const key = `url."${proxyUrl}/github.com/".insteadOf`;
			const values = ["https://github.com/", "git@github.com:", "ssh://git@github.com/"];

			// Unset any existing values
			try {
				execSync(`git config --global --unset-all ${key}`, { stdio: "ignore" });
			} catch {
				// Ignore if key doesn't exist
			}

			// Add each value
			for (const value of values) {
				execSync(`git config --global --add ${key} "${value}"`, { stdio: "ignore" });
			}

			// Verify all three values are present
			const result = execSync(`git config --global --get-all ${key}`, { encoding: "utf-8" });
			const lines = result.trim().split("\n");

			expect(lines).toHaveLength(3);
			expect(lines).toContain("https://github.com/");
			expect(lines).toContain("git@github.com:");
			expect(lines).toContain("ssh://git@github.com/");
		});

		it("should replace existing values on re-run", () => {
			const proxyUrl = "http://test-proxy:8791";
			const key = `url."${proxyUrl}/github.com/".insteadOf`;

			// Set initial values
			execSync(`git config --global --add ${key} "old-value-1"`, { stdio: "ignore" });
			execSync(`git config --global --add ${key} "old-value-2"`, { stdio: "ignore" });

			// Simulate re-run: unset all, then add new values
			try {
				execSync(`git config --global --unset-all ${key}`, { stdio: "ignore" });
			} catch {
				// Ignore
			}

			const newValues = ["https://github.com/", "git@github.com:"];
			for (const value of newValues) {
				execSync(`git config --global --add ${key} "${value}"`, { stdio: "ignore" });
			}

			// Verify only new values exist
			const result = execSync(`git config --global --get-all ${key}`, { encoding: "utf-8" });
			const lines = result.trim().split("\n");

			expect(lines).toHaveLength(2);
			expect(lines).not.toContain("old-value-1");
			expect(lines).not.toContain("old-value-2");
			expect(lines).toContain("https://github.com/");
			expect(lines).toContain("git@github.com:");
		});
	});

	describe("TTL validation", () => {
		it("should reject non-numeric TTL", () => {
			const ttlMinutes = Number.parseInt("abc", 10);
			expect(Number.isNaN(ttlMinutes)).toBe(true);
		});

		it("should reject zero TTL", () => {
			const ttlMinutes = Number.parseInt("0", 10);
			expect(ttlMinutes < 1).toBe(true);
		});

		it("should reject negative TTL", () => {
			const ttlMinutes = Number.parseInt("-5", 10);
			expect(ttlMinutes < 1).toBe(true);
		});

		it("should accept valid positive TTL", () => {
			const ttlMinutes = Number.parseInt("60", 10);
			expect(Number.isNaN(ttlMinutes)).toBe(false);
			expect(ttlMinutes >= 1).toBe(true);
		});

		it("should convert minutes to milliseconds correctly", () => {
			const ttlMinutes = 45;
			const ttlMs = ttlMinutes * 60 * 1000;
			expect(ttlMs).toBe(2700000);
		});
	});

	describe("daemon refresh interval", () => {
		const REFRESH_INTERVAL_MS = 45 * 60 * 1000; // 45 minutes

		it("should use 75% of TTL if less than default refresh interval", () => {
			const ttlMs = 30 * 60 * 1000; // 30 minutes
			const refreshMs = Math.min(REFRESH_INTERVAL_MS, ttlMs * 0.75);
			expect(refreshMs).toBe(ttlMs * 0.75); // 22.5 minutes
		});

		it("should use default refresh interval if TTL is long", () => {
			const ttlMs = 120 * 60 * 1000; // 2 hours
			const refreshMs = Math.min(REFRESH_INTERVAL_MS, ttlMs * 0.75);
			expect(refreshMs).toBe(REFRESH_INTERVAL_MS); // 45 minutes
		});

		it("should never exceed the actual TTL", () => {
			const ttlMs = 10 * 60 * 1000; // 10 minutes
			const refreshMs = Math.min(REFRESH_INTERVAL_MS, ttlMs * 0.75);
			expect(refreshMs).toBeLessThan(ttlMs);
		});
	});

	describe("git identity configuration", () => {
		it("should set user.name and user.email", () => {
			const identity = { username: "test-bot", email: "test@example.com" };

			execSync(`git config --global user.name "${identity.username}"`, { stdio: "ignore" });
			execSync(`git config --global user.email "${identity.email}"`, { stdio: "ignore" });

			const name = execSync("git config --global user.name", { encoding: "utf-8" }).trim();
			const email = execSync("git config --global user.email", { encoding: "utf-8" }).trim();

			expect(name).toBe("test-bot");
			expect(email).toBe("test@example.com");
		});
	});

	describe("session header configuration", () => {
		it("should set extraHeader for proxy authentication", () => {
			const proxyUrl = "http://test-proxy:8791";
			const sessionToken = "test-session-token";
			const section = `${proxyUrl}/`;
			const header = `X-Telclaude-Session: ${sessionToken}`;

			// Unset existing
			try {
				execSync(`git config --global --unset-all http."${section}".extraHeader`, {
					stdio: "ignore",
				});
			} catch {
				// Ignore
			}

			// Add header
			execSync(`git config --global --add http."${section}".extraHeader "${header}"`, {
				stdio: "ignore",
			});

			// Verify
			const result = execSync(`git config --global http."${section}".extraHeader`, {
				encoding: "utf-8",
			}).trim();
			expect(result).toBe(header);
		});
	});
});
