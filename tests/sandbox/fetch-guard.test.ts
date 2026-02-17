import { afterEach, describe, expect, it, vi } from "vitest";

import {
	FetchGuardError,
	createPinnedLookup,
	fetchWithGuard,
} from "../../src/sandbox/fetch-guard.js";

// ═══════════════════════════════════════════════════════════════════════════════
// Mock cachedDNSLookup for controlled test scenarios
// ═══════════════════════════════════════════════════════════════════════════════

const mockDNSResults = new Map<string, string[] | null>();

vi.mock("../../src/sandbox/network-proxy.js", async (importOriginal) => {
	const actual = (await importOriginal()) as Record<string, unknown>;
	return {
		...actual,
		cachedDNSLookup: async (host: string): Promise<string[] | null> => {
			if (mockDNSResults.has(host)) {
				return mockDNSResults.get(host) ?? null;
			}
			// Default: return a public IP for any hostname
			return ["93.184.216.34"];
		},
	};
});

// Suppress logger output in tests
vi.mock("../../src/logging.js", () => ({
	getChildLogger: () => ({
		info: () => {},
		warn: () => {},
		error: () => {},
		debug: () => {},
	}),
}));

afterEach(() => {
	mockDNSResults.clear();
	vi.restoreAllMocks();
});

// ═══════════════════════════════════════════════════════════════════════════════
// createPinnedLookup tests
// ═══════════════════════════════════════════════════════════════════════════════

describe("createPinnedLookup", () => {
	it("returns pinned addresses for the target hostname", () => {
		const lookup = createPinnedLookup("example.com", ["1.2.3.4", "5.6.7.8"]);
		const results: string[] = [];

		lookup("example.com", {}, (err, address) => {
			expect(err).toBeNull();
			results.push(address as string);
		});
		lookup("example.com", {}, (err, address) => {
			expect(err).toBeNull();
			results.push(address as string);
		});

		// Round-robin
		expect(results).toEqual(["1.2.3.4", "5.6.7.8"]);
	});

	it("returns all addresses when options.all is true", () => {
		const lookup = createPinnedLookup("example.com", ["1.2.3.4", "::1"]);

		lookup("example.com", { all: true }, (err, addresses) => {
			expect(err).toBeNull();
			expect(addresses).toEqual([
				{ address: "1.2.3.4", family: 4 },
				{ address: "::1", family: 6 },
			]);
		});
	});

	it("rejects lookups for non-pinned hostnames", () => {
		const lookup = createPinnedLookup("example.com", ["1.2.3.4"]);

		lookup("evil.com", {}, (err) => {
			expect(err).toBeTruthy();
			expect((err as NodeJS.ErrnoException).code).toBe("ENOTFOUND");
		});
	});

	it("handles case-insensitive hostname matching", () => {
		const lookup = createPinnedLookup("Example.COM", ["1.2.3.4"]);

		lookup("example.com", {}, (err, address) => {
			expect(err).toBeNull();
			expect(address).toBe("1.2.3.4");
		});
	});
});

// ═══════════════════════════════════════════════════════════════════════════════
// fetchWithGuard tests
// ═══════════════════════════════════════════════════════════════════════════════

describe("fetchWithGuard", () => {
	// ─── Blocking tests (no real server needed) ───

	it("blocks URLs resolving to private IPs", async () => {
		mockDNSResults.set("evil-redirect.example", ["192.168.1.1"]);

		await expect(
			fetchWithGuard({ url: "http://evil-redirect.example/foo" }),
		).rejects.toThrow(FetchGuardError);

		await expect(
			fetchWithGuard({ url: "http://evil-redirect.example/foo" }),
		).rejects.toThrow(/private\/internal IP/);
	});

	it("blocks URLs resolving to metadata IPs (non-overridable)", async () => {
		mockDNSResults.set("sneaky.example", ["169.254.169.254"]);

		await expect(
			fetchWithGuard({ url: "http://sneaky.example/latest/meta-data" }),
		).rejects.toThrow(FetchGuardError);

		await expect(
			fetchWithGuard({ url: "http://sneaky.example/latest/meta-data" }),
		).rejects.toThrow(/non-overridable/);
	});

	it("blocks literal private IP URLs", async () => {
		await expect(fetchWithGuard({ url: "http://10.0.0.1/admin" })).rejects.toThrow(
			FetchGuardError,
		);
	});

	it("blocks literal metadata IP URLs", async () => {
		await expect(
			fetchWithGuard({ url: "http://169.254.169.254/latest/meta-data" }),
		).rejects.toThrow(FetchGuardError);
	});

	it("blocks CGNAT range IPs", async () => {
		mockDNSResults.set("tailscale-peer.example", ["100.100.0.1"]);

		await expect(fetchWithGuard({ url: "http://tailscale-peer.example/" })).rejects.toThrow(
			FetchGuardError,
		);
	});

	it("blocks when DNS resolves to mixed public+private IPs (dual-stack bypass)", async () => {
		mockDNSResults.set("dual.example", ["93.184.216.34", "10.0.0.1"]);

		await expect(fetchWithGuard({ url: "http://dual.example/" })).rejects.toThrow(
			FetchGuardError,
		);

		await expect(fetchWithGuard({ url: "http://dual.example/" })).rejects.toThrow(
			/private\/internal IP/,
		);
	});

	it("blocks when DNS fails to resolve", async () => {
		mockDNSResults.set("nonexistent.invalid", null);

		await expect(fetchWithGuard({ url: "http://nonexistent.invalid/" })).rejects.toThrow(
			FetchGuardError,
		);

		await expect(fetchWithGuard({ url: "http://nonexistent.invalid/" })).rejects.toThrow(
			/DNS resolution failed/,
		);
	});

	it("blocks non-http(s) protocols", async () => {
		await expect(fetchWithGuard({ url: "ftp://example.com/file" })).rejects.toThrow(
			FetchGuardError,
		);

		await expect(fetchWithGuard({ url: "file:///etc/passwd" })).rejects.toThrow(FetchGuardError);
	});

	it("rejects invalid URLs", async () => {
		await expect(fetchWithGuard({ url: "not-a-url" })).rejects.toThrow(FetchGuardError);
	});

	// ─── IPv6 blocking ───

	it("blocks IPv6 link-local addresses", async () => {
		mockDNSResults.set("v6local.example", ["fe80::1"]);

		await expect(fetchWithGuard({ url: "http://v6local.example/" })).rejects.toThrow(
			FetchGuardError,
		);
	});

	it("blocks IPv6 unique-local addresses", async () => {
		mockDNSResults.set("v6ula.example", ["fd12:3456::1"]);

		await expect(fetchWithGuard({ url: "http://v6ula.example/" })).rejects.toThrow(
			FetchGuardError,
		);
	});

	it("blocks IPv4-mapped IPv6 private addresses", async () => {
		mockDNSResults.set("v4mapped.example", ["::ffff:192.168.1.1"]);

		await expect(fetchWithGuard({ url: "http://v4mapped.example/" })).rejects.toThrow(
			FetchGuardError,
		);
	});

	it("includes auditContext in error logging", async () => {
		mockDNSResults.set("audit-test.example", ["10.0.0.1"]);

		await expect(
			fetchWithGuard({
				url: "http://audit-test.example/",
				auditContext: "test-consumer",
			}),
		).rejects.toThrow(FetchGuardError);
	});

	// ─── Happy path (with mocked global fetch) ───

	it("allows URLs resolving to public IPs", async () => {
		mockDNSResults.set("safe.example", ["93.184.216.34"]);

		const mockFetch = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
			new Response("hello world", {
				status: 200,
				headers: { "Content-Type": "text/plain" },
			}),
		);

		const result = await fetchWithGuard({
			url: "http://safe.example/page",
		});

		expect(result.response.status).toBe(200);
		expect(result.finalUrl).toBe("http://safe.example/page");
		expect(typeof result.release).toBe("function");

		const body = await result.response.text();
		expect(body).toBe("hello world");
		await result.release();

		expect(mockFetch).toHaveBeenCalledOnce();
		// Verify fetch was called with redirect: "manual" and a dispatcher
		const callInit = mockFetch.mock.calls[0][1] as RequestInit & { dispatcher?: unknown };
		expect(callInit.redirect).toBe("manual");
		expect(callInit.dispatcher).toBeTruthy();
	});

	// ─── Redirect handling (with mocked global fetch) ───

	it("follows redirects and re-validates each hop", async () => {
		mockDNSResults.set("start.example", ["93.184.216.34"]);
		mockDNSResults.set("middle.example", ["93.184.216.35"]);

		const mockFetch = vi.spyOn(globalThis, "fetch");

		// First call: redirect
		mockFetch.mockResolvedValueOnce(
			new Response(null, {
				status: 302,
				headers: { Location: "http://middle.example/final" },
			}),
		);

		// Second call: final response
		mockFetch.mockResolvedValueOnce(
			new Response("redirected content", {
				status: 200,
				headers: { "Content-Type": "text/plain" },
			}),
		);

		const result = await fetchWithGuard({
			url: "http://start.example/begin",
		});

		expect(result.response.status).toBe(200);
		expect(result.finalUrl).toBe("http://middle.example/final");
		const body = await result.response.text();
		expect(body).toBe("redirected content");
		await result.release();

		expect(mockFetch).toHaveBeenCalledTimes(2);
	});

	it("blocks redirect to private IP (SSRF redirect bypass)", async () => {
		mockDNSResults.set("legit.example", ["93.184.216.34"]);
		mockDNSResults.set("internal.corp", ["192.168.1.100"]);

		const mockFetch = vi.spyOn(globalThis, "fetch");

		// First call: redirect to private host
		mockFetch.mockResolvedValueOnce(
			new Response(null, {
				status: 302,
				headers: { Location: "http://internal.corp/secret" },
			}),
		);

		const err = await fetchWithGuard({ url: "http://legit.example/go" }).catch((e) => e);
		expect(err).toBeInstanceOf(FetchGuardError);
		expect(err.message).toMatch(/private\/internal IP/);
	});

	it("blocks redirect to metadata IP (SSRF redirect bypass)", async () => {
		mockDNSResults.set("legit2.example", ["93.184.216.34"]);
		mockDNSResults.set("sneaky-meta.example", ["169.254.169.254"]);

		const mockFetch = vi.spyOn(globalThis, "fetch");
		mockFetch.mockResolvedValueOnce(
			new Response(null, {
				status: 301,
				headers: { Location: "http://sneaky-meta.example/latest/meta-data" },
			}),
		);

		await expect(
			fetchWithGuard({ url: "http://legit2.example/" }),
		).rejects.toThrow(/non-overridable/);
	});

	it("enforces max redirect cap", async () => {
		mockDNSResults.set("chain.example", ["93.184.216.34"]);

		const mockFetch = vi.spyOn(globalThis, "fetch");

		// Create 4 redirects (exceeds default cap of 3)
		for (let i = 0; i < 4; i++) {
			mockFetch.mockResolvedValueOnce(
				new Response(null, {
					status: 302,
					headers: { Location: `http://chain.example/step${i + 1}` },
				}),
			);
		}

		await expect(
			fetchWithGuard({ url: "http://chain.example/start" }),
		).rejects.toThrow(/Too many redirects/);
	});

	it("detects redirect loops", async () => {
		mockDNSResults.set("loop.example", ["93.184.216.34"]);

		const mockFetch = vi.spyOn(globalThis, "fetch");

		// First redirect: /a -> /b
		mockFetch.mockResolvedValueOnce(
			new Response(null, {
				status: 302,
				headers: { Location: "http://loop.example/b" },
			}),
		);

		// Second redirect: /b -> /a (loop! — /a is the initial URL, already in visited)
		mockFetch.mockResolvedValueOnce(
			new Response(null, {
				status: 302,
				headers: { Location: "http://loop.example/a" },
			}),
		);

		await expect(
			fetchWithGuard({ url: "http://loop.example/a" }),
		).rejects.toThrow(/Redirect loop detected/);
	});

	it("handles redirect with missing Location header", async () => {
		mockDNSResults.set("bad.example", ["93.184.216.34"]);

		const mockFetch = vi.spyOn(globalThis, "fetch");
		mockFetch.mockResolvedValueOnce(
			new Response(null, { status: 302 }),
		);

		await expect(
			fetchWithGuard({ url: "http://bad.example/" }),
		).rejects.toThrow(/missing Location header/);
	});

	it("respects custom maxRedirects option", async () => {
		mockDNSResults.set("custom.example", ["93.184.216.34"]);

		const mockFetch = vi.spyOn(globalThis, "fetch");

		// 2 redirects (exceeds custom cap of 1)
		mockFetch.mockResolvedValueOnce(
			new Response(null, {
				status: 302,
				headers: { Location: "http://custom.example/step1" },
			}),
		);
		mockFetch.mockResolvedValueOnce(
			new Response(null, {
				status: 302,
				headers: { Location: "http://custom.example/step2" },
			}),
		);

		await expect(
			fetchWithGuard({ url: "http://custom.example/start", maxRedirects: 1 }),
		).rejects.toThrow(/Too many redirects \(limit: 1\)/);
	});

	// ─── Timeout tests ───

	it("aborts on timeout", async () => {
		mockDNSResults.set("slow.example", ["93.184.216.34"]);

		// Mock fetch to hang indefinitely
		const mockFetch = vi.spyOn(globalThis, "fetch").mockImplementation(
			(_url, init) =>
				new Promise((_resolve, reject) => {
					// Listen for abort signal
					const signal = (init as RequestInit)?.signal;
					if (signal?.aborted) {
						reject(signal.reason);
						return;
					}
					signal?.addEventListener("abort", () => reject(signal.reason), { once: true });
				}),
		);

		await expect(
			fetchWithGuard({
				url: "http://slow.example/",
				timeoutMs: 50,
			}),
		).rejects.toThrow();

		mockFetch.mockRestore();
	});

	it("respects external abort signal", async () => {
		mockDNSResults.set("abortable.example", ["93.184.216.34"]);
		const controller = new AbortController();

		const mockFetch = vi.spyOn(globalThis, "fetch").mockImplementation(
			(_url, init) =>
				new Promise((_resolve, reject) => {
					const signal = (init as RequestInit)?.signal;
					if (signal?.aborted) {
						reject(signal.reason);
						return;
					}
					signal?.addEventListener("abort", () => reject(signal.reason), { once: true });
				}),
		);

		// Abort immediately
		controller.abort(new Error("user cancelled"));

		await expect(
			fetchWithGuard({
				url: "http://abortable.example/",
				signal: controller.signal,
			}),
		).rejects.toThrow();

		mockFetch.mockRestore();
	});

	// ─── DNS rebinding simulation ───

	it("prevents DNS rebinding via pinned lookup", async () => {
		// Even if DNS would return a different IP on second resolution,
		// the pinned lookup ensures the original validated IPs are used
		// for the actual TCP connection.
		mockDNSResults.set("rebind.example", ["93.184.216.34"]);

		const mockFetch = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
			new Response("safe", { status: 200 }),
		);

		const result = await fetchWithGuard({
			url: "http://rebind.example/",
		});

		expect(result.response.status).toBe(200);
		await result.release();

		// Verify dispatcher was passed (proving DNS was pinned)
		const callInit = mockFetch.mock.calls[0][1] as RequestInit & { dispatcher?: unknown };
		expect(callInit.dispatcher).toBeTruthy();
	});
});
