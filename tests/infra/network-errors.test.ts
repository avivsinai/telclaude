import { describe, expect, it } from "vitest";
import {
	collectErrorCandidates,
	formatErrorSafe,
	isAbortError,
	isRecoverableError,
	isTransientNetworkError,
} from "../../src/infra/network-errors.js";

describe("infra/network-errors", () => {
	it("collectErrorCandidates traverses nested cause/reason/errors and handles cycles", () => {
		const nested = { message: "nested" };
		const transient = { code: "ECONNRESET", message: "socket hang up" };
		const root: Record<string, unknown> = {
			message: "root",
			cause: transient,
			reason: { name: "AbortError" },
			errors: [nested],
		};
		(transient as Record<string, unknown>).cause = root;

		const candidates = collectErrorCandidates(root);

		expect(candidates).toContain(root);
		expect(candidates).toContain(transient);
		expect(candidates).toContain(nested);
		expect(candidates.length).toBeLessThan(10);
	});

	it("detects TimeoutError as transient", () => {
		const timeoutErr = { name: "TimeoutError", message: "stream-read timed out after 30000ms" };
		expect(isTransientNetworkError(timeoutErr)).toBe(true);

		const nestedTimeout = { cause: timeoutErr };
		expect(isTransientNetworkError(nestedTimeout)).toBe(true);
	});

	it("detects transient network errors by nested code and message", () => {
		const errWithCode = {
			cause: {
				code: "UND_ERR_CONNECT_TIMEOUT",
			},
		};
		const errWithMessage = new Error("Client network socket disconnected before secure TLS connection");

		expect(isTransientNetworkError(errWithCode)).toBe(true);
		expect(isTransientNetworkError(errWithMessage)).toBe(true);
		expect(isTransientNetworkError(new Error("validation failed"))).toBe(false);
	});

	it("detects abort errors by name, code, or message", () => {
		expect(isAbortError({ name: "AbortError" })).toBe(true);
		expect(isAbortError({ code: "ABORT_ERR" })).toBe(true);
		expect(isAbortError(new Error("This operation was aborted"))).toBe(true);
		expect(isAbortError(new Error("hard failure"))).toBe(false);
	});

	it("classifies recoverable errors as transient or abort", () => {
		expect(isRecoverableError({ code: "ETIMEDOUT" })).toBe(true);
		expect(isRecoverableError({ name: "AbortError" })).toBe(true);
		expect(isRecoverableError(new Error("permanent auth failure"))).toBe(false);
	});

	it("formats errors safely with URL redaction and truncation", () => {
		const err = new Error(
			"request failed at https://user:token@example.com/path?secret=1 due to timeout",
		);

		const formatted = formatErrorSafe(err, 80);
		expect(formatted).toContain("[URL]");
		expect(formatted).not.toContain("https://");
		expect(formatted.length).toBeLessThanOrEqual(80);
	});

	it("includes cause chain while formatting errors", () => {
		const cause = new Error("read ECONNRESET");
		const err = new Error("fetch failed", { cause });

		const formatted = formatErrorSafe(err, 200);
		expect(formatted).toContain("Error: fetch failed");
		expect(formatted).toContain("cause:");
		expect(formatted).toContain("read ECONNRESET");
	});
});
