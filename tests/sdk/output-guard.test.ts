import { describe, expect, it } from "vitest";
import {
	buildOverflowRecoverySummary,
	DEFAULT_MAX_TOOL_RESULT_CHARS,
	guardToolResultOutput,
	isContextOverflowError,
	truncateToolResult,
} from "../../src/sdk/output-guard.js";

describe("truncateToolResult", () => {
	it("returns content unchanged when under the limit", () => {
		const content = "short content";
		const result = truncateToolResult(content, 1000);
		expect(result.wasTruncated).toBe(false);
		expect(result.content).toBe(content);
		expect(result.originalSize).toBe(content.length);
	});

	it("returns content unchanged when exactly at the limit", () => {
		const content = "x".repeat(1000);
		const result = truncateToolResult(content, 1000);
		expect(result.wasTruncated).toBe(false);
		expect(result.content).toBe(content);
	});

	it("truncates content exceeding the limit", () => {
		const content = "x".repeat(10_000);
		const result = truncateToolResult(content, 5000);
		expect(result.wasTruncated).toBe(true);
		expect(result.content.length).toBeLessThanOrEqual(5500); // allow marker overhead
		expect(result.originalSize).toBe(10_000);
		expect(result.content).toContain("[... truncated");
	});

	it("keeps head and tail portions", () => {
		const head = "HEAD_MARKER_" + "a".repeat(5000);
		const middle = "b".repeat(90_000);
		const tail = "c".repeat(4000) + "_TAIL_MARKER";
		const content = head + middle + tail;
		const result = truncateToolResult(content, 10_000);

		expect(result.wasTruncated).toBe(true);
		expect(result.content).toContain("HEAD_MARKER_");
		expect(result.content).toContain("_TAIL_MARKER");
		expect(result.content).toContain("[... truncated");
	});

	it("tries to break at newline boundaries", () => {
		const lines = Array.from({ length: 200 }, (_, i) => `line ${i}: ${"x".repeat(50)}`).join(
			"\n",
		);
		const result = truncateToolResult(lines, 5000);
		expect(result.wasTruncated).toBe(true);
		// Head portion should end at a newline (not mid-line)
		const markerIdx = result.content.indexOf("[... truncated");
		const beforeMarker = result.content.slice(0, markerIdx);
		expect(beforeMarker.endsWith("\n")).toBe(true);
	});

	it("uses default max size when none specified", () => {
		const content = "x".repeat(DEFAULT_MAX_TOOL_RESULT_CHARS + 1000);
		const result = truncateToolResult(content);
		expect(result.wasTruncated).toBe(true);
		expect(result.content.length).toBeLessThan(content.length);
	});

	it("respects minimum keep size", () => {
		// Even with a very small maxSize, we keep at least MIN_KEEP_CHARS (2000)
		const content = "x".repeat(10_000);
		const result = truncateToolResult(content, 100);
		expect(result.wasTruncated).toBe(true);
		// The result should be at least 2000 chars (MIN_KEEP_CHARS)
		expect(result.content.length).toBeGreaterThanOrEqual(2000);
	});

	it("includes human-readable size in marker", () => {
		const content = "x".repeat(150_000);
		const result = truncateToolResult(content, 10_000);
		expect(result.content).toMatch(/\[... truncated \d+(\.\d+)?K chars .../);
	});

	it("shows M chars for very large truncations", () => {
		const content = "x".repeat(2_000_000);
		const result = truncateToolResult(content, 10_000);
		expect(result.content).toMatch(/\d+(\.\d+)?M chars/);
	});
});

describe("guardToolResultOutput", () => {
	it("passes through small string outputs unchanged", () => {
		const { output, truncation } = guardToolResultOutput("small output", 1000);
		expect(output).toBe("small output");
		expect(truncation).toBeUndefined();
	});

	it("passes through null/undefined unchanged", () => {
		expect(guardToolResultOutput(null).output).toBeNull();
		expect(guardToolResultOutput(undefined).output).toBeUndefined();
	});

	it("truncates large string outputs", () => {
		const large = "x".repeat(10_000);
		const { output, truncation } = guardToolResultOutput(large, 5000);
		expect(typeof output).toBe("string");
		expect((output as string).length).toBeLessThan(large.length);
		expect(truncation).toBeDefined();
		expect(truncation?.wasTruncated).toBe(true);
		expect(truncation?.originalSize).toBe(10_000);
	});

	it("handles object outputs by serializing", () => {
		const obj = { data: "x".repeat(10_000) };
		const { output, truncation } = guardToolResultOutput(obj, 5000);
		expect(typeof output).toBe("string");
		expect(truncation?.wasTruncated).toBe(true);
	});

	it("does not truncate small object outputs", () => {
		const obj = { result: "ok" };
		const { output, truncation } = guardToolResultOutput(obj);
		expect(output).toEqual(obj);
		expect(truncation).toBeUndefined();
	});
});

describe("isContextOverflowError", () => {
	it("detects context length exceeded errors", () => {
		expect(isContextOverflowError("context_length_exceeded")).toBe(true);
		expect(isContextOverflowError("Error: context window limit exceeded")).toBe(true);
		expect(isContextOverflowError("maximum context length reached")).toBe(true);
		expect(isContextOverflowError("too many tokens in request")).toBe(true);
		expect(isContextOverflowError("prompt too long for model")).toBe(true);
		expect(isContextOverflowError("input too large")).toBe(true);
		expect(isContextOverflowError("request too large")).toBe(true);
		expect(isContextOverflowError("max_tokens_exceeded")).toBe(true);
		expect(isContextOverflowError("prompt_too_long")).toBe(true);
	});

	it("handles Error objects", () => {
		expect(isContextOverflowError(new Error("context_length_exceeded"))).toBe(true);
		expect(isContextOverflowError(new Error("token limit exceeded"))).toBe(true);
	});

	it("returns false for unrelated errors", () => {
		expect(isContextOverflowError("network timeout")).toBe(false);
		expect(isContextOverflowError("rate limit exceeded")).toBe(false);
		expect(isContextOverflowError("authentication failed")).toBe(false);
		expect(isContextOverflowError("")).toBe(false);
		expect(isContextOverflowError(null)).toBe(false);
		expect(isContextOverflowError(undefined)).toBe(false);
	});
});

describe("buildOverflowRecoverySummary", () => {
	it("includes turn count and error info", () => {
		const summary = buildOverflowRecoverySummary({
			poolKey: "chat-123",
			error: "context_length_exceeded",
			numTurns: 5,
		});
		expect(summary).toContain("5 turn(s)");
		expect(summary).toContain("context_length_exceeded");
		expect(summary).toContain("Session will be reset");
	});
});
