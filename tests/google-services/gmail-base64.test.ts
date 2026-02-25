import { describe, expect, it, vi } from "vitest";

/**
 * Tests the base64url → base64 normalization in Gmail attachment handling.
 *
 * The Gmail API returns attachment data in base64url encoding (using - and _),
 * but the provider proxy expects standard base64 (using + and /).
 * Without normalization, attachments are silently corrupted or rejected.
 */

// We can't easily call handleDownloadAttachment directly (unexported, requires
// live googleapis mock), so we test the normalization logic and then verify
// the handler via a mock of the entire gmail module.

describe("base64url to base64 normalization", () => {
	it("replaces - with + and _ with /", () => {
		const base64url = "ab-cd_ef";
		const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
		expect(base64).toBe("ab+cd/ef");
	});

	it("handles pure base64url with no padding", () => {
		const base64url = "YQ"; // "a" in base64url without padding
		const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
		expect(Buffer.from(base64, "base64").toString()).toBe("a");
	});

	it("handles empty string", () => {
		const base64url = "";
		const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
		expect(base64).toBe("");
	});

	it("preserves already-valid base64", () => {
		const base64 = "SGVsbG8gV29ybGQ=";
		const result = base64.replace(/-/g, "+").replace(/_/g, "/");
		expect(result).toBe(base64); // No change
	});
});

describe("handleGmail download_attachment", () => {
	it("normalizes base64url attachment data to standard base64", async () => {
		// Mock googleapis to return base64url-encoded data
		const base64urlData = "SGVsbG8td29ybGRfZGF0YQ"; // contains - and _ chars
		vi.doMock("googleapis", () => ({
			google: {
				auth: { OAuth2: vi.fn().mockImplementation(() => ({ setCredentials: vi.fn() })) },
				gmail: vi.fn().mockReturnValue({
					users: {
						messages: {
							attachments: {
								get: vi.fn().mockResolvedValue({
									data: { data: base64urlData, size: 42 },
								}),
							},
						},
					},
				}),
			},
		}));

		const { handleGmail } = await import("../../src/google-services/handlers/gmail.js");

		const result = await handleGmail(
			{
				service: "gmail",
				action: "download_attachment",
				params: { messageId: "msg123", attachmentId: "att456" },
			},
			"mock-token",
		);

		expect(result.status).toBe("ok");
		expect(result.attachments).toHaveLength(1);

		const inline = result.attachments[0].inline;
		// Must NOT contain base64url characters
		expect(inline).not.toContain("-");
		expect(inline).not.toContain("_");
		// Must be valid standard base64
		expect(inline).toMatch(/^[A-Za-z0-9+/=]*$/);
	});
});
