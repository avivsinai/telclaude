import { beforeEach, describe, expect, it, vi } from "vitest";

beforeEach(() => {
	vi.resetModules();
	vi.clearAllMocks();
});

describe("Drive folderId sanitization", () => {
	it("rejects folderId values that can alter query semantics", async () => {
		const listFiles = vi.fn();
		vi.doMock("googleapis", () => ({
			google: {
				auth: { OAuth2: vi.fn().mockImplementation(() => ({ setCredentials: vi.fn() })) },
				drive: vi.fn().mockReturnValue({
					files: {
						list: listFiles,
					},
				}),
			},
		}));

		const { handleDrive } = await import("../../src/google-services/handlers/drive.js");
		const result = await handleDrive(
			{
				service: "drive",
				action: "list_files",
				params: { folderId: "root' or name contains 'secret" },
			},
			"mock-token",
		);

		expect(result.status).toBe("error");
		expect(result.error).toBe("Invalid folderId");
		expect(listFiles).not.toHaveBeenCalled();
	});

	it("accepts valid Drive IDs and uses a bounded query", async () => {
		const listFiles = vi.fn().mockResolvedValue({ data: { files: [] } });
		vi.doMock("googleapis", () => ({
			google: {
				auth: { OAuth2: vi.fn().mockImplementation(() => ({ setCredentials: vi.fn() })) },
				drive: vi.fn().mockReturnValue({
					files: {
						list: listFiles,
					},
				}),
			},
		}));

		const { handleDrive } = await import("../../src/google-services/handlers/drive.js");
		const result = await handleDrive(
			{
				service: "drive",
				action: "list_files",
				params: { folderId: "abc_DEF-123" },
			},
			"mock-token",
		);

		expect(result.status).toBe("ok");
		expect(listFiles).toHaveBeenCalledWith(
			expect.objectContaining({
				q: "'abc_DEF-123' in parents and trashed = false",
			}),
		);
	});
});

describe("Gmail draft header sanitization", () => {
	it("strips CRLF from header fields before RFC822 assembly", async () => {
		const createDraft = vi.fn().mockResolvedValue({ data: { id: "draft-1" } });
		vi.doMock("googleapis", () => ({
			google: {
				auth: { OAuth2: vi.fn().mockImplementation(() => ({ setCredentials: vi.fn() })) },
				gmail: vi.fn().mockReturnValue({
					users: {
						drafts: {
							create: createDraft,
						},
					},
				}),
			},
		}));

		const { handleGmail } = await import("../../src/google-services/handlers/gmail.js");
		const result = await handleGmail(
			{
				service: "gmail",
				action: "create_draft",
				params: {
					to: "user@example.com\r\nBcc:attacker@evil.com",
					subject: "Hello\r\nX-Injected: yes",
					cc: "team@example.com\r\nCc:extra@evil.com",
					body: "Body",
				},
			},
			"mock-token",
		);

		expect(result.status).toBe("ok");
		expect(createDraft).toHaveBeenCalledTimes(1);

		const raw = createDraft.mock.calls[0]?.[0]?.requestBody?.message?.raw as string;
		const decoded = Buffer.from(raw, "base64url").toString("utf-8");
		const headerLines = decoded.split("\r\n\r\n")[0].split("\r\n");

		expect(headerLines).toContain("To: user@example.com Bcc:attacker@evil.com");
		expect(headerLines).toContain("Subject: Hello X-Injected: yes");
		expect(headerLines).toContain("Cc: team@example.com Cc:extra@evil.com");
		expect(headerLines.some((line) => line.startsWith("Bcc:"))).toBe(false);
		expect(headerLines.some((line) => line.startsWith("X-Injected:"))).toBe(false);
	});

	it("rejects empty required headers after sanitization", async () => {
		const createDraft = vi.fn().mockResolvedValue({ data: { id: "draft-1" } });
		vi.doMock("googleapis", () => ({
			google: {
				auth: { OAuth2: vi.fn().mockImplementation(() => ({ setCredentials: vi.fn() })) },
				gmail: vi.fn().mockReturnValue({
					users: {
						drafts: {
							create: createDraft,
						},
					},
				}),
			},
		}));

		const { handleGmail } = await import("../../src/google-services/handlers/gmail.js");
		const result = await handleGmail(
			{
				service: "gmail",
				action: "create_draft",
				params: {
					to: "\r\n",
					subject: "   ",
					body: "Body",
				},
			},
			"mock-token",
		);

		expect(result.status).toBe("error");
		expect(result.error).toBe("Invalid draft headers");
		expect(createDraft).not.toHaveBeenCalled();
	});
});
