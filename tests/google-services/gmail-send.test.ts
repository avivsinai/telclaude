import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { getAction } from "../../src/google-services/actions.js";

/**
 * gmail.send is the outbound delivery action behind the relay's email transport.
 * The relay composes a CRLF-safe RFC822 message and base64url-encodes it; the
 * approval token's paramsHash binds the exact `raw`. The sidecar must:
 *  - reject anything that is not a non-empty base64url string,
 *  - bound the decoded size before the API call (availability),
 *  - send the bytes verbatim (no header re-parsing),
 * and make NO Gmail API call on a rejected input.
 */

// biome-ignore lint/suspicious/noExplicitAny: vitest mock spy
let sendSpy: any;

function mockGoogleapis(
	sendImpl: () => Promise<unknown> = async () => ({ data: { id: "sent-1", threadId: "t-1" } }),
): void {
	sendSpy = vi.fn(sendImpl);
	vi.doMock("googleapis", () => ({
		google: {
			auth: { OAuth2: vi.fn().mockImplementation(() => ({ setCredentials: vi.fn() })) },
			gmail: vi.fn().mockReturnValue({ users: { messages: { send: sendSpy } } }),
		},
	}));
}

async function send(raw: unknown) {
	const { handleGmail } = await import("../../src/google-services/handlers/gmail.js");
	return handleGmail({ service: "gmail", action: "send", params: { raw } }, "mock-token");
}

beforeEach(() => {
	vi.resetModules();
});
afterEach(() => {
	vi.doUnmock("googleapis");
});

describe("gmail.send action registration", () => {
	it("is an approval-gated action with the gmail.send scope and a required raw param", () => {
		const action = getAction("gmail", "send");
		expect(action).toBeDefined();
		expect(action?.type).toBe("action");
		expect(action?.scope).toBe("https://www.googleapis.com/auth/gmail.send");
		expect(action?.params.raw?.required).toBe(true);
	});
});

describe("handleGmail send", () => {
	it("sends the base64url raw verbatim and returns the platform id", async () => {
		mockGoogleapis();
		const raw = Buffer.from("From: a@b.test\r\nTo: c@d.test\r\n\r\nhi").toString("base64url");
		const result = await send(raw);
		expect(result.status).toBe("ok");
		expect(sendSpy).toHaveBeenCalledTimes(1);
		expect(sendSpy).toHaveBeenCalledWith({ userId: "me", requestBody: { raw } });
	});

	it("rejects an empty raw and makes no API call", async () => {
		mockGoogleapis();
		const result = await send("");
		expect(result.status).toBe("error");
		expect(result.error).toContain("base64url");
		expect(sendSpy).not.toHaveBeenCalled();
	});

	it("rejects a non-string raw and makes no API call", async () => {
		mockGoogleapis();
		const result = await send(undefined);
		expect(result.status).toBe("error");
		expect(sendSpy).not.toHaveBeenCalled();
	});

	it("rejects a raw containing non-base64url characters (whitespace/CRLF/+/=) — no API call", async () => {
		mockGoogleapis();
		for (const bad of ["has space", "a+b/c", "padded=", "line\r\nbreak"]) {
			const result = await send(bad);
			expect(result.status).toBe("error");
		}
		expect(sendSpy).not.toHaveBeenCalled();
	});

	it("rejects an impossible base64url length (len % 4 === 1) even when all chars are valid", async () => {
		mockGoogleapis();
		// "ABCDE" is all valid base64url chars but length 5 — no byte sequence
		// encodes to that length, so it must be rejected before the API call.
		const result = await send("ABCDE");
		expect(result.status).toBe("error");
		expect(result.error).toContain("base64url");
		expect(sendSpy).not.toHaveBeenCalled();
	});

	it("rejects an oversized message before the API call (availability guard)", async () => {
		mockGoogleapis();
		// > 25 MiB once decoded (raw.length * 3/4); all-'A' is valid base64url so the
		// failure is the size guard specifically, not the encoding check.
		const tooBig = "A".repeat(34_952_536);
		const result = await send(tooBig);
		expect(result.status).toBe("error");
		expect(result.error).toContain("send limit");
		expect(sendSpy).not.toHaveBeenCalled();
	});

	it("surfaces a Gmail API failure as an error response", async () => {
		mockGoogleapis(async () => {
			throw new Error("rate limit");
		});
		const raw = Buffer.from("From: a@b.test\r\n\r\nhi").toString("base64url");
		const result = await send(raw);
		expect(result.status).toBe("error");
	});
});
