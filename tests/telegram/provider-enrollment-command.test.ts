import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const startProviderSessionEnrollmentMock = vi.hoisted(() => vi.fn());
const pollProviderSessionEnrollmentMock = vi.hoisted(() => vi.fn());
const isAdminMock = vi.hoisted(() => vi.fn(() => true));
const getIdentityLinkMock = vi.hoisted(() =>
	vi.fn(() => ({ chatId: 123, localUserId: "admin", linkedAt: Date.now(), linkedBy: "test" })),
);
const getTOTPSessionForChatMock = vi.hoisted(() =>
	vi.fn(() => ({ localUserId: "admin", verifiedAt: Date.now(), expiresAt: Date.now() + 60_000 })),
);
const freshStepUpVerifyMock = vi.hoisted(() => vi.fn(() => ({ ok: true, metadata: {} })));

vi.mock("../../src/relay/provider-enrollment.js", () => ({
	startProviderSessionEnrollment: startProviderSessionEnrollmentMock,
	pollProviderSessionEnrollment: pollProviderSessionEnrollmentMock,
}));

vi.mock("../../src/security/linking.js", () => ({
	getIdentityLink: getIdentityLinkMock,
	isAdmin: isAdminMock,
}));

vi.mock("../../src/security/totp-session.js", () => ({
	getTOTPSessionForChat: getTOTPSessionForChatMock,
	stepUpMetadataForTOTPSession: vi.fn((input) => ({
		method: "totp",
		actorId: input.actorId,
		verifiedAtMs: input.session.verifiedAt,
		expiresAtMs: input.session.expiresAt,
	})),
	freshTotpStepUpVerification: {
		verify: freshStepUpVerifyMock,
	},
}));

import { startProviderSessionEnrollmentCommand } from "../../src/telegram/control-command-actions.js";

function makeApi() {
	return {
		sendMessage: vi.fn(async () => ({ message_id: 1 })),
		editMessageReplyMarkup: vi.fn(async () => {}),
	};
}

async function waitFor(condition: () => boolean): Promise<void> {
	for (let i = 0; i < 50; i++) {
		if (condition()) return;
		await new Promise((resolve) => setTimeout(resolve, 5));
	}
	throw new Error("Timed out waiting for condition");
}

describe("provider enrollment Telegram command", () => {
	beforeEach(() => {
		vi.clearAllMocks();
		isAdminMock.mockReturnValue(true);
		getIdentityLinkMock.mockReturnValue({
			chatId: 123,
			localUserId: "admin",
			linkedAt: Date.now(),
			linkedBy: "test",
		});
		getTOTPSessionForChatMock.mockReturnValue({
			localUserId: "admin",
			verifiedAt: Date.now(),
			expiresAt: Date.now() + 60_000,
		});
		freshStepUpVerifyMock.mockReturnValue({ ok: true, metadata: {} });
		startProviderSessionEnrollmentMock.mockResolvedValue({
			status: "enroll_pending",
			enrollmentId: "enr_123",
			interactUrl: "https://novnc.test/?token=single-use",
			expiresAt: Date.now() + 60_000,
			pollPath: "/v1/credentials/enroll-session/enr_123",
		});
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("renders the one-time browser URL only in Telegram and starts no durable state", async () => {
		const api = makeApi();

		await startProviderSessionEnrollmentCommand(api as never, {
			chatId: 123,
			threadId: 9,
			service: "clalit",
			actorUserId: "453371121",
			subjectUserId: "admin",
			poll: false,
		});

		expect(startProviderSessionEnrollmentMock).toHaveBeenCalledWith({
			service: "clalit",
			actorUserId: "453371121",
			subjectUserId: "admin",
		});
		expect(api.sendMessage).toHaveBeenCalledWith(
			123,
			expect.stringContaining("Secure enrollment started for clalit."),
			expect.objectContaining({
				message_thread_id: 9,
				reply_markup: {
					inline_keyboard: [
						[{ text: "Open secure browser", url: "https://novnc.test/?token=single-use" }],
					],
				},
			}),
		);
		expect(pollProviderSessionEnrollmentMock).not.toHaveBeenCalled();
	});

	it("resolves the enrollment subject from the linked chat when omitted", async () => {
		const api = makeApi();
		getIdentityLinkMock.mockReturnValue({
			chatId: 123,
			localUserId: "william",
			linkedAt: Date.now(),
			linkedBy: "test",
		});

		await startProviderSessionEnrollmentCommand(api as never, {
			chatId: 123,
			service: "clalit",
			actorUserId: "453371121",
			poll: false,
		});

		expect(startProviderSessionEnrollmentMock).toHaveBeenCalledWith({
			service: "clalit",
			actorUserId: "453371121",
			subjectUserId: "william",
		});
	});

	it("requires fresh 2FA before opening the enrollment browser", async () => {
		const api = makeApi();
		freshStepUpVerifyMock.mockReturnValue({
			ok: false,
			code: "fresh_step_up_stale",
			reason: "too old",
			retryable: true,
		});

		await startProviderSessionEnrollmentCommand(api as never, {
			chatId: 123,
			threadId: 9,
			service: "clalit",
			actorUserId: "453371121",
			subjectUserId: "admin",
			poll: false,
		});

		expect(startProviderSessionEnrollmentMock).not.toHaveBeenCalled();
		expect(api.sendMessage).toHaveBeenCalledWith(
			123,
			expect.stringContaining("Fresh 2FA verification is required"),
			expect.objectContaining({ message_thread_id: 9 }),
		);
	});

	it("does not expose token-bearing provider start errors in Telegram", async () => {
		const api = makeApi();
		startProviderSessionEnrollmentMock.mockResolvedValueOnce({
			status: "error",
			error: "Open https://novnc.test/vnc.html?token=single-use-secret to continue enrollment",
		});

		await startProviderSessionEnrollmentCommand(api as never, {
			chatId: 123,
			threadId: 9,
			service: "clalit",
			actorUserId: "453371121",
			subjectUserId: "admin",
			poll: false,
		});

		const serializedMessages = JSON.stringify(api.sendMessage.mock.calls);
		expect(serializedMessages).not.toContain("single-use-secret");
		expect(serializedMessages).not.toContain("novnc.test");
		expect(api.sendMessage).toHaveBeenLastCalledWith(
			123,
			expect.stringContaining("Check provider status and relay logs."),
			expect.objectContaining({ message_thread_id: 9 }),
		);
	});

	it("removes the browser URL button from the enrollment message after terminal status", async () => {
		const api = makeApi();
		api.sendMessage.mockResolvedValueOnce({ message_id: 44 });
		pollProviderSessionEnrollmentMock.mockResolvedValueOnce({
			status: "ok",
			summary: {
				service: "clalit",
				owner: "admin",
				authorizedOperators: ["admin", "453371121"],
				credentialKeys: [],
				hasSession: true,
				updatedAt: "2026-06-14T09:00:00.000Z",
			},
		});

		await startProviderSessionEnrollmentCommand(api as never, {
			chatId: 123,
			threadId: 9,
			service: "clalit",
			actorUserId: "453371121",
			subjectUserId: "admin",
			poll: true,
			pollIntervalMs: 0,
		});

		await waitFor(() => api.editMessageReplyMarkup.mock.calls.length > 0);

		expect(api.editMessageReplyMarkup).toHaveBeenCalledWith(123, 44, {
			reply_markup: undefined,
		});
		expect(api.sendMessage).toHaveBeenLastCalledWith(
			123,
			expect.stringContaining("Enrollment complete for clalit."),
			expect.objectContaining({ message_thread_id: 9 }),
		);
	});

	it("does not expose token-bearing provider poll errors in Telegram", async () => {
		const api = makeApi();
		api.sendMessage.mockResolvedValueOnce({ message_id: 45 });
		pollProviderSessionEnrollmentMock.mockResolvedValueOnce({
			status: "error",
			error: "poll failed at https://operator.test/browser/session?auth_token=poll-secret",
		});

		await startProviderSessionEnrollmentCommand(api as never, {
			chatId: 123,
			threadId: 9,
			service: "clalit",
			actorUserId: "453371121",
			subjectUserId: "admin",
			poll: true,
			pollIntervalMs: 0,
		});

		await waitFor(() => api.editMessageReplyMarkup.mock.calls.length > 0);

		const serializedMessages = JSON.stringify(api.sendMessage.mock.calls);
		expect(serializedMessages).not.toContain("poll-secret");
		expect(serializedMessages).not.toContain("operator.test");
		expect(api.editMessageReplyMarkup).toHaveBeenCalledWith(123, 45, {
			reply_markup: undefined,
		});
		expect(api.sendMessage).toHaveBeenLastCalledWith(
			123,
			expect.stringContaining("Check provider status and relay logs."),
			expect.objectContaining({ message_thread_id: 9 }),
		);
	});

	it("clears the enrollment button and sanitizes Telegram text when polling throws", async () => {
		const api = makeApi();
		api.sendMessage.mockResolvedValueOnce({ message_id: 46 });
		pollProviderSessionEnrollmentMock.mockRejectedValueOnce(
			new Error("sidecar leaked https://novnc.test/vnc.html?token=throw-secret"),
		);

		await startProviderSessionEnrollmentCommand(api as never, {
			chatId: 123,
			threadId: 9,
			service: "clalit",
			actorUserId: "453371121",
			subjectUserId: "admin",
			poll: true,
			pollIntervalMs: 0,
		});

		await waitFor(() => api.editMessageReplyMarkup.mock.calls.length > 0);

		const serializedMessages = JSON.stringify(api.sendMessage.mock.calls);
		const terminalMessage = api.sendMessage.mock.calls.at(-1)?.[1];
		expect(serializedMessages).not.toContain("throw-secret");
		expect(terminalMessage).not.toContain("novnc.test");
		expect(api.editMessageReplyMarkup).toHaveBeenCalledWith(123, 46, {
			reply_markup: undefined,
		});
		expect(api.sendMessage).toHaveBeenLastCalledWith(
			123,
			expect.stringContaining("Check provider status and relay logs."),
			expect.objectContaining({ message_thread_id: 9 }),
		);
	});
});
