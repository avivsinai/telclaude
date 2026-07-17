import { describe, expect, it, vi } from "vitest";
import type { ExternalProviderConfig } from "../../src/config/config.js";
import { createProviderChallengeSidecar } from "../../src/relay/provider-challenge-sidecar.js";

const provider = {
	id: "israel-services",
	baseUrl: "http://provider.internal:3001",
	services: ["clalit"],
} as ExternalProviderConfig;

describe("provider challenge sidecar transport", () => {
	it("signs the exact login body and captures only a bounded SMS challenge", async () => {
		const sign = vi.fn(async (input) => ({
			"x-relay-signature": `signed:${input.path}:${input.rawBody}`,
		}));
		const fetch = vi.fn(
			async () =>
				new Response(
					JSON.stringify({
						status: "challenge_pending",
						challenge: { id: "challenge-opaque", type: "otp_sms", service: "clalit" },
					}),
					{ status: 202, headers: { "content-type": "application/json" } },
				),
		);
		const sidecar = createProviderChallengeSidecar({
			provider,
			fetch,
			sign,
			validateUrl: async () => ({ url: new URL(provider.baseUrl), port: 3001 }),
		});

		await expect(
			sidecar.initiate({ actorUserId: "actor-a", subjectUserId: "household:parent-a" }),
		).resolves.toEqual({
			status: "challenge",
			challengeId: "challenge-opaque",
			challengeType: "sms_otp",
		});
		const body = JSON.stringify({
			service: "clalit",
			action: "home",
			params: {},
			subjectUserId: "household:parent-a",
		});
		expect(sign).toHaveBeenCalledWith({
			provider,
			method: "POST",
			path: "/v1/fetch",
			rawBody: body,
			actorUserId: "actor-a",
		});
		expect(fetch).toHaveBeenCalledWith(
			"http://provider.internal:3001/v1/fetch",
			expect.objectContaining({
				method: "POST",
				body,
				headers: expect.objectContaining({
					"x-actor-user-id": "actor-a",
					"x-relay-signature": `signed:/v1/fetch:${body}`,
				}),
			}),
		);
	});

	it("sends actor only in the signed header on challenge response", async () => {
		const sign = vi.fn(async () => ({ "x-relay-signature": "signed" }));
		const fetch = vi.fn(
			async () =>
				new Response(JSON.stringify({ status: "ok", data: {} }), {
					status: 200,
					headers: { "content-type": "application/json" },
				}),
		);
		const sidecar = createProviderChallengeSidecar({
			provider,
			fetch,
			sign,
			validateUrl: async () => ({ url: new URL(provider.baseUrl), port: 3001 }),
		});

		await expect(
			sidecar.respond({ actorUserId: "actor-a", challengeId: "challenge-opaque", code: "123456" }),
		).resolves.toEqual({ status: "success" });
		const body = JSON.stringify({
			service: "clalit",
			challengeId: "challenge-opaque",
			code: "123456",
		});
		expect(JSON.parse(body)).not.toHaveProperty("actorUserId");
		expect(sign).toHaveBeenCalledWith({
			provider,
			method: "POST",
			path: "/v1/challenge/respond",
			rawBody: body,
			actorUserId: "actor-a",
		});
		expect(fetch).toHaveBeenCalledWith(
			"http://provider.internal:3001/v1/challenge/respond",
			expect.objectContaining({
				body,
				headers: expect.objectContaining({ "x-actor-user-id": "actor-a" }),
			}),
		);
	});

	it("fails closed without exposing a secret-bearing sidecar response", async () => {
		const sidecar = createProviderChallengeSidecar({
			provider,
			validateUrl: async () => ({ url: new URL(provider.baseUrl), port: 3001 }),
			sign: async () => ({ "x-relay-signature": "signed" }),
			fetch: async () =>
				new Response(JSON.stringify({ status: "error", error: "secret 123456 at http://token" }), {
					status: 500,
					headers: { "content-type": "application/json" },
				}),
		});

		await expect(
			sidecar.respond({ actorUserId: "actor-a", challengeId: "challenge-opaque", code: "123456" }),
		).resolves.toEqual({ status: "error" });
		await expect(
			sidecar.initiate({ actorUserId: "actor-a", subjectUserId: "household:parent-a" }),
		).resolves.toEqual({ status: "error" });
	});

	it("does not treat a follow-up challenge as successful authentication", async () => {
		const sidecar = createProviderChallengeSidecar({
			provider,
			validateUrl: async () => ({ url: new URL(provider.baseUrl), port: 3001 }),
			sign: async () => ({ "x-relay-signature": "signed" }),
			fetch: async () =>
				new Response(
					JSON.stringify({
						status: "challenge_pending",
						challenge: { id: "captcha", type: "captcha", service: "clalit" },
					}),
					{ status: 202, headers: { "content-type": "application/json" } },
				),
		});

		await expect(
			sidecar.respond({ actorUserId: "actor-a", challengeId: "challenge-opaque", code: "123456" }),
		).resolves.toEqual({ status: "error" });
	});
});
