import { describe, expect, it, vi } from "vitest";
import {
	forwardWhatsAppInboundWithRetry,
	type WhatsAppInboundForwardRetryInfo,
} from "../../src/whatsapp-bridge/relay-forward.js";

describe("WhatsApp inbound relay forwarding", () => {
	it("retries network failures with the same signed body until accepted", async () => {
		const outcomes: Array<Error | Response> = [
			new TypeError("fetch failed"),
			new TypeError("fetch failed"),
			new Response(null, { status: 202 }),
		];
		const calls: RequestInit[] = [];
		const fetchImpl = vi.fn(
			async (_input: Parameters<typeof fetch>[0], init?: RequestInit): Promise<Response> => {
				if (init) calls.push(init);
				const outcome = outcomes.shift();
				if (!outcome) throw new Error("unexpected extra fetch");
				if (outcome instanceof Error) throw outcome;
				return outcome;
			},
		);
		const onRetry = vi.fn<(info: WhatsAppInboundForwardRetryInfo) => void>();

		const response = await forwardWhatsAppInboundWithRetry(
			"http://telclaude:8790/v1/whatsapp/inbound",
			{ method: "POST", body: "SIGNED_BODY", headers: { signature: "SIGNED" } },
			{
				fetchImpl: fetchImpl as typeof fetch,
				timeoutMs: 1_000,
				baseDelayMs: 0,
				maxDelayMs: 0,
				jitter: 0,
				onRetry,
			},
		);

		expect(response.status).toBe(202);
		expect(fetchImpl).toHaveBeenCalledTimes(3);
		expect(calls.map((call) => call.body)).toEqual(["SIGNED_BODY", "SIGNED_BODY", "SIGNED_BODY"]);
		expect(onRetry).toHaveBeenNthCalledWith(1, { attempt: 1, delayMs: 0 });
		expect(onRetry).toHaveBeenNthCalledWith(2, { attempt: 2, delayMs: 0 });
	});

	it("retries transient relay statuses but returns client failures", async () => {
		const retryFetch = vi
			.fn<Parameters<typeof fetch>, ReturnType<typeof fetch>>()
			.mockResolvedValueOnce(new Response(null, { status: 503 }))
			.mockResolvedValueOnce(new Response(null, { status: 202 }));
		const onRetry = vi.fn<(info: WhatsAppInboundForwardRetryInfo) => void>();

		await expect(
			forwardWhatsAppInboundWithRetry(
				"http://telclaude:8790/v1/whatsapp/inbound",
				{ method: "POST", body: "SIGNED_BODY" },
				{
					fetchImpl: retryFetch,
					timeoutMs: 1_000,
					baseDelayMs: 0,
					maxDelayMs: 0,
					jitter: 0,
					onRetry,
				},
			),
		).resolves.toMatchObject({ status: 202 });
		expect(onRetry).toHaveBeenCalledWith({ attempt: 1, delayMs: 0, status: 503 });

		const clientFailure = vi
			.fn<Parameters<typeof fetch>, ReturnType<typeof fetch>>()
			.mockResolvedValue(new Response(null, { status: 400 }));
		const response = await forwardWhatsAppInboundWithRetry(
			"http://telclaude:8790/v1/whatsapp/inbound",
			{ method: "POST", body: "SIGNED_BODY" },
			{ fetchImpl: clientFailure, timeoutMs: 1_000, baseDelayMs: 0, maxDelayMs: 0, jitter: 0 },
		);

		expect(response.status).toBe(400);
		expect(clientFailure).toHaveBeenCalledTimes(1);
	});

	it("stops retrying when the bridge is shutting down", async () => {
		const controller = new AbortController();
		const fetchImpl = vi.fn<Parameters<typeof fetch>, ReturnType<typeof fetch>>();
		fetchImpl.mockImplementation(async () => {
			controller.abort();
			throw new TypeError("fetch failed");
		});

		await expect(
			forwardWhatsAppInboundWithRetry(
				"http://telclaude:8790/v1/whatsapp/inbound",
				{ method: "POST", body: "SIGNED_BODY" },
				{
					fetchImpl,
					timeoutMs: 1_000,
					signal: controller.signal,
					baseDelayMs: 0,
					maxDelayMs: 0,
					jitter: 0,
				},
			),
		).rejects.toMatchObject({ name: "AbortError" });
		expect(fetchImpl).toHaveBeenCalledTimes(1);
	});
});
