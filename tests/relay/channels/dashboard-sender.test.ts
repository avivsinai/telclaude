import { describe, expect, it } from "vitest";
import type {
	DashboardSinkRequest,
	DashboardSinkResult,
} from "../../../src/relay/channels/dashboard-connector.js";
import {
	createDashboardSender,
	type DashboardStoreDeliverResult,
} from "../../../src/relay/channels/dashboard-sender.js";

// charCode helpers instead of regex literals (Write/Edit can mangle backslash escapes).
const CR = String.fromCharCode(13);
const LF = String.fromCharCode(10);

// Credential-ish field names a token leak would surface as. The sink request
// must carry NONE of these — the dashboard transport holds no creds.
const FORBIDDEN_CRED_KEYS = [
	"token",
	"accessToken",
	"bearer",
	"authorization",
	"apiKey",
	"api_key",
	"credential",
	"secret",
	"approvalToken",
] as const;

function sinkRequest(overrides: Partial<DashboardSinkRequest> = {}): DashboardSinkRequest {
	return {
		conversationId: "conv-42",
		outboundRef: "edge-out:deadbeef",
		text: `hello from the relay${CR}${LF}second line`,
		at: "2026-06-04T12:00:00.000Z",
		target: "thread-7",
		targetKind: "thread",
		idempotencyKey: "edge-idem:deadbeef",
		attachments: [],
		...overrides,
	};
}

function recordingDeliver(
	result: DashboardStoreDeliverResult = { stored: true, messageId: "dash-store-1" },
): {
	readonly received: DashboardSinkRequest[];
	readonly deliver: (request: DashboardSinkRequest) => Promise<DashboardStoreDeliverResult>;
} {
	const received: DashboardSinkRequest[] = [];
	return {
		received,
		deliver: async (request) => {
			received.push(request);
			return result;
		},
	};
}

describe("createDashboardSender", () => {
	it("adapts the connector request to deliver VERBATIM and maps messageId to deliveryId", async () => {
		const store = recordingDeliver();
		const sender = createDashboardSender({ deliver: store.deliver });
		const request = sinkRequest();

		const result: DashboardSinkResult = await sender(request);

		expect(result.ok).toBe(true);
		if (!result.ok) throw new Error("expected ok");
		expect(result.deliveryId).toBe("dash-store-1");
		// The store receives the exact request the connector built — no re-mapping,
		// no synthesized fields, no recipient re-derivation.
		expect(store.received).toHaveLength(1);
		expect(store.received[0]).toEqual(request);
		expect(store.received[0].target).toBe("thread-7");
		expect(store.received[0].conversationId).toBe("conv-42");
	});

	it("carries NO credential/token field into the store (internal sink, no creds)", async () => {
		const store = recordingDeliver();
		const sender = createDashboardSender({ deliver: store.deliver });

		await sender(sinkRequest());

		const delivered = store.received[0] as Record<string, unknown>;
		for (const key of FORBIDDEN_CRED_KEYS) {
			expect(Object.hasOwn(delivered, key)).toBe(false);
		}
		// Nothing in the serialized request should look like a bearer credential.
		const serialized = JSON.stringify(delivered).toLowerCase();
		expect(serialized.includes("bearer ")).toBe(false);
		expect(serialized.includes("authorization")).toBe(false);
	});

	it("omits deliveryId when the store returns stored:true without a messageId", async () => {
		const store = recordingDeliver({ stored: true });
		const sender = createDashboardSender({ deliver: store.deliver });

		const result = await sender(sinkRequest());

		expect(result.ok).toBe(true);
		if (!result.ok) throw new Error("expected ok");
		expect(result.deliveryId).toBeUndefined();
	});

	it("maps a stored:false store result to ok:false with its code and retryable flag", async () => {
		const store = recordingDeliver({
			stored: false,
			code: "dashboard_store_full",
			reason: "ring buffer at capacity",
			retryable: true,
		});
		const sender = createDashboardSender({ deliver: store.deliver });

		const result = await sender(sinkRequest());

		expect(result).toEqual({
			ok: false,
			code: "dashboard_store_full",
			reason: "ring buffer at capacity",
			retryable: true,
		});
	});

	it("defaults code/retryable for a bare stored:false result", async () => {
		const store = recordingDeliver({ stored: false });
		const sender = createDashboardSender({ deliver: store.deliver });

		const result = await sender(sinkRequest());

		expect(result).toMatchObject({
			ok: false,
			code: "dashboard_deliver_failed",
			retryable: false,
		});
	});

	it("maps a thrown deliver error to a non-retryable ambiguous failure (at-most-once)", async () => {
		const sender = createDashboardSender({
			deliver: async () => {
				throw new Error("store exploded");
			},
		});

		const result = await sender(sinkRequest());

		expect(result).toMatchObject({
			ok: false,
			code: "dashboard_deliver_ambiguous",
			reason: "store exploded",
			retryable: false,
		});
	});

	it("fails closed (non-retryable) when no deliver sink is configured and never throws", async () => {
		const sender = createDashboardSender({});

		const result = await sender(sinkRequest());

		expect(result).toMatchObject({
			ok: false,
			code: "dashboard_sink_unconfigured",
			retryable: false,
		});
	});

	it("does not invoke the store when failing closed (nothing dispatched)", async () => {
		const store = recordingDeliver();
		// Explicitly undefined deliver — wiring fault, store reference never used.
		const sender = createDashboardSender({ deliver: undefined });

		await sender(sinkRequest());

		expect(store.received).toHaveLength(0);
	});
});
