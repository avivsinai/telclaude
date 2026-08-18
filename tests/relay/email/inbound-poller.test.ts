import { describe, expect, it } from "vitest";
import type { NormalizedInbound } from "../../../src/relay/edge-channel-connector.js";
import {
	createEmailInboundPoller,
	EMAIL_INBOUND_RISK_WRAP_REQUIRED,
	normalizeInboundEmail,
	type RawInboundEmail,
} from "../../../src/relay/email/inbound-poller.js";

const rawEmail = (overrides: Partial<RawInboundEmail> = {}): RawInboundEmail => ({
	messageId: "<m1@x.test>",
	fromAddress: "alice@example.test",
	cursor: "12345",
	receivedAtMs: 1_717_459_200_000,
	...overrides,
});

describe("email inbound poller (fail-closed until CL-1)", () => {
	it("throws from startListener — inbound stays dark and cannot reach edge.ingest", async () => {
		const poller = createEmailInboundPoller();
		let called = false;
		const sink = async (_: NormalizedInbound) => {
			called = true;
		};
		await expect(poller.startListener(sink)).rejects.toThrow(EMAIL_INBOUND_RISK_WRAP_REQUIRED);
		// The sink must never be invoked: no inbound email reaches the pipeline.
		expect(called).toBe(false);
	});

	it("normalizes a fetched email to the channel-agnostic inbound shape, releasing no bytes", () => {
		const out = normalizeInboundEmail(rawEmail({ inReplyTo: "<root@x.test>", text: "hello" }));
		expect(out).toEqual({
			channel: "email",
			senderPrincipalId: "alice@example.test",
			conversationKey: "alice@example.test",
			inReplyToTransportId: "<root@x.test>",
			text: "hello",
			attachmentRefs: [],
			transportMessageId: "<m1@x.test>",
			transportCursor: "12345",
			receivedAtMs: 1_717_459_200_000,
		});
	});

	it("omits optional fields when absent (no undefined In-Reply-To/text leakage)", () => {
		const out = normalizeInboundEmail(rawEmail());
		expect("inReplyToTransportId" in out).toBe(false);
		expect("text" in out).toBe(false);
		expect(out.attachmentRefs).toEqual([]);
	});
});
