import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
	createGmailEmailTransport,
	type GmailApprovalTokenSigner,
	type GmailSidecarProviderCall,
} from "../../../src/relay/email/gmail-transport.js";
import type {
	EmailSendRequest,
	OutboundAuthorizationContext,
} from "../../../src/relay/email/transport.js";
import type { ProviderProxyResponse } from "../../../src/relay/provider-proxy.js";

const AUTH: OutboundAuthorizationContext = {
	actorUserId: "telegram:42",
	outboundRef: "edge-out:abc",
	sideEffectLedgerRef: "edge-ledger:abc",
	edgePreparedHash: "h".repeat(64),
};

function sendRequest(overrides: Partial<EmailSendRequest> = {}): EmailSendRequest {
	return {
		rawMime: "From: a@b.test\r\nTo: c@d.test\r\n\r\nhi",
		from: "a@b.test",
		to: ["c@d.test"],
		idempotencyKey: "idem:1",
		authorization: AUTH,
		...overrides,
	};
}

function expectedNonce(auth: OutboundAuthorizationContext): string {
	return createHash("sha256")
		.update(
			`edge-outbound-google-send:${auth.outboundRef}:${auth.sideEffectLedgerRef}:${auth.edgePreparedHash}`,
		)
		.digest("hex");
}

interface Recorder {
	// biome-ignore lint/suspicious/noExplicitAny: captured mock args
	tokenReqs: any[];
	// biome-ignore lint/suspicious/noExplicitAny: captured mock args
	providerReqs: any[];
}

function harness(
	providerResult: ProviderProxyResponse = { status: "ok", data: { id: "gmail-msg-1" } },
	tokenImpl?: () => Promise<string>,
) {
	const rec: Recorder = { tokenReqs: [], providerReqs: [] };
	const issueApprovalToken: GmailApprovalTokenSigner = async (req) => {
		rec.tokenReqs.push(req);
		return tokenImpl ? tokenImpl() : "v1.signed-token";
	};
	const callProvider: GmailSidecarProviderCall = async (req) => {
		rec.providerReqs.push(req);
		return providerResult;
	};
	const transport = createGmailEmailTransport({
		issueApprovalToken,
		callProvider,
	});
	return { rec, transport };
}

describe("gmail email transport", () => {
	it("mints a gmail.send token and delivers via the provider sidecar with that exact token", async () => {
		const { rec, transport } = harness();
		const result = await transport.send(sendRequest());

		expect(result).toEqual({ ok: true, platformMessageId: "gmail-msg-1" });

		const raw = Buffer.from(sendRequest().rawMime, "utf-8").toString("base64url");
		expect(rec.tokenReqs).toHaveLength(1);
		expect(rec.tokenReqs[0]).toEqual({
			service: "gmail",
			action: "send",
			params: { raw },
			actorUserId: "telegram:42",
			subjectUserId: null,
			approvalNonce: expectedNonce(AUTH),
		});

		expect(rec.providerReqs).toHaveLength(1);
		expect(rec.providerReqs[0]).toMatchObject({
			providerId: "google",
			path: "/v1/fetch",
			method: "POST",
			userId: "telegram:42",
			approvalToken: "v1.signed-token",
			approvalMode: "preapproved-ledger",
		});
	});

	it("binds the token params to the EXACT bytes sent (no paramsHash drift)", async () => {
		const { rec, transport } = harness();
		await transport.send(sendRequest());
		const tokenParams = rec.tokenReqs[0].params;
		const sentBody = JSON.parse(rec.providerReqs[0].body);
		// The params hashed into the token must be identical to the params the
		// sidecar receives, or its paramsHash check would reject the token.
		expect(sentBody).toEqual({ service: "gmail", action: "send", params: tokenParams });
	});

	it("never receives or forwards a raw credential — auth flows only through the minted token", async () => {
		const { rec, transport } = harness();
		await transport.send(sendRequest());
		const providerReq = rec.providerReqs[0];
		// The transport authorizes solely with the approval token + actor id; it
		// carries no bearer/secret/credential field of its own.
		expect(providerReq.approvalToken).toBe("v1.signed-token");
		expect(JSON.stringify(providerReq)).not.toMatch(
			/Bearer|access_token|client_secret|refresh_token/,
		);
	});

	it("fails closed without minting or calling the sidecar when the actor id is missing", async () => {
		const { rec, transport } = harness();
		const result = await transport.send(
			sendRequest({ authorization: { ...AUTH, actorUserId: "" } }),
		);
		expect(result).toMatchObject({
			ok: false,
			code: "missing_authorizing_actor",
			retryable: false,
		});
		expect(rec.tokenReqs).toHaveLength(0);
		expect(rec.providerReqs).toHaveLength(0);
	});

	it("surfaces a token-mint failure as retryable and does not call the sidecar", async () => {
		const { rec, transport } = harness({ status: "ok" }, async () => {
			throw new Error("vault unavailable");
		});
		const result = await transport.send(sendRequest());
		expect(result).toMatchObject({
			ok: false,
			code: "approval_token_unavailable",
			retryable: true,
		});
		expect(rec.providerReqs).toHaveLength(0);
	});

	it("maps a sidecar approval mismatch to a non-retryable failure", async () => {
		const { transport } = harness({
			status: "error",
			errorCode: "approval_mismatch",
			error: "Params hash mismatch",
		});
		const result = await transport.send(sendRequest());
		expect(result).toMatchObject({ ok: false, code: "approval_mismatch", retryable: false });
	});

	it("maps auth_expired to a non-retryable failure (needs human re-auth)", async () => {
		const { transport } = harness({ status: "error", errorCode: "auth_expired" });
		const result = await transport.send(sendRequest());
		expect(result).toMatchObject({ ok: false, code: "auth_expired", retryable: false });
	});

	it("makes even a transient sidecar error NON-retryable post-call (at-most-once, avoid duplicate)", async () => {
		// The request already reached the sidecar; a retry could duplicate a send
		// Gmail accepted. So no error result from the sidecar is retryable.
		const { transport } = harness({
			status: "error",
			errorCode: "degraded",
			error: "upstream 503",
		});
		const result = await transport.send(sendRequest());
		expect(result).toMatchObject({ ok: false, code: "degraded", retryable: false });
	});

	it("fails closed and non-retryable when the sidecar call itself throws (ambiguous: may have sent)", async () => {
		const rec: { providerReqs: number } = { providerReqs: 0 };
		const transport = createGmailEmailTransport({
			issueApprovalToken: async () => "v1.signed-token",
			callProvider: async () => {
				rec.providerReqs += 1;
				throw new Error("ECONNRESET");
			},
		});
		const result = await transport.send(sendRequest());
		expect(result).toMatchObject({ ok: false, code: "gmail_send_ambiguous", retryable: false });
		// The token was minted and the call was attempted exactly once.
		expect(rec.providerReqs).toBe(1);
	});
});
