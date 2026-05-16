import { describe, expect, it } from "vitest";
import {
	assertWebhookSecret,
	createWebhookSignatureHeader,
	verifyWebhookSignature,
} from "../../src/webhooks/auth.js";
import { ipAllowedByCidrs, validateAllowedCidrs } from "../../src/webhooks/cidr.js";

const SECRET = "0123456789abcdef0123456789abcdef";

describe("webhook auth", () => {
	it("accepts HMAC-SHA256 over timestamp and raw body bytes", () => {
		const rawBody = Buffer.from('{"hello":"world"}');
		const header = createWebhookSignatureHeader({
			secret: SECRET,
			rawBody,
			timestampSeconds: 1_700_000_000,
		});

		const result = verifyWebhookSignature({
			header,
			secret: SECRET,
			rawBody,
			nowMs: 1_700_000_010_000,
		});

		expect(result.ok).toBe(true);
		expect(result.signatureValid).toBe(true);
		expect(result.timestampDeltaSeconds).toBe(10);
	});

	it("rejects body tampering even when JSON would parse to similar data", () => {
		const rawBody = Buffer.from('{"a":1}');
		const header = createWebhookSignatureHeader({
			secret: SECRET,
			rawBody,
			timestampSeconds: 1_700_000_000,
		});

		const result = verifyWebhookSignature({
			header,
			secret: SECRET,
			rawBody: Buffer.from('{"a": 1}'),
			nowMs: 1_700_000_000_000,
		});

		expect(result.ok).toBe(false);
		expect(result.failureReason).toBe("signature_mismatch");
	});

	it("rejects stale timestamps after validating the HMAC", () => {
		const rawBody = Buffer.from("ok");
		const header = createWebhookSignatureHeader({
			secret: SECRET,
			rawBody,
			timestampSeconds: 1_700_000_000,
		});

		const result = verifyWebhookSignature({
			header,
			secret: SECRET,
			rawBody,
			nowMs: 1_700_001_000_000,
		});

		expect(result.ok).toBe(false);
		expect(result.signatureValid).toBe(true);
		expect(result.failureReason).toBe("timestamp_out_of_range");
	});

	it("requires secrets with at least 32 bytes", () => {
		expect(() => assertWebhookSecret("too-short")).toThrow(/at least 32 bytes/);
	});
});

describe("webhook CIDR allowlist", () => {
	it("matches IPv4 CIDRs and normalizes mapped IPv6 loopback", () => {
		expect(validateAllowedCidrs(["127.0.0.0/8"])).toEqual(["127.0.0.0/8"]);
		expect(ipAllowedByCidrs("127.0.0.1", ["127.0.0.0/8"])).toBe(true);
		expect(ipAllowedByCidrs("::ffff:127.0.0.1", ["127.0.0.0/8"])).toBe(true);
		expect(ipAllowedByCidrs("10.0.0.1", ["127.0.0.0/8"])).toBe(false);
	});

	it("fails closed on invalid addresses", () => {
		expect(ipAllowedByCidrs("not-an-ip", ["127.0.0.0/8"])).toBe(false);
		expect(() => validateAllowedCidrs(["not-a-cidr"])).toThrow(/invalid CIDR/);
	});
});
