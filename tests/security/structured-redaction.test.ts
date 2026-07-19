import { describe, expect, it } from "vitest";
import {
	isRelayActionRef,
	isRelayAttachmentRef,
	isRelayContainerId,
	redactStructuredSecrets,
} from "../../src/security/structured-redaction.js";

const OPAQUE_UUID = "550e8400-e29b-41d4-a716-123456782abc";
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

describe("structured secret redaction", () => {
	it("redacts strings by default, including opaque-looking identifiers", () => {
		expect(redactStructuredSecrets({ opaqueId: OPAQUE_UUID })).toEqual({
			opaqueId: "550e8400-e29b-41d4-a716-[REDACTED:israeli_id]abc",
		});
	});

	it("preserves an explicitly listed field only when its opaque grammar validates", () => {
		expect(
			redactStructuredSecrets(
				{ opaqueId: OPAQUE_UUID },
				{ opaqueFields: { opaqueId: (value) => UUID_PATTERN.test(value) } },
			),
		).toEqual({ opaqueId: OPAQUE_UUID });
	});

	it("still redacts a listed field when its value fails the opaque grammar", () => {
		expect(
			redactStructuredSecrets(
				{ opaqueId: "leaked identity 123456782" },
				{ opaqueFields: { opaqueId: (value) => UUID_PATTERN.test(value) } },
			),
		).toEqual({ opaqueId: "leaked identity [REDACTED:israeli_id]" });
	});

	it("accepts only the exact lowercase grammar minted by relay producers", () => {
		expect(isRelayActionRef(`effect-${OPAQUE_UUID}`)).toBe(true);
		expect(isRelayActionRef(`effect-${OPAQUE_UUID.toUpperCase()}`)).toBe(false);
		expect(isRelayActionRef(`effect-${OPAQUE_UUID.replace("-4", "-1")}`)).toBe(false);
		expect(isRelayAttachmentRef("att_0123abcd.1784419200.0123456789abcdef")).toBe(true);
		expect(isRelayAttachmentRef("att_0123ABCD.1784419200.0123456789abcdef")).toBe(false);
		expect(isRelayContainerId("a".repeat(64))).toBe(true);
		expect(isRelayContainerId("A".repeat(64))).toBe(false);
		expect(isRelayContainerId("a".repeat(63))).toBe(false);
	});
});
