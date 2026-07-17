import crypto from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import {
	createPendingProviderChallengeRegistry,
	DEFAULT_PROVIDER_CHALLENGE_TTL_MS,
	type PendingProviderChallengeBindingEvidence,
} from "../../src/relay/pending-provider-challenge.js";

describe("pending provider challenge registry", () => {
	it("arms, replaces, caps TTL, expires, and cancels without exposing the challenge id", () => {
		let nowMs = 100_000;
		const block = vi.fn();
		const registry = createPendingProviderChallengeRegistry({
			nowMs: () => nowMs,
			makeRef: refs(),
			turnControl: {
				register: vi.fn(),
				block,
				isBlocked: vi.fn(),
				cleanup: vi.fn(),
				clear: vi.fn(),
			},
		});

		const first = registry.arm(armInput({ sidecarExpiresAtMs: nowMs + 500_000 }));
		expect(first).toEqual({
			ref: "provider_challenge_test_1",
			expiresAtMs: nowMs + DEFAULT_PROVIDER_CHALLENGE_TTL_MS,
			replaced: false,
		});
		expect(JSON.stringify(first)).not.toContain("synthetic-challenge-secret");
		expect(block).toHaveBeenCalledWith(`turn_${"a".repeat(32)}`, first.expiresAtMs);

		expect(registry.arm(armInput({ providerChallengeId: "replacement" }))).toMatchObject({
			replaced: true,
		});
		expect(registry.cancel("parent-a")).toBe(true);
		expect(registry.peekForInbound(binding())).toEqual({ status: "none" });

		registry.arm(armInput({ sidecarExpiresAtMs: 100_500 }));
		nowMs = 100_500;
		expect(registry.peekForInbound(binding())).toEqual({ status: "expired" });
	});

	it("claims atomically once and deletes before returning the secret-bearing claim", async () => {
		const registry = createPendingProviderChallengeRegistry({ nowMs: () => 100_000 });
		registry.arm(armInput());

		const [left, right] = await Promise.all([
			Promise.resolve().then(() => registry.claimForInbound(binding())),
			Promise.resolve().then(() => registry.claimForInbound(binding())),
		]);

		expect([left, right].filter((result) => result.ok)).toHaveLength(1);
		expect([left, right].filter((result) => !result.ok)).toEqual([{ ok: false, status: "none" }]);
		expect(registry.peekForInbound(binding())).toEqual({ status: "none" });
	});

	it.each([
		["actor", { actorId: "household:whatsapp:parent-b" }],
		["subject", { subjectUserId: "household:parent-b" }],
		["profile", { profileId: "parent-b" }],
		["conversation token", { conversationToken: `conv_${"b".repeat(32)}` }],
		["conversation id", { conversationId: "whatsapp:household:parent-b" }],
		["principal", { senderPrincipalHash: digest("whatsapp:+15550000002") }],
	] as const)("fails closed on %s drift and spends the suspect entry", (_name, mutation) => {
		const registry = createPendingProviderChallengeRegistry({ nowMs: () => 100_000 });
		registry.arm(armInput());

		expect(registry.claimForInbound(binding(mutation))).toEqual({
			ok: false,
			status: "binding_mismatch",
		});
		expect(registry.claimForInbound(binding())).toEqual({ ok: false, status: "none" });
	});

	it("keeps concurrent parent challenges isolated", async () => {
		const registry = createPendingProviderChallengeRegistry({ nowMs: () => 100_000 });
		const parentA = binding();
		const parentB = binding({
			bindingId: "parent-b",
			actorId: "household:whatsapp:parent-b",
			subjectUserId: "household:parent-b",
			profileId: "parent-b",
			conversationToken: `conv_${"b".repeat(32)}`,
			conversationId: "whatsapp:household:parent-b",
			senderPrincipalHash: digest("whatsapp:+15550000002"),
		});
		registry.arm(armInput({ binding: parentA }));
		registry.arm(
			armInput({
				binding: parentB,
				initiationRef: "provider_login_parent_b_12345678",
				initiatingTurnRef: `turn_${"b".repeat(32)}`,
				providerChallengeId: "synthetic-parent-b-secret",
			}),
		);

		const [claimedA, claimedB] = await Promise.all([
			Promise.resolve().then(() => registry.claimForInbound(parentA)),
			Promise.resolve().then(() => registry.claimForInbound(parentB)),
		]);

		expect(claimedA).toMatchObject({ ok: true, claim: { bindingId: "parent-a" } });
		expect(claimedB).toMatchObject({ ok: true, claim: { bindingId: "parent-b" } });
	});

	it("rejects non-coordinator, legacy challenge types, and already-expired arms", () => {
		const registry = createPendingProviderChallengeRegistry({ nowMs: () => 100_000 });

		expect(() =>
			registry.arm({ ...armInput(), origin: "agent" as "relay_login_coordinator" }),
		).toThrow("relay login coordinator");
		expect(() => registry.arm({ ...armInput(), challengeType: "otp_sms" as "sms_otp" })).toThrow(
			"canonical Clalit sms_otp",
		);
		expect(() => registry.arm(armInput({ sidecarExpiresAtMs: 100_000 }))).toThrow(
			"already expired",
		);
	});

	it("has no list or serialization surface", () => {
		const registry = createPendingProviderChallengeRegistry({ nowMs: () => 100_000 });
		registry.arm(armInput());

		expect(JSON.stringify(registry)).toBe("{}");
		expect(registry).not.toHaveProperty("list");
		expect(registry).not.toHaveProperty("get");
		expect(registry).not.toHaveProperty("getByChallengeId");
	});
});

function armInput(
	overrides: Partial<
		Parameters<ReturnType<typeof createPendingProviderChallengeRegistry>["arm"]>[0]
	> = {},
) {
	return {
		origin: "relay_login_coordinator" as const,
		initiationRef: "provider_login_parent_a_12345678",
		initiatingTurnRef: `turn_${"a".repeat(32)}`,
		binding: binding(),
		service: "clalit" as const,
		providerChallengeId: "synthetic-challenge-secret",
		challengeType: "sms_otp" as const,
		sidecarExpiresAtMs: 200_000,
		nowMs: 100_000,
		...overrides,
	};
}

function binding(
	overrides: Partial<PendingProviderChallengeBindingEvidence> = {},
): PendingProviderChallengeBindingEvidence {
	return {
		bindingId: "parent-a",
		actorId: "household:whatsapp:parent-a",
		subjectUserId: "household:parent-a",
		profileId: "parent-a",
		conversationToken: `conv_${"a".repeat(32)}`,
		conversationId: "whatsapp:household:parent-a",
		senderPrincipalHash: digest("whatsapp:+15550000001"),
		...overrides,
	};
}

function refs(): () => string {
	let next = 0;
	return () => `provider_challenge_test_${++next}`;
}

function digest(value: string): `sha256:${string}` {
	return `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
}
