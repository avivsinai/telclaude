import { describe, expect, it } from "vitest";
import {
	EdgeAdapterSchemaVersions,
	type PreparedOutbound,
	PreparedOutboundSchema,
} from "../../src/hermes/edge-adapter-contract.js";
import {
	createAttachmentQuarantineStore,
	QUARANTINE_MAX_BYTES,
} from "../../src/relay/attachment-quarantine-store.js";
import type {
	EdgeChannelConnector,
	OutboundDeliveryContext,
} from "../../src/relay/edge-channel-connector.js";
import { createEdgeOutboundExecutorRegistry } from "../../src/relay/edge-outbound-executor-registry.js";
import {
	createOutboundDeliveryDispatcher,
	type OutboundConversationContext,
} from "../../src/relay/outbound-delivery-dispatcher.js";

const HEX64 = "a".repeat(64);

function preparedOutbound(overrides: Partial<PreparedOutbound> = {}): PreparedOutbound {
	return PreparedOutboundSchema.parse({
		schemaVersion: EdgeAdapterSchemaVersions.preparedOutbound,
		outboundRef: "edge-out:deadbeef",
		channel: "email",
		resolvedDestination: {
			kind: "address",
			addressRef: "a@b.test",
			conversationId: "email:conv:1",
		},
		finalRenderedBody: "hello",
		mediaRefs: [],
		authorizingActor: {
			schemaVersion: EdgeAdapterSchemaVersions.actorRef,
			actorId: "relay:pairing-authority",
			channelIdentity: { channel: "email", principalId: "relay:pairing-authority" },
			identityAssurance: "strong_link",
			scopes: [],
			revocation: { revoked: false },
		},
		edgePreparedHash: HEX64,
		policyResult: { decision: "allowed", reason: "authorized" },
		approvalRequirement: { required: false },
		idempotencyKey: "edge-idem:deadbeef",
		sideEffectLedgerRef: "edge-ledger:deadbeef",
		createdAt: "2026-06-04T00:00:00.000Z",
		retryPolicy: { maxAttempts: 3, backoff: "exponential", deadLetterAfterAttempts: 5 },
		...overrides,
	});
}

function stubConnector(
	channel: EdgeChannelConnector["channel"],
	send: (
		ctx: OutboundDeliveryContext,
	) => Promise<Awaited<ReturnType<EdgeChannelConnector["send"]>>>,
): EdgeChannelConnector {
	return { channel, send };
}

const ctx = (
	conversationToken: string,
	threadMessageIds: readonly string[] = [],
): OutboundConversationContext => ({
	conversationToken,
	threadMessageIds,
});

describe("attachment quarantine store — owner binding", () => {
	it("releases bytes only to the conversation the attachment was authorized for", () => {
		const store = createAttachmentQuarantineStore();
		const ref = store.store({
			bytes: new TextEncoder().encode("secret"),
			mediaType: "text/plain",
			conversationToken: "conv_aaa",
			scanState: "clean",
		});
		expect(store.resolve(ref.quarantineId, { conversationToken: "conv_aaa" })?.mediaType).toBe(
			"text/plain",
		);
		// Cross-conversation read is denied (the core exfil guard).
		expect(store.resolve(ref.quarantineId, { conversationToken: "conv_bbb" })).toBeNull();
		// Unknown id → null, never throws.
		expect(store.resolve("tc-quarantine:nope", { conversationToken: "conv_aaa" })).toBeNull();
	});

	it("never releases un-scanned (non-clean) bytes", () => {
		const store = createAttachmentQuarantineStore();
		const ref = store.store({
			bytes: new Uint8Array([1, 2, 3]),
			mediaType: "image/png",
			conversationToken: "conv_aaa",
			// scanState defaults to "pending" (fail-closed)
		});
		expect(ref.scanState).toBe("pending");
		expect(store.resolve(ref.quarantineId, { conversationToken: "conv_aaa" })).toBeNull();
	});

	it("expires bytes after the TTL and cleanupExpired drops them", () => {
		let nowMs = 1000;
		const store = createAttachmentQuarantineStore({ now: () => nowMs });
		const ref = store.store({
			bytes: new Uint8Array([1]),
			mediaType: "text/plain",
			conversationToken: "conv_aaa",
			scanState: "clean",
			ttlMs: 50,
		});
		expect(store.resolve(ref.quarantineId, { conversationToken: "conv_aaa" })).not.toBeNull();
		nowMs += 51;
		expect(store.resolve(ref.quarantineId, { conversationToken: "conv_aaa" })).toBeNull();
		expect(store.cleanupExpired()).toBe(1);
		expect(store.inspect(ref.quarantineId)).toBeNull();
	});

	it("rejects bytes over the 25 MiB cap", () => {
		const store = createAttachmentQuarantineStore();
		expect(() =>
			store.store({
				bytes: new Uint8Array(QUARANTINE_MAX_BYTES + 1),
				mediaType: "application/octet-stream",
				conversationToken: "conv_aaa",
			}),
		).toThrow(/exceeds cap/);
	});

	it("recomputes the content hash over the stored bytes", () => {
		const store = createAttachmentQuarantineStore();
		const ref = store.store({
			bytes: new TextEncoder().encode("abc"),
			mediaType: "text/plain",
			conversationToken: "conv_aaa",
			scanState: "clean",
		});
		// sha256("abc")
		expect(ref.contentHash).toBe(
			"sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		);
	});

	it("mutating the ref returned by store() cannot make pending/cross-conv bytes resolvable", () => {
		const store = createAttachmentQuarantineStore();
		const ref = store.store({
			bytes: new TextEncoder().encode("secret"),
			mediaType: "text/plain",
			conversationToken: "conv_aaa",
			scanState: "pending", // not resolvable
		});
		// Attempt the in-process bypass: flip scan/lifecycle and inject another conversation.
		const tamper = ref as {
			scanState: string;
			lifecycle: { state: string; authorizedFor: string[] };
		};
		try {
			tamper.scanState = "clean";
			tamper.lifecycle.state = "authorized";
			tamper.lifecycle.authorizedFor.push("conv_bbb");
		} catch {
			// frozen clones may throw in strict mode — either way the store is unaffected.
		}
		// The store's private authority is unchanged: still pending, still conv_aaa-only.
		expect(store.resolve(ref.quarantineId, { conversationToken: "conv_aaa" })).toBeNull();
		expect(store.resolve(ref.quarantineId, { conversationToken: "conv_bbb" })).toBeNull();
	});

	it("mutating inspect() output cannot change a resolve() decision", () => {
		const store = createAttachmentQuarantineStore();
		const ref = store.store({
			bytes: new TextEncoder().encode("secret"),
			mediaType: "text/plain",
			conversationToken: "conv_aaa",
			scanState: "clean",
		});
		const view = store.inspect(ref.quarantineId);
		expect(view).not.toBeNull();
		const tamper = view as unknown as { lifecycle: { authorizedFor: string[] } };
		try {
			tamper.lifecycle.authorizedFor.push("conv_bbb");
		} catch {
			// ignore
		}
		// conv_bbb still cannot read; conv_aaa still can.
		expect(store.resolve(ref.quarantineId, { conversationToken: "conv_bbb" })).toBeNull();
		expect(store.resolve(ref.quarantineId, { conversationToken: "conv_aaa" })).not.toBeNull();
	});

	it("mutating the caller's input buffer after store() does not alter quarantined bytes", () => {
		const store = createAttachmentQuarantineStore();
		const buf = new Uint8Array([1, 2, 3]);
		const ref = store.store({
			bytes: buf,
			mediaType: "application/octet-stream",
			conversationToken: "conv_aaa",
			scanState: "clean",
		});
		buf[0] = 99; // mutate after store
		const resolved = store.resolve(ref.quarantineId, { conversationToken: "conv_aaa" });
		expect(resolved?.bytes[0]).toBe(1);
	});
});

describe("outbound delivery dispatcher", () => {
	const quarantineStore = createAttachmentQuarantineStore();

	function build(
		connector: EdgeChannelConnector | null,
		resolveConversation: () => Promise<OutboundConversationContext | null>,
	) {
		const registry = createEdgeOutboundExecutorRegistry(connector ? [connector] : []);
		return createOutboundDeliveryDispatcher({
			registry,
			resolveConversation,
			quarantineStore,
			now: () => 1717459200000,
		});
	}

	it("maps a successful send to a 'sent' receipt bound to the prepared idempotency key", async () => {
		const dispatch = build(
			stubConnector("email", async () => ({ ok: true, platformMessageId: "gmail-123" })),
			async () => ctx("conv_aaa"),
		);
		const receipt = await dispatch(preparedOutbound());
		expect(receipt.deliveryStatus).toBe("sent");
		expect(receipt.platformMessageId).toBe("gmail-123");
		expect(receipt.outboundRef).toBe("edge-out:deadbeef");
		expect(receipt.retry.idempotencyKey).toBe("edge-idem:deadbeef");
		expect(receipt.retry.maxAttempts).toBe(3);
		expect(receipt.timestamps.sentAt).toBeDefined();
		expect(receipt.timestamps.failedAt).toBeUndefined();
	});

	it("fails closed when no connector is registered for the channel", async () => {
		const dispatch = build(null, async () => ctx("conv_aaa"));
		const receipt = await dispatch(preparedOutbound());
		expect(receipt.deliveryStatus).toBe("failed");
		expect(receipt.timestamps.failedAt).toBeDefined();
	});

	it("fails closed when the conversation is no longer resolvable", async () => {
		const dispatch = build(
			stubConnector("email", async () => ({ ok: true })),
			async () => null,
		);
		expect((await dispatch(preparedOutbound())).deliveryStatus).toBe("failed");
	});

	it("fails closed when the connector reports a failure", async () => {
		const dispatch = build(
			stubConnector("email", async () => ({
				ok: false,
				code: "transport_unavailable",
				retryable: true,
			})),
			async () => ctx("conv_aaa"),
		);
		expect((await dispatch(preparedOutbound())).deliveryStatus).toBe("failed");
	});

	it("treats a throwing transport as a failed attempt, not a runtime crash", async () => {
		const dispatch = build(
			stubConnector("email", async () => {
				throw new Error("smtp exploded");
			}),
			async () => ctx("conv_aaa"),
		);
		expect((await dispatch(preparedOutbound())).deliveryStatus).toBe("failed");
	});

	function storedAttachment(conversationToken: string) {
		return quarantineStore.store({
			bytes: new TextEncoder().encode("att"),
			mediaType: "text/plain",
			conversationToken,
			scanState: "clean",
		});
	}

	async function resolveViaConnector(
		prepared: PreparedOutbound,
		conversationToken: string,
		quarantineId: string,
	): Promise<unknown> {
		let resolved: unknown = "unset";
		const dispatch = build(
			stubConnector("email", async (deliveryCtx) => {
				resolved = await deliveryCtx.resolveAttachment(quarantineId);
				return { ok: true };
			}),
			async () => ctx(conversationToken),
		);
		await dispatch(prepared);
		return resolved;
	}

	it("releases an attachment listed in this prepared outbound's mediaRefs", async () => {
		const ref = storedAttachment("conv_aaa");
		const resolved = await resolveViaConnector(
			preparedOutbound({ mediaRefs: [ref] }),
			"conv_aaa",
			ref.quarantineId,
		);
		expect(resolved).not.toBeNull();
	});

	it("does NOT release a same-conversation attachment not attached to this outbound", async () => {
		const ref = storedAttachment("conv_aaa");
		// preparedOutbound() default mediaRefs is [] — the attachment is not declared here.
		const resolved = await resolveViaConnector(preparedOutbound(), "conv_aaa", ref.quarantineId);
		expect(resolved).toBeNull();
	});

	it("fails closed when a listed ref's contentHash does not match the stored bytes", async () => {
		const ref = storedAttachment("conv_aaa");
		const tampered = { ...ref, contentHash: `sha256:${"b".repeat(64)}` };
		const resolved = await resolveViaConnector(
			preparedOutbound({ mediaRefs: [tampered] }),
			"conv_aaa",
			ref.quarantineId,
		);
		expect(resolved).toBeNull();
	});

	it("does NOT release a listed attachment when dispatched on a different conversation", async () => {
		const ref = storedAttachment("conv_aaa");
		// Even listed in mediaRefs, the store denies release for conv_bbb (owner-bound).
		const resolved = await resolveViaConnector(
			preparedOutbound({ mediaRefs: [ref] }),
			"conv_bbb",
			ref.quarantineId,
		);
		expect(resolved).toBeNull();
	});

	it("invokes onDelivered only on success", async () => {
		let delivered = 0;
		const okDispatch = createOutboundDeliveryDispatcher({
			registry: createEdgeOutboundExecutorRegistry([
				stubConnector("email", async () => ({ ok: true, observedThreadMessageId: "mid-1" })),
			]),
			resolveConversation: async () => ctx("conv_aaa"),
			quarantineStore,
			onDelivered: async () => {
				delivered += 1;
			},
		});
		await okDispatch(preparedOutbound());
		expect(delivered).toBe(1);
	});

	it("still returns a 'sent' receipt when onDelivered throws after a successful send", async () => {
		let reportedError: unknown = null;
		const dispatch = createOutboundDeliveryDispatcher({
			registry: createEdgeOutboundExecutorRegistry([
				stubConnector("email", async () => ({ ok: true, platformMessageId: "gmail-xyz" })),
			]),
			resolveConversation: async () => ctx("conv_aaa"),
			quarantineStore,
			now: () => 1717459200000,
			onDelivered: async () => {
				throw new Error("recordThreadMessageId failed");
			},
			onDeliveredError: (_p, _c, _o, error) => {
				reportedError = error;
			},
		});
		// The send already happened — a bookkeeping failure must not undo it.
		const receipt = await dispatch(preparedOutbound());
		expect(receipt.deliveryStatus).toBe("sent");
		expect(receipt.platformMessageId).toBe("gmail-xyz");
		expect(reportedError).toBeInstanceOf(Error);
	});
});

describe("edge outbound executor registry", () => {
	it("rejects a duplicate connector for the same channel", () => {
		const registry = createEdgeOutboundExecutorRegistry([
			stubConnector("email", async () => ({ ok: true })),
		]);
		expect(() => registry.register(stubConnector("email", async () => ({ ok: true })))).toThrow(
			/already registered/,
		);
		expect(registry.has("email")).toBe(true);
		expect(registry.channels()).toEqual(["email"]);
	});
});
