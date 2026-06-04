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
import {
	createDefaultEdgeOutboundExecutorRegistry,
	createEdgeOutboundExecutorRegistry,
} from "../../src/relay/edge-outbound-executor-registry.js";
import {
	createOutboundDeliveryDispatcher,
	type OutboundConversationContext,
} from "../../src/relay/outbound-delivery-dispatcher.js";
import {
	createWhatsAppEdgeChannelConnector,
	digestWhatsAppSidecarSendRequest,
	WHATSAPP_INBOUND_RISK_WRAP_REQUIRED,
	WHATSAPP_SIDECAR_ALLOWED_HOST,
	WHATSAPP_SIDECAR_MAX_MEDIA_BYTES,
	WHATSAPP_SIDECAR_REQUEST_DIGEST_HEADER,
	WHATSAPP_SIDECAR_SESSION_EXPIRES_AT_HEADER,
	WHATSAPP_SIDECAR_SESSION_KEY_HEADER,
	type WhatsAppSidecarSendRequest,
} from "../../src/relay/whatsapp-edge-channel-connector.js";

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

	it("sends WhatsApp through the connector with resolvedDestination verbatim", async () => {
		const sent: WhatsAppSidecarSendRequest[] = [];
		const sessions: string[] = [];
		const resolvedDestination = {
			kind: "address" as const,
			addressRef: "whatsapp:+15551234567",
			conversationId: "relay-conversation-token",
		};
		const connector = createWhatsAppEdgeChannelConnector({
			now: () => 1717459200000,
			sendToSidecar: async (request, session) => {
				sent.push(request);
				sessions.push(session.requestDigest);
				return { ok: true, platformMessageId: "wa-msg-1", observedThreadMessageId: "wa-msg-1" };
			},
		});
		const dispatch = createOutboundDeliveryDispatcher({
			registry: createEdgeOutboundExecutorRegistry([connector]),
			resolveConversation: async () => ctx("relay-conversation-token", ["wa-thread-previous"]),
			quarantineStore,
			now: () => 1717459200000,
		});

		const receipt = await dispatch(
			preparedOutbound({
				channel: "whatsapp",
				resolvedDestination,
				finalRenderedBody: "On my way",
			}),
		);

		expect(receipt.deliveryStatus).toBe("sent");
		expect(sent).toEqual([
			expect.objectContaining({
				outboundRef: "edge-out:deadbeef",
				idempotencyKey: "edge-idem:deadbeef",
				destination: resolvedDestination,
				body: "On my way",
				threadMessageIds: ["wa-thread-previous"],
			}),
		]);
		expect(sessions).toEqual([
			digestWhatsAppSidecarSendRequest(sent[0] as WhatsAppSidecarSendRequest),
		]);
	});

	it("registers WhatsApp by default but fails closed without sidecar config", async () => {
		const failures: unknown[] = [];
		const registry = createDefaultEdgeOutboundExecutorRegistry({ whatsapp: {} });
		const dispatch = createOutboundDeliveryDispatcher({
			registry,
			resolveConversation: async () => ctx("relay-conversation-token"),
			quarantineStore,
			now: () => 1717459200000,
			onSendFailure: (_prepared, failure) => failures.push(failure),
		});

		const receipt = await dispatch(
			preparedOutbound({
				channel: "whatsapp",
				resolvedDestination: {
					kind: "address",
					addressRef: "whatsapp:+15551234567",
					conversationId: "relay-conversation-token",
				},
			}),
		);

		expect(registry.has("whatsapp")).toBe(true);
		expect(receipt.deliveryStatus).toBe("failed");
		expect(failures).toEqual([
			expect.objectContaining({
				code: "whatsapp_sidecar_unconfigured",
				retryable: false,
			}),
		]);
	});

	it("generates fresh bridge-session headers and keeps them out of the sidecar body", async () => {
		const seen: Array<{
			readonly url: string;
			readonly headers: Record<string, string>;
			readonly body: string;
		}> = [];
		const connector = createWhatsAppEdgeChannelConnector({
			sidecarUrl: "http://whatsapp-bridge:3004",
			now: () => 1717459200000,
			fetch: async (url, init) => {
				seen.push({
					url: url.toString(),
					headers: init.headers,
					body: init.body,
				});
				return {
					ok: true,
					status: 200,
					json: async () => ({ ok: true, platformMessageId: `wa-http-${seen.length}` }),
					text: async () => "",
				};
			},
		});
		const dispatch = createOutboundDeliveryDispatcher({
			registry: createEdgeOutboundExecutorRegistry([connector]),
			resolveConversation: async () => ctx("relay-conversation-token"),
			quarantineStore,
			now: () => 1717459200000,
		});

		const request = {
			channel: "whatsapp" as const,
			resolvedDestination: {
				kind: "address" as const,
				addressRef: "whatsapp:+15551234567",
				conversationId: "relay-conversation-token",
			},
		};
		const firstReceipt = await dispatch(
			preparedOutbound({
				...request,
				outboundRef: "edge-out:first",
				idempotencyKey: "edge-idem:first",
			}),
		);
		const secondReceipt = await dispatch(
			preparedOutbound({
				...request,
				outboundRef: "edge-out:second",
				idempotencyKey: "edge-idem:second",
			}),
		);

		expect(firstReceipt.deliveryStatus).toBe("sent");
		expect(secondReceipt.deliveryStatus).toBe("sent");
		expect(seen).toHaveLength(2);
		expect(seen[0]).toEqual(
			expect.objectContaining({
				url: "http://whatsapp-bridge:3004/v1/whatsapp/send",
				headers: expect.objectContaining({
					[WHATSAPP_SIDECAR_SESSION_KEY_HEADER]: expect.stringMatching(/^wa-session:/),
					[WHATSAPP_SIDECAR_REQUEST_DIGEST_HEADER]: digestWhatsAppSidecarSendRequest(
						JSON.parse(seen[0]?.body ?? "{}"),
					),
					[WHATSAPP_SIDECAR_SESSION_EXPIRES_AT_HEADER]: "2024-06-04T00:01:00.000Z",
				}),
			}),
		);
		expect(seen[1]?.headers[WHATSAPP_SIDECAR_SESSION_KEY_HEADER]).not.toBe(
			seen[0]?.headers[WHATSAPP_SIDECAR_SESSION_KEY_HEADER],
		);
		expect(seen[0]?.body).not.toContain(
			seen[0]?.headers[WHATSAPP_SIDECAR_SESSION_KEY_HEADER] ?? "missing-session",
		);
		expect(seen[1]?.body).not.toContain(
			seen[1]?.headers[WHATSAPP_SIDECAR_SESSION_KEY_HEADER] ?? "missing-session",
		);
	});

	it("uses injected bridge-session material when a runtime owns the one-shot issuer", async () => {
		let seen:
			| {
					readonly headers: Record<string, string>;
					readonly body: string;
			  }
			| undefined;
		const connector = createWhatsAppEdgeChannelConnector({
			sidecarUrl: "http://whatsapp-bridge:3004",
			bridgeSessionFactory: async (request) => ({
				sessionKey: "relay-issued-single-use-session",
				requestDigest: digestWhatsAppSidecarSendRequest(request),
				expiresAtMs: 1717459260000,
			}),
			fetch: async (_url, init) => {
				seen = {
					headers: init.headers,
					body: init.body,
				};
				return {
					ok: true,
					status: 200,
					json: async () => ({ ok: true, platformMessageId: "wa-http-1" }),
					text: async () => "",
				};
			},
		});
		const dispatch = createOutboundDeliveryDispatcher({
			registry: createEdgeOutboundExecutorRegistry([connector]),
			resolveConversation: async () => ctx("relay-conversation-token"),
			quarantineStore,
			now: () => 1717459200000,
		});

		await dispatch(
			preparedOutbound({
				channel: "whatsapp",
				resolvedDestination: {
					kind: "address",
					addressRef: "whatsapp:+15551234567",
					conversationId: "relay-conversation-token",
				},
			}),
		);

		expect(seen).toEqual(
			expect.objectContaining({
				headers: expect.objectContaining({
					[WHATSAPP_SIDECAR_SESSION_KEY_HEADER]: "relay-issued-single-use-session",
					[WHATSAPP_SIDECAR_REQUEST_DIGEST_HEADER]: digestWhatsAppSidecarSendRequest(
						JSON.parse(seen?.body ?? "{}"),
					),
				}),
			}),
		);
		expect(seen?.body).not.toContain("relay-issued-single-use-session");
	});

	it("applies bridge-session binding to injected sidecar senders", async () => {
		let seen:
			| {
					readonly request: WhatsAppSidecarSendRequest;
					readonly sessionKey: string;
					readonly requestDigest: string;
			  }
			| undefined;
		const connector = createWhatsAppEdgeChannelConnector({
			bridgeSessionFactory: async (request) => ({
				sessionKey: "relay-issued-single-use-session",
				requestDigest: digestWhatsAppSidecarSendRequest(request),
				expiresAtMs: 1717459260000,
			}),
			sendToSidecar: async (request, session) => {
				seen = {
					request,
					sessionKey: session.sessionKey,
					requestDigest: session.requestDigest,
				};
				return { ok: true, platformMessageId: "wa-direct-1" };
			},
		});
		const dispatch = createOutboundDeliveryDispatcher({
			registry: createEdgeOutboundExecutorRegistry([connector]),
			resolveConversation: async () => ctx("relay-conversation-token"),
			quarantineStore,
			now: () => 1717459200000,
		});

		const receipt = await dispatch(
			preparedOutbound({
				channel: "whatsapp",
				resolvedDestination: {
					kind: "address",
					addressRef: "whatsapp:+15551234567",
					conversationId: "relay-conversation-token",
				},
			}),
		);

		expect(receipt.deliveryStatus).toBe("sent");
		expect(seen?.sessionKey).toBe("relay-issued-single-use-session");
		expect(seen?.requestDigest).toBe(
			digestWhatsAppSidecarSendRequest(seen?.request as WhatsAppSidecarSendRequest),
		);
	});

	it("fails closed before sidecar I/O when bridge-session digest does not match the request", async () => {
		let sidecarCalls = 0;
		const failures: unknown[] = [];
		const connector = createWhatsAppEdgeChannelConnector({
			sidecarUrl: "http://whatsapp-bridge:3004",
			bridgeSessionFactory: async () => ({
				sessionKey: "relay-issued-single-use-session",
				requestDigest: `sha256:${"b".repeat(64)}`,
				expiresAtMs: 1717459260000,
			}),
			fetch: async () => {
				sidecarCalls += 1;
				throw new Error("sidecar must not be called with mismatched session binding");
			},
		});
		const dispatch = createOutboundDeliveryDispatcher({
			registry: createEdgeOutboundExecutorRegistry([connector]),
			resolveConversation: async () => ctx("relay-conversation-token"),
			quarantineStore,
			now: () => 1717459200000,
			onSendFailure: (_prepared, failure) => failures.push(failure),
		});

		const receipt = await dispatch(
			preparedOutbound({
				channel: "whatsapp",
				resolvedDestination: {
					kind: "address",
					addressRef: "whatsapp:+15551234567",
					conversationId: "relay-conversation-token",
				},
			}),
		);

		expect(receipt.deliveryStatus).toBe("failed");
		expect(sidecarCalls).toBe(0);
		expect(failures).toEqual([
			expect.objectContaining({
				code: "whatsapp_bridge_session_digest_mismatch",
				retryable: false,
			}),
		]);
	});

	it("fails closed before injected sender I/O when bridge-session digest does not match", async () => {
		let sidecarCalls = 0;
		const failures: unknown[] = [];
		const connector = createWhatsAppEdgeChannelConnector({
			bridgeSessionFactory: async () => ({
				sessionKey: "relay-issued-single-use-session",
				requestDigest: `sha256:${"b".repeat(64)}`,
				expiresAtMs: 1717459260000,
			}),
			sendToSidecar: async () => {
				sidecarCalls += 1;
				throw new Error("sender must not be called with mismatched session binding");
			},
		});
		const dispatch = createOutboundDeliveryDispatcher({
			registry: createEdgeOutboundExecutorRegistry([connector]),
			resolveConversation: async () => ctx("relay-conversation-token"),
			quarantineStore,
			now: () => 1717459200000,
			onSendFailure: (_prepared, failure) => failures.push(failure),
		});

		const receipt = await dispatch(
			preparedOutbound({
				channel: "whatsapp",
				resolvedDestination: {
					kind: "address",
					addressRef: "whatsapp:+15551234567",
					conversationId: "relay-conversation-token",
				},
			}),
		);

		expect(receipt.deliveryStatus).toBe("failed");
		expect(sidecarCalls).toBe(0);
		expect(failures).toEqual([
			expect.objectContaining({
				code: "whatsapp_bridge_session_digest_mismatch",
				retryable: false,
			}),
		]);
	});

	it("rejects WhatsApp sidecar URLs outside the dedicated bridge hostname", async () => {
		let sidecarCalls = 0;
		const failures: unknown[] = [];
		const connector = createWhatsAppEdgeChannelConnector({
			sidecarUrl: "https://api.example.com",
			fetch: async () => {
				sidecarCalls += 1;
				throw new Error("wrong sidecar host must not be fetched");
			},
		});
		const dispatch = createOutboundDeliveryDispatcher({
			registry: createEdgeOutboundExecutorRegistry([connector]),
			resolveConversation: async () => ctx("relay-conversation-token"),
			quarantineStore,
			now: () => 1717459200000,
			onSendFailure: (_prepared, failure) => failures.push(failure),
		});

		const receipt = await dispatch(
			preparedOutbound({
				channel: "whatsapp",
				resolvedDestination: {
					kind: "address",
					addressRef: "whatsapp:+15551234567",
					conversationId: "relay-conversation-token",
				},
			}),
		);

		expect(receipt.deliveryStatus).toBe("failed");
		expect(sidecarCalls).toBe(0);
		expect(failures).toEqual([
			expect.objectContaining({
				code: "whatsapp_sidecar_config_invalid",
				reason: `WhatsApp sidecar host must be ${WHATSAPP_SIDECAR_ALLOWED_HOST}`,
				retryable: false,
			}),
		]);
	});

	it("enforces the 25 MiB WhatsApp media cap at the sidecar boundary", async () => {
		let sidecarCalls = 0;
		const halfPlusOne = Math.floor(WHATSAPP_SIDECAR_MAX_MEDIA_BYTES / 2) + 1;
		const first = quarantineStore.store({
			bytes: new Uint8Array(halfPlusOne),
			mediaType: "application/octet-stream",
			conversationToken: "relay-conversation-token",
			scanState: "clean",
		});
		const second = quarantineStore.store({
			bytes: new Uint8Array(halfPlusOne),
			mediaType: "application/octet-stream",
			conversationToken: "relay-conversation-token",
			scanState: "clean",
		});
		const connector = createWhatsAppEdgeChannelConnector({
			sendToSidecar: async () => {
				sidecarCalls += 1;
				return { ok: true };
			},
		});
		const failures: unknown[] = [];
		const dispatch = createOutboundDeliveryDispatcher({
			registry: createEdgeOutboundExecutorRegistry([connector]),
			resolveConversation: async () => ctx("relay-conversation-token"),
			quarantineStore,
			now: () => 1717459200000,
			onSendFailure: (_prepared, failure) => failures.push(failure),
		});

		const receipt = await dispatch(
			preparedOutbound({
				channel: "whatsapp",
				resolvedDestination: {
					kind: "address",
					addressRef: "whatsapp:+15551234567",
					conversationId: "relay-conversation-token",
				},
				mediaRefs: [first, second],
			}),
		);

		expect(receipt.deliveryStatus).toBe("failed");
		expect(sidecarCalls).toBe(0);
		expect(failures).toEqual([
			expect.objectContaining({
				code: "whatsapp_media_too_large",
				retryable: false,
			}),
		]);
	});

	it("keeps WhatsApp inbound dark until CL-1 risk wrapping is wired", async () => {
		const connector = createWhatsAppEdgeChannelConnector({
			sendToSidecar: async () => ({ ok: true }),
		});

		await expect(
			connector.startListener?.(async () => {
				throw new Error("sink must not receive raw WhatsApp inbound");
			}),
		).rejects.toThrow(WHATSAPP_INBOUND_RISK_WRAP_REQUIRED);
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
