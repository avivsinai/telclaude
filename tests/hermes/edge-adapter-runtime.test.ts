import { describe, expect, it } from "vitest";
import { EdgeAdapterSchemaVersions } from "../../src/hermes/edge-adapter-contract.js";
import {
	createTelclaudeEdgeRuntime,
	isTelclaudeEdgeRuntimeDeniedError,
} from "../../src/hermes/edge-adapter-runtime.js";

const observedAt = "2026-05-31T09:00:00.000Z";

describe("Telclaude edge adapter runtime", () => {
	it("quarantines inbound attachments as refs and denies raw access to Hermes", () => {
		const runtime = createTelclaudeEdgeRuntime({ now: () => observedAt });
		const inbound = runtime.ingest({
			channel: "whatsapp",
			domain: "household",
			text: "scan this",
			attachments: [
				{
					attachmentId: "family-photo",
					mediaType: "image/jpeg",
					sizeBytes: 512,
					rawBytes: "RAW_IMAGE_BYTES",
				},
			],
		});
		const attachment = inbound.normalized.mediaRefs[0];

		expect(JSON.stringify(inbound)).not.toContain("RAW_IMAGE_BYTES");
		expect(attachment).toMatchObject({
			schemaVersion: EdgeAdapterSchemaVersions.attachmentRef,
			mediaType: "image/jpeg",
			scanState: "clean",
			lifecycle: { state: "authorized" },
		});
		expectDenied(
			() =>
				runtime.readAttachmentRaw({
					quarantineId: attachment.quarantineId,
					requester: "hermes",
				}),
			"attachment.raw-bytes-denied",
		);
	});

	it("prepares outbound sends as edge-owned refs and denies mutation, credentials, and replay", () => {
		const runtime = createTelclaudeEdgeRuntime({ now: () => observedAt });
		const inbound = runtime.ingest({
			channel: "whatsapp",
			domain: "private",
			text: "reply please",
			attachments: [
				{
					attachmentId: "inbound-1",
					mediaType: "image/png",
					sizeBytes: 128,
					rawBytes: "RAW_IMAGE_BYTES",
				},
			],
		});
		const request = {
			schemaVersion: EdgeAdapterSchemaVersions.outboundRequest,
			channel: "whatsapp",
			recipient: {
				kind: "thread",
				threadId: inbound.conversationRef.threadId,
			},
			requestedBody: "Reply through edge",
			mediaRefs: inbound.normalized.mediaRefs,
			conversationRef: inbound.conversationRef,
			correlationId: "runtime-test-1",
		};

		expectDenied(
			() =>
				runtime.prepareOutbound({
					request: { ...request, transportCredentials: { token: "raw-token" } },
					authorizingActor: inbound.actorRef,
				}),
			"outbound.transport-credentials-denied",
		);
		expectDenied(
			() =>
				runtime.prepareOutbound({
					request: {
						...request,
						mediaRefs: [
							{
								...inbound.normalized.mediaRefs[0],
								quarantineId: "edge-quarantine:forged",
							},
						],
					},
					authorizingActor: inbound.actorRef,
				}),
			"attachment.unknown-quarantine-denied",
		);
		expectDenied(
			() =>
				runtime.prepareOutbound({
					request: {
						...request,
						mediaRefs: [
							{
								...inbound.normalized.mediaRefs[0],
								lifecycle: { state: "authorized", authorizedFor: ["tc-public-social"] },
							},
						],
					},
					authorizingActor: inbound.actorRef,
				}),
			"attachment.unknown-quarantine-denied",
		);

		const prepared = runtime.prepareOutbound({
			request,
			authorizingActor: inbound.actorRef,
		});

		expect(prepared).toMatchObject({
			schemaVersion: EdgeAdapterSchemaVersions.preparedOutbound,
			policyResult: { decision: "allowed" },
			authorizingActor: inbound.actorRef,
		});
		expectDenied(
			() =>
				runtime.executeOutbound({
					preparedOutbound: { ...prepared, finalRenderedBody: "mutated" },
				}),
			"outbound.recipient-body-bound",
		);
		expectDenied(
			() =>
				runtime.executeOutbound({
					preparedOutbound: prepared,
					approvalToken: "hermes-supplied-token",
				}),
			"outbound.approval-token-denied",
		);

		const receipt = runtime.executeOutbound({ preparedOutbound: prepared });
		expect(receipt).toMatchObject({
			schemaVersion: EdgeAdapterSchemaVersions.deliveryReceipt,
			outboundRef: prepared.outboundRef,
			deliveryStatus: "sent",
		});
		expect(JSON.stringify(receipt)).not.toContain("raw-token");
		expectDenied(
			() => runtime.executeOutbound({ preparedOutbound: prepared }),
			"outbound.replay-denied",
		);
	});

	it("binds migrated identity to actor refs instead of session ids", () => {
		const runtime = createTelclaudeEdgeRuntime({ now: () => observedAt });
		const inbound = runtime.ingest({
			channel: "whatsapp",
			domain: "private",
			text: "identity check",
		});
		const request = {
			schemaVersion: EdgeAdapterSchemaVersions.outboundRequest,
			channel: "whatsapp",
			recipient: {
				kind: "thread",
				threadId: inbound.conversationRef.threadId,
			},
			requestedBody: "Reply through edge",
			mediaRefs: [],
			conversationRef: inbound.conversationRef,
			correlationId: "identity-runtime-test-1",
		};
		const conversationWithoutAuthorization: Record<string, unknown> = {
			...inbound.conversationRef,
		};
		delete conversationWithoutAuthorization.authorization;

		expectDenied(
			() =>
				runtime.prepareOutbound({
					request,
					authorizingActor: {
						...inbound.actorRef,
						actorId: "whatsapp:actor:forged",
					},
				}),
			"identity.forged-actor-denied",
		);
		expectDenied(
			() =>
				runtime.prepareOutbound({
					request,
					authorizingActor: {
						...inbound.actorRef,
						revocation: {
							revoked: true,
							revokedAt: observedAt,
							reason: "test revocation",
						},
					},
				}),
			"identity.revocation-enforced",
		);
		expectDenied(
			() =>
				runtime.prepareOutbound({
					request: {
						...request,
						conversationRef: conversationWithoutAuthorization,
					},
					authorizingActor: inbound.actorRef,
				}),
			"identity.session-id-not-authority",
		);
		expectDenied(
			() =>
				runtime.prepareOutbound({
					request: {
						...request,
						conversationRef: {
							...inbound.conversationRef,
							recipients: inbound.conversationRef.recipients.map((recipient) => ({
								...recipient,
								channelIdentity: {
									...recipient.channelIdentity,
									channel: "email",
								},
							})),
						},
					},
					authorizingActor: inbound.actorRef,
				}),
			"identity.cross-channel-denied",
		);
	});

	it("allows only strongly linked household provider reads in scoped conversations", () => {
		const runtime = createTelclaudeEdgeRuntime({ now: () => observedAt });
		const inbound = runtime.ingest({
			channel: "whatsapp",
			domain: "household",
			actorId: "whatsapp:actor:family-member",
			principalId: "whatsapp:principal:family-member",
			identityAssurance: "strong_link",
			scopes: [
				{
					scope: "message:reply",
					actions: ["read", "send", "reply"],
					grantedAt: observedAt,
				},
				{
					scope: "household:benign",
					actions: ["read"],
					grantedAt: observedAt,
				},
			],
			text: "check appointment",
		});

		expect(
			runtime.authorizeHouseholdProviderAccess({
				actorRef: inbound.actorRef,
				conversationRef: inbound.conversationRef,
				providerAccount: "clalit:family-member",
				providerAccountBinding: "strong_link",
				action: "read",
			}),
		).toMatchObject({ releaseRef: expect.stringMatching(/^household-provider:/) });
		expectDenied(
			() =>
				runtime.authorizeHouseholdProviderAccess({
					actorRef: {
						...inbound.actorRef,
						identityAssurance: "channel_bound",
					},
					conversationRef: inbound.conversationRef,
					providerAccount: "clalit:family-member",
					providerAccountBinding: "strong_link",
					action: "read",
				}),
			"household.strong-link-required",
		);
		expectDenied(
			() =>
				runtime.authorizeHouseholdProviderAccess({
					actorRef: inbound.actorRef,
					conversationRef: inbound.conversationRef,
					providerAccount: "clalit:family-member",
					providerAccountBinding: "number_only",
					action: "read",
				}),
			"household.number-only-provider-denied",
		);
		expectDenied(
			() =>
				runtime.authorizeHouseholdProviderAccess({
					actorRef: inbound.actorRef,
					conversationRef: inbound.conversationRef,
					providerAccount: "clalit:family-member",
					providerAccountBinding: "strong_link",
					action: "read",
					privateMemorySource: "telegram:default",
				}),
			"household.private-memory-denied",
		);
		expectDenied(
			() =>
				runtime.authorizeHouseholdProviderAccess({
					actorRef: inbound.actorRef,
					conversationRef: inbound.conversationRef,
					providerAccount: "clalit:family-member",
					providerAccountBinding: "strong_link",
					action: "prepare_write",
					classification: "benign",
					approved: false,
				}),
			"provider.sensitive-release-approval-required",
		);
		expectDenied(
			() =>
				runtime.prepareOutbound({
					request: {
						schemaVersion: EdgeAdapterSchemaVersions.outboundRequest,
						channel: "whatsapp",
						recipient: {
							kind: "actor",
							actorId: "whatsapp:actor:other-family-member",
						},
						requestedBody: "Scoped reply",
						mediaRefs: [],
						conversationRef: inbound.conversationRef,
						correlationId: "household-runtime-test-1",
					},
					authorizingActor: inbound.actorRef,
				}),
			"household.cross-recipient-denied",
		);
	});

	it("keeps channel bridge resources and public-social authority edge-owned", () => {
		const runtime = createTelclaudeEdgeRuntime({ now: () => observedAt });
		const socialInbound = runtime.ingest({
			channel: "social",
			domain: "public-social",
			text: "timeline event",
		});
		const emailInbound = runtime.ingest({
			channel: "email",
			domain: "public",
			text: "mail event",
		});

		expectDenied(
			() =>
				runtime.ingest({
					channel: "whatsapp",
					domain: "public",
					authorizedSender: false,
				}),
			"whatsapp.unknown-sender-denied",
		);
		expectDenied(
			() => runtime.accessChannelResource({ channel: "whatsapp", requester: "hermes" }),
			"whatsapp.direct-bridge-denied",
		);
		expectDenied(
			() => runtime.accessChannelResource({ channel: "email", requester: "hermes" }),
			"email.direct-mailbox-denied",
		);
		expectDenied(
			() => runtime.accessChannelResource({ channel: "agentmail", requester: "hermes" }),
			"agentmail.direct-key-denied",
		);
		expectDenied(
			() =>
				runtime.ingest({
					channel: "agentmail",
					domain: "public",
					authorizedSender: false,
				}),
			"agentmail.unauthorized-sender-denied",
		);
		expectDenied(
			() =>
				runtime.prepareOutbound({
					request: {
						schemaVersion: EdgeAdapterSchemaVersions.outboundRequest,
						channel: "email",
						recipient: {
							kind: "thread",
							threadId: "email:public:thread:wrong",
						},
						requestedBody: "wrong thread",
						mediaRefs: [],
						conversationRef: emailInbound.conversationRef,
						correlationId: "email-thread-test-1",
					},
					authorizingActor: emailInbound.actorRef,
				}),
			"email.wrong-thread-denied",
		);
		expectDenied(
			() =>
				runtime.authorizeSocialPost({
					actorRef: socialInbound.actorRef,
					conversationRef: socialInbound.conversationRef,
					approved: false,
					budgetRemaining: 1,
				}),
			"social.unapproved-posting-denied",
		);
		expectDenied(
			() =>
				runtime.authorizeSocialPost({
					actorRef: socialInbound.actorRef,
					conversationRef: socialInbound.conversationRef,
					approved: true,
					budgetRemaining: 0,
				}),
			"social.budget-denied",
		);
		expect(
			runtime.authorizePublicSocialIsolation({
				actorRef: socialInbound.actorRef,
				conversationRef: socialInbound.conversationRef,
				budgetRemaining: 1,
			}),
		).toMatchObject({ profileRef: expect.stringMatching(/^public-social-profile:/) });
		expectDenied(
			() =>
				runtime.authorizePublicSocialIsolation({
					actorRef: socialInbound.actorRef,
					conversationRef: socialInbound.conversationRef,
					workspaceMount: "/workspace/private",
					budgetRemaining: 1,
				}),
			"public-social.private-workspace-denied",
		);
		expectDenied(
			() =>
				runtime.authorizePublicSocialIsolation({
					actorRef: socialInbound.actorRef,
					conversationRef: socialInbound.conversationRef,
					providerScope: "bank:operator",
					budgetRemaining: 1,
				}),
			"public-social.provider-scope-denied",
		);
	});
});

function expectDenied(fn: () => unknown, control: string): void {
	try {
		fn();
		throw new Error(`expected ${control} denial`);
	} catch (error) {
		expect(isTelclaudeEdgeRuntimeDeniedError(error, control)).toBe(true);
	}
}
