import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { TelclaudeConfig } from "../../src/config/config.js";
import { TelclaudeEdgeRuntime } from "../../src/hermes/edge-adapter-runtime.js";
import type {
	TelclaudeMcpAttachmentGetRequest,
	TelclaudeMcpAuthorityStamp,
	TelclaudeMcpMemorySearchRequest,
	TelclaudeMcpMemoryWriteRequest,
	TelclaudeMcpOutboundPrepareRequest,
	TelclaudeMcpProviderPrepareWriteRequest,
	TelclaudeMcpProviderReadRequest,
} from "../../src/hermes/mcp/bridge.js";
import {
	createStoredAttachmentOutboundMediaResolver,
	createTelclaudeLiveMcpRelayClients,
} from "../../src/hermes/mcp/live-relay-clients.js";
import { startTelclaudeLiveMcpRuntime } from "../../src/hermes/mcp/live-runtime.js";
import { createTelclaudeMcpSideEffectLedger } from "../../src/hermes/mcp/side-effect-ledger.js";
import { createRelayConversationStore } from "../../src/hermes/relay-conversation-store.js";
import {
	collectHouseholdMetricRollups,
	configureHouseholdMetrics,
} from "../../src/household-metrics/store.js";
import { createAttachmentQuarantineStore } from "../../src/relay/attachment-quarantine-store.js";
import { createMediaActionConfirmationStore } from "../../src/relay/media-action-confirmation-store.js";
import type { AttachmentRef } from "../../src/storage/attachment-refs.js";
import { getDb, resetDatabase } from "../../src/storage/db.js";

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

describe("Telclaude live MCP relay-client adapters", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tc-live-mcp-clients-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		resetDatabase();
	});

	afterEach(() => {
		configureHouseholdMetrics({ enabled: false });
		vi.restoreAllMocks();
		resetDatabase();
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) {
			delete process.env.TELCLAUDE_DATA_DIR;
		} else {
			process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
		}
	});

	it("reads and writes memory only through the authority-derived source", async () => {
		const clients = createTelclaudeLiveMcpRelayClients({ ledger: testLedger() });

		await clients.memoryWrite(memoryWrite({ id: "private-1", content: "operator likes tea" }));
		await clients.memoryWrite(
			memoryWrite({
				...socialStamp(),
				id: "social-1",
				category: "posts",
				content: "public draft about launch",
				trust: "untrusted",
			}),
		);

		await expect(
			clients.memorySearch(memorySearch({ filters: { sources: ["social"] } })),
		).rejects.toThrow("memory filters denied: sources");
		await expect(
			clients.memorySearch(memorySearch({ filters: { categories: ["profile;DROP"] } })),
		).rejects.toThrow("invalid memory category filter");
		await expect(clients.memorySearch(memorySearch({ memorySource: "social" }))).rejects.toThrow(
			"live MCP private authority must use telegram profile memory source",
		);

		const privateResult = await clients.memorySearch(memorySearch({ query: "operator" }));
		expect(privateResult).toMatchObject({
			entries: [
				expect.objectContaining({
					id: "private-1",
					_provenance: expect.objectContaining({ source: "telegram:ops" }),
				}),
			],
		});

		const socialResult = await clients.memorySearch(
			memorySearch({
				...socialStamp(),
				query: "public",
				filters: { categories: ["posts"], trust: ["untrusted"] },
			}),
		);
		expect(socialResult).toMatchObject({
			entries: [
				expect.objectContaining({
					id: "social-1",
					_provenance: expect.objectContaining({ source: "social" }),
				}),
			],
		});
	});

	it("routes provider reads through the relay proxy and returns sanitized data only", async () => {
		const calls: unknown[] = [];
		const clients = createTelclaudeLiveMcpRelayClients({
			ledger: testLedger(),
			providerProxy: async (request) => {
				calls.push(request);
				return { status: "ok", data: { messages: [{ id: "m1" }] } };
			},
		});

		await expect(
			clients.providerRead(
				providerRead({
					providerId: "google",
					service: "google",
					action: "gmail.search",
					params: { q: "from:clinic" },
					subjectUserId: "admin",
				}),
			),
		).resolves.toEqual({ messages: [{ id: "m1" }] });
		expect(calls).toEqual([
			{
				providerId: "google",
				path: "/v1/fetch",
				method: "POST",
				body: JSON.stringify({
					service: "gmail",
					action: "search",
					params: { q: "from:clinic" },
					subjectUserId: "admin",
				}),
				userId: "operator",
			},
		]);

		const failing = createTelclaudeLiveMcpRelayClients({
			ledger: testLedger(),
			providerProxy: async () => ({
				status: "error",
				error: "upstream token sk-ant-thisshouldberedacted1234567890",
			}),
		});
		await expect(failing.providerRead(providerRead())).rejects.toThrow("provider read failed");
		await expect(failing.providerRead(providerRead())).rejects.not.toThrow("sk-ant-");
	});

	it("prepares provider and outbound side effects in the shared ledger without executing them", async () => {
		const ledger = testLedger();
		let providerProxyCalled = false;
		const requestedApprovals: string[] = [];
		const clients = createTelclaudeLiveMcpRelayClients({
			ledger,
			makeApprovalRequestId: makeApprovalIds(),
			providerProxy: async () => {
				providerProxyCalled = true;
				return { status: "ok", data: {} };
			},
			providerWriteApproverActorId: "operator:provider-approver",
			outboundApproverActorId: "operator:outbound-approver",
			requestSideEffectApproval: (record) => {
				requestedApprovals.push(record.ref);
			},
		});

		const providerPrepared = (await clients.providerPrepareWrite(
			providerPrepare({
				service: "bank",
				action: "transfer.execute",
				params: { amount: 100, currency: "ILS" },
				subjectUserId: "admin",
				idempotencyKey: "idem-provider",
			}),
		)) as { actionRef: string; approvalRequestId: string };
		expect(providerProxyCalled).toBe(false);
		expect(providerPrepared.approvalRequestId).toBe("approval-1");
		expect(ledger.get(providerPrepared.actionRef)).toMatchObject({
			kind: "provider",
			status: "prepared",
			actorId: "operator",
			approverActorId: "operator:provider-approver",
			providerId: "bank",
			service: "bank",
			action: "transfer.execute",
			params: { amount: 100, currency: "ILS" },
			subjectUserId: "admin",
			idempotencyKey: "idem-provider",
		});

		const { token } = mintWhatsappConversation("dinner", { humanPairingProvenance: true });
		const turnConversationRef = mintWhatsappTurn(token, "dinner");
		const outboundPrepared = (await clients.outboundPrepare(
			outboundPrepare({
				conversationToken: token,
				turnConversationRef,
				replyIntent: { kind: "address", addressRef: "+15551234567" },
				body: "I'll pick up dinner at 19:00.",
			}),
		)) as {
			outboundRef: string;
			approvalRequestId: string;
			edgePreparedRef: string;
			edgePreparedHash: string;
		};
		expect(outboundPrepared.approvalRequestId).toBe("approval-2");
		expect(outboundPrepared.edgePreparedRef).toMatch(/^edge-out:/);
		expect(outboundPrepared.edgePreparedHash).toMatch(/^[a-f0-9]{64}$/);
		expect(ledger.get(outboundPrepared.outboundRef)).toMatchObject({
			kind: "outbound",
			status: "prepared",
			actorId: "operator",
			approverActorId: "operator:outbound-approver",
			channel: "whatsapp",
			destination: "+15551234567",
			renderedBody: "I'll pick up dinner at 19:00.",
			mediaRefs: [],
			conversationRef: token,
			turnConversationRef,
			approvalMetadata: expect.objectContaining({
				pairedProvenance: true,
				replyCapableActorSeat: true,
			}),
			edgePreparedRef: outboundPrepared.edgePreparedRef,
			edgePreparedHash: outboundPrepared.edgePreparedHash,
		});
		expect(requestedApprovals).toEqual([providerPrepared.actionRef, outboundPrepared.outboundRef]);
	});

	it("enforces the Phase 0 Clalit action allowlist for household reads and writes", async () => {
		configureHouseholdMetrics({ enabled: true });
		const ledger = testLedger();
		const providerCalls: unknown[] = [];
		const clients = createTelclaudeLiveMcpRelayClients({
			ledger,
			providerWriteApproverActorId: "telegram:111",
			providerProxy: async (request) => {
				providerCalls.push(request);
				return { status: "ok", data: { appointments: [] } };
			},
		});

		await expect(
			clients.providerRead(
				providerRead({
					...householdStamp(),
					providerId: "clalit",
					service: "clalit",
					action: "appointments",
				}),
			),
		).resolves.toEqual({ appointments: [] });
		expect(providerCalls).toHaveLength(1);
		await expect(
			clients.providerRead(
				providerRead({
					...householdStamp(),
					providerId: "clalit",
					service: "clalit",
					action: "appointments",
					params: { symptoms: "כאבים בחזה" },
				}),
			),
		).rejects.toThrow("urgent_health_escalation_required");

		for (const action of ["home", "appointment_booking", "tofes_17"] as const) {
			await expect(
				clients.providerRead(
					providerRead({
						...householdStamp(),
						providerId: "clalit",
						service: "clalit",
						action,
					}),
				),
			).rejects.toThrow("household Phase 0 provider action denied");
		}
		await expect(
			clients.providerPrepareWrite(
				providerPrepare({
					...householdStamp(),
					providerId: "clalit",
					service: "clalit",
					action: "prescription_renewal",
					params: { prescriptionId: "synthetic-rx" },
				}),
			),
		).resolves.toMatchObject({ actionRef: expect.any(String) });
		await expect(
			clients.providerPrepareWrite(
				providerPrepare({
					...householdStamp(),
					providerId: "clalit",
					service: "clalit",
					action: "appointment_booking",
				}),
			),
		).rejects.toThrow("household Phase 0 provider action denied");
		expect(providerCalls).toHaveLength(1);
		expect(ledger.list()).toHaveLength(1);
		expect(collectHouseholdMetricRollups()).toEqual([
			{ bindingKey: "parent-a", metricKind: "prescription_renewal_prepared", count: 1 },
			{ bindingKey: "parent-a", metricKind: "read_succeeded", count: 1 },
		]);

		getDb().exec("DROP TABLE household_metrics");
		await expect(
			clients.providerRead(
				providerRead({
					...householdStamp(),
					providerId: "clalit",
					service: "clalit",
					action: "appointments",
				}),
			),
		).resolves.toEqual({ appointments: [] });
		await expect(
			clients.providerPrepareWrite(
				providerPrepare({
					...householdStamp(),
					providerId: "clalit",
					service: "clalit",
					action: "prescription_renewal",
					params: { prescriptionId: "synthetic-rx-2" },
				}),
			),
		).resolves.toMatchObject({ actionRef: expect.any(String) });
	});

	it("rejects unexpected household Clalit params before proxying or ledger preparation", async () => {
		const ledger = testLedger();
		const providerProxy = vi.fn(async () => ({
			status: "ok" as const,
			data: { appointments: [] },
		}));
		const clients = createTelclaudeLiveMcpRelayClients({
			ledger,
			providerWriteApproverActorId: "telegram:111",
			providerProxy,
		});

		await expect(
			clients.providerRead(
				providerRead({
					...householdStamp(),
					providerId: "clalit",
					service: "clalit",
					action: "appointments",
					params: { subjectUserId: "synthetic-subject" },
				}),
			),
		).rejects.toThrowError(new Error("household Phase 0 provider params denied"));
		await expect(
			clients.providerPrepareWrite(
				providerPrepare({
					...householdStamp(),
					providerId: "clalit",
					service: "clalit",
					action: "prescription_renewal",
					params: {
						prescriptionId: "synthetic-rx",
						filter: { subjectId: "synthetic-subject" },
					},
				}),
			),
		).rejects.toThrowError(new Error("household Phase 0 provider params denied"));

		expect(providerProxy).not.toHaveBeenCalled();
		expect(ledger.list()).toEqual([]);
	});

	it("counts household auth-required reads without changing the provider failure", async () => {
		configureHouseholdMetrics({ enabled: true });
		const clients = createTelclaudeLiveMcpRelayClients({
			ledger: testLedger(),
			providerProxy: async () => ({
				status: "error",
				errorCode: "auth_required",
				error: "Enrollment required",
			}),
		});
		const request = providerRead({
			...householdStamp(),
			providerId: "clalit",
			service: "clalit",
			action: "appointments",
		});

		await expect(clients.providerRead(request)).rejects.toThrow(
			"provider read failed: auth_required",
		);
		expect(collectHouseholdMetricRollups()).toEqual([
			{ bindingKey: "parent-a", metricKind: "auth_required", count: 1 },
		]);

		getDb().exec("DROP TABLE household_metrics");
		await expect(clients.providerRead(request)).rejects.toThrow(
			"provider read failed: auth_required",
		);
	});

	it.each([
		["cardiac", "לחץ בחזה"],
		["stroke", "חצי גוף חלש ודיבור מעורפל"],
		["breathing", "אני לא יכולה לנשום"],
		["collapse", "נפלתי והתעלפתי"],
		["bleeding", "דימום חזק"],
		["suicidal ideation", "אני לא רוצה לחיות ורוצה לפגוע בעצמי"],
		["explicit emergency", "הצילו, זה מקרה חירום"],
		["unconscious", "מחוסר הכרה"],
		["English breathing", "I cannot breathe"],
		["English bleeding", "I have heavy bleeding"],
	] as const)("keeps shared urgent-health defense in depth for %s", async (_emergencyClass, symptoms) => {
		const providerProxy = vi.fn(async () => ({
			status: "ok" as const,
			data: { appointments: [] },
		}));
		const clients = createTelclaudeLiveMcpRelayClients({
			ledger: testLedger(),
			providerProxy,
		});

		await expect(
			clients.providerRead(
				providerRead({
					...householdStamp(),
					providerId: "clalit",
					service: "clalit",
					action: "appointments",
					params: { symptoms },
				}),
			),
		).rejects.toThrow("urgent_health_escalation_required");
		expect(providerProxy).not.toHaveBeenCalled();
	});

	it("keeps provider-write and household schedule results byte-identical with no eligible media", async () => {
		const turnConversationRef = `turn_${"9".repeat(32)}`;
		const gate = createMediaActionConfirmationStore({ encryptionKey: "k".repeat(32) });
		const providerRequest = providerPrepare({
			...householdStamp({ turnConversationRef }),
			providerId: "clalit",
			service: "clalit",
			action: "prescription_renewal",
			params: { prescriptionId: "synthetic-rx" },
		});
		const baselineProvider = createTelclaudeLiveMcpRelayClients({
			ledger: testLedger(),
			makeApprovalRequestId: makeApprovalIds(),
			providerWriteApproverActorId: "operator:provider-approver",
		});
		const guardedProvider = createTelclaudeLiveMcpRelayClients({
			ledger: testLedger(),
			makeApprovalRequestId: makeApprovalIds(),
			providerWriteApproverActorId: "operator:provider-approver",
			mediaActionConfirmationGate: gate,
		});

		const baselineProviderBytes = JSON.stringify(
			await baselineProvider.providerPrepareWrite(providerRequest),
		);
		const guardedProviderBytes = JSON.stringify(
			await guardedProvider.providerPrepareWrite(providerRequest),
		);
		expect(guardedProviderBytes).toBe(baselineProviderBytes);

		let uuid = 0;
		vi.spyOn(crypto, "randomUUID").mockImplementation(
			() => `00000000-0000-4000-8000-${String(++uuid).padStart(12, "0")}`,
		);
		const scheduleRequest = {
			...householdStamp({ turnConversationRef }),
			schedule: { kind: "at" as const, at: futureJerusalemMinute(60) },
			prompt: "לקחת מסמכים",
		};
		const baselineSchedule = createTelclaudeLiveMcpRelayClients({
			ledger: testLedger(),
			householdReminderConfig: mediaConfirmationHouseholdConfig,
		});
		const baselineScheduleBytes = JSON.stringify(
			await baselineSchedule.scheduleCreate(scheduleRequest),
		);
		resetDatabase();
		uuid = 0;
		const guardedSchedule = createTelclaudeLiveMcpRelayClients({
			ledger: testLedger(),
			householdReminderConfig: mediaConfirmationHouseholdConfig,
			mediaActionConfirmationGate: gate,
		});
		const guardedScheduleBytes = JSON.stringify(
			await guardedSchedule.scheduleCreate(scheduleRequest),
		);
		expect(guardedScheduleBytes).toBe(baselineScheduleBytes);
	});

	it("blocks eligible media-derived provider writes before ledger preparation", async () => {
		const ledger = testLedger();
		const gate = eligibleMediaGate(`turn_${"a".repeat(32)}`);
		const requestMediaActionConfirmation = vi.fn(async () => undefined);
		const clients = createTelclaudeLiveMcpRelayClients({
			ledger,
			providerWriteApproverActorId: "operator:provider-approver",
			mediaActionConfirmationGate: gate,
			requestMediaActionConfirmation,
		});

		await expect(
			clients.providerPrepareWrite(
				providerPrepare({
					...householdStamp({ turnConversationRef: `turn_${"a".repeat(32)}` }),
					providerId: "clalit",
					service: "clalit",
					action: "prescription_renewal",
					params: { prescriptionId: "synthetic-rx" },
				}),
			),
		).rejects.toMatchObject({ code: "media_action_confirmation_required" });
		expect(ledger.list()).toEqual([]);
		expect(requestMediaActionConfirmation).toHaveBeenCalledWith(
			expect.objectContaining({
				actionToolName: "tc_provider_prepare_write",
				bindingId: "parent-a",
			}),
		);
		expect(
			getDb().prepare("SELECT action_tool_name FROM household_media_action_confirmations").all(),
		).toEqual([{ action_tool_name: "tc_provider_prepare_write" }]);
	});

	it("consumes a confirmed fresh-turn provider capability exactly once", async () => {
		const originalTurnRef = `turn_${"d".repeat(32)}`;
		const freshTurnRef = `turn_${"e".repeat(32)}`;
		const ledger = testLedger();
		const gate = eligibleMediaGate(originalTurnRef);
		const request = providerPrepare({
			...householdStamp({ turnConversationRef: originalTurnRef }),
			providerId: "clalit",
			service: "clalit",
			action: "prescription_renewal",
			params: { prescriptionId: "synthetic-rx" },
		});
		const clients = createTelclaudeLiveMcpRelayClients({
			ledger,
			providerWriteApproverActorId: "operator:provider-approver",
			mediaActionConfirmationGate: gate,
		});
		await expect(clients.providerPrepareWrite(request)).rejects.toMatchObject({
			code: "media_action_confirmation_required",
		});
		gate.resolveChoice({
			owner: mediaGateOwner,
			eventId: "event-live-fresh",
			messageId: "message-live-fresh",
			choice: "confirm",
			mintFreshTurn: () => ({ ref: freshTurnRef }),
		});

		await expect(
			clients.providerPrepareWrite({ ...request, turnConversationRef: freshTurnRef }),
		).resolves.toMatchObject({ actionRef: expect.any(String) });
		await expect(
			clients.providerPrepareWrite({ ...request, turnConversationRef: freshTurnRef }),
		).rejects.toMatchObject({ code: "media_confirmed_action_denied" });
		expect(ledger.list()).toHaveLength(1);
	});

	it.each([
		{
			toolName: "tc_schedule_create" as const,
			invoke: (clients: ReturnType<typeof createTelclaudeLiveMcpRelayClients>, turnRef: string) =>
				clients.scheduleCreate({
					...householdStamp({ turnConversationRef: turnRef }),
					schedule: { kind: "at", at: futureJerusalemMinute(60) },
					prompt: "לקחת מסמכים",
				}),
		},
		{
			toolName: "tc_schedule_update" as const,
			invoke: (clients: ReturnType<typeof createTelclaudeLiveMcpRelayClients>, turnRef: string) =>
				clients.scheduleUpdate({
					...householdStamp({ turnConversationRef: turnRef }),
					jobId: "reminder-absent",
					schedule: { kind: "at", at: futureJerusalemMinute(60) },
					prompt: "לקחת מסמכים",
				}),
		},
		{
			toolName: "tc_schedule_cancel" as const,
			invoke: (clients: ReturnType<typeof createTelclaudeLiveMcpRelayClients>, turnRef: string) =>
				clients.scheduleCancel({
					...householdStamp({ turnConversationRef: turnRef }),
					jobId: "reminder-absent",
				}),
		},
	])("blocks eligible media-derived $toolName before any reminder mutation", async (fixture) => {
		const turnConversationRef = `turn_${"b".repeat(32)}`;
		const clients = createTelclaudeLiveMcpRelayClients({
			ledger: testLedger(),
			householdReminderConfig: mediaConfirmationHouseholdConfig,
			mediaActionConfirmationGate: eligibleMediaGate(turnConversationRef),
		});

		await expect(fixture.invoke(clients, turnConversationRef)).rejects.toMatchObject({
			code: "media_action_confirmation_required",
		});
		expect(getDb().prepare("SELECT COUNT(*) AS count FROM household_reminders").get()).toEqual({
			count: 0,
		});
		expect(
			getDb().prepare("SELECT action_tool_name FROM household_media_action_confirmations").all(),
		).toEqual([{ action_tool_name: fixture.toolName }]);
	});

	it("derives household WhatsApp replies from the current sender and rejects alternate targets", async () => {
		const ledger = testLedger();
		const senderAddress = "whatsapp:+15557654321";
		const clients = createTelclaudeLiveMcpRelayClients({
			ledger,
			makeApprovalRequestId: makeApprovalIds(),
			outboundApproverActorId: "operator:outbound-approver",
			resolveHouseholdReplyBinding: householdReplyBindingResolver(senderAddress),
		});
		const { token } = mintWhatsappConversation("household-parent-a", {
			profileId: "parent-a",
			domain: "household",
			threadId: senderAddress,
			members: [
				{
					actorId: "household:whatsapp:parent-a",
					principalId: senderAddress,
					role: "sender",
					identityAssurance: "strong_link",
					scopes: ["message:reply", "whatsapp:reply"],
				},
			],
			humanPairingProvenance: true,
		});
		const turnConversationRef = mintWhatsappTurn(token, "household-parent-a", {
			senderActorId: "household:whatsapp:parent-a",
		});
		const request = outboundPrepare({
			...householdStamp(),
			conversationToken: token,
			turnConversationRef,
			body: "See you at 19:00",
		});

		const prepared = (await clients.outboundPrepare(request)) as { outboundRef: string };
		expect(ledger.get(prepared.outboundRef)).toMatchObject({
			domain: "household",
			subjectUserId: "household:parent-a",
			householdReplyBinding: {
				bindingId: "parent-a",
				subjectUserId: "household:parent-a",
				senderPrincipalHash: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
				recipientPrincipalHash: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
				identityAssurance: "strong_link",
			},
			destination: senderAddress,
			resolvedDestination: expect.objectContaining({
				addressRef: senderAddress,
			}),
		});

		await expect(
			clients.outboundPrepare({
				...request,
				replyIntent: { kind: "address", addressRef: "whatsapp:+15550000000" },
			}),
		).rejects.toThrow("household outbound reply intent must match the current sender address");
	});

	it.each([
		{
			name: "missing subject",
			stamp: { subjectUserId: undefined },
			resolver: householdReplyBindingResolver("whatsapp:+15557654321"),
			error: "live MCP household subject must equal memory source",
		},
		{
			name: "removed pairing",
			stamp: {},
			resolver: () => null,
			error: "household reply binding unavailable or mismatched",
		},
		{
			name: "cross-parent principal",
			stamp: {},
			resolver: householdReplyBindingResolver("whatsapp:+15550000000"),
			error: "household reply binding does not match the live conversation",
		},
	])("rejects household prepare when $name", async ({ stamp, resolver, error }) => {
		const ledger = testLedger();
		const senderAddress = "whatsapp:+15557654321";
		const clients = createTelclaudeLiveMcpRelayClients({
			ledger,
			outboundApproverActorId: "operator:outbound-approver",
			resolveHouseholdReplyBinding: resolver,
		});
		const { token } = mintWhatsappConversation(`binding-negative-${error}`, {
			profileId: "parent-a",
			domain: "household",
			threadId: senderAddress,
			humanPairingProvenance: true,
			members: [
				{
					actorId: "household:whatsapp:parent-a",
					principalId: senderAddress,
					role: "sender",
					identityAssurance: "strong_link",
					scopes: ["message:reply"],
				},
			],
		});
		const turnConversationRef = mintWhatsappTurn(token, "binding-negative", {
			senderActorId: "household:whatsapp:parent-a",
		});

		await expect(
			clients.outboundPrepare(
				outboundPrepare({
					...householdStamp(stamp),
					conversationToken: token,
					turnConversationRef,
				}),
			),
		).rejects.toThrow(error);
		expect(ledger.list()).toEqual([]);
	});

	it("revokes prepared side effects when the human approval request cannot be created", async () => {
		const ledger = testLedger();
		const clients = createTelclaudeLiveMcpRelayClients({
			ledger,
			makeApprovalRequestId: makeApprovalIds(),
			providerWriteApproverActorId: "operator:provider-approver",
			requestSideEffectApproval: () => {
				throw new Error("approval request unavailable");
			},
		});

		await expect(clients.providerPrepareWrite(providerPrepare())).rejects.toThrow(
			"approval request unavailable",
		);
		expect(ledger.list()).toEqual([
			expect.objectContaining({
				kind: "provider",
				status: "revoked",
				revokeReason: "side-effect approval request failed",
			}),
		]);
	});

	it("fails outbound preparation closed when the conversation is not relay-authorized", async () => {
		const ledger = testLedger();
		const clients = createTelclaudeLiveMcpRelayClients({
			ledger,
			makeApprovalRequestId: makeApprovalIds(),
			outboundApproverActorId: "operator:outbound-approver",
		});
		const denied = mintWhatsappConversation("denied", { authorizationState: "denied" });

		await expect(
			clients.outboundPrepare(
				outboundPrepare({
					conversationToken: denied.token,
					body: "should not prepare",
				}),
			),
		).rejects.toThrow("outbound conversation unavailable or unauthorized");
		expect(ledger.list()).toEqual([]);
	});

	it("preserves validated outbound MIME, safe filename, and byte size in the prepared ledger", async () => {
		const sourcePath = path.join(tempDir, "provider-internal-object");
		fs.writeFileSync(sourcePath, "%PDF-1.4\nprovider document");
		const ledger = testLedger();
		const edgeRuntime = new TelclaudeEdgeRuntime();
		const resolver = createStoredAttachmentOutboundMediaResolver({
			edgeRuntime,
			quarantineStore: createAttachmentQuarantineStore(),
			validateAttachment: () => ({
				valid: true,
				attachment: {
					ref: "provider-ref",
					actorUserId: "operator",
					providerId: "bank",
					filepath: sourcePath,
					filename: "Provider Statement (final).pdf",
					mimeType: "application/pdf",
					size: fs.statSync(sourcePath).size,
					createdAt: 1000,
					expiresAt: 2000,
				},
			}),
		});
		const clients = createTelclaudeLiveMcpRelayClients({
			ledger,
			edgeRuntime,
			resolveOutboundMediaRefs: resolver,
			makeApprovalRequestId: makeApprovalIds(),
			outboundApproverActorId: "operator:outbound-approver",
		});
		const { token } = mintWhatsappConversation("metadata-round-trip");
		const turnConversationRef = mintWhatsappTurn(token, "metadata-round-trip");

		const prepared = (await clients.outboundPrepare(
			outboundPrepare({
				conversationToken: token,
				turnConversationRef,
				mediaRefs: ["provider-ref"],
			}),
		)) as { outboundRef: string };

		expect(ledger.get(prepared.outboundRef)).toMatchObject({
			preparedMediaRefs: [
				{
					mediaType: "application/pdf",
					redactedFilename: "Provider_Statement_final_.pdf",
					sizeBytes: fs.statSync(sourcePath).size,
				},
			],
		});
		expect(JSON.stringify(ledger.get(prepared.outboundRef))).not.toContain(sourcePath);
	});

	it("requires a live relay turn authority for outbound preparation", async () => {
		const ledger = testLedger();
		const edgeRuntime = new CountingEdgeRuntime();
		let mediaResolutions = 0;
		const clients = createTelclaudeLiveMcpRelayClients({
			ledger,
			makeApprovalRequestId: makeApprovalIds(),
			outboundApproverActorId: "operator:outbound-approver",
			edgeRuntime,
			resolveOutboundMediaRefs: () => {
				mediaResolutions += 1;
				return [];
			},
		});
		const { token } = mintWhatsappConversation("turn-required");

		await expect(
			clients.outboundPrepare(
				outboundPrepare({
					conversationToken: token,
				}),
			),
		).rejects.toThrow("outbound turn authority required");

		await expect(
			clients.outboundPrepare(
				outboundPrepare({
					conversationToken: token,
					turnConversationRef: `turn_${"b".repeat(32)}`,
				}),
			),
		).rejects.toThrow("outbound turn authority unavailable or unauthorized");

		const recipientTurn = mintWhatsappTurn(token, "turn-required-recipient", {
			senderActorId: "actor:turn-required:recipient",
		});
		await expect(
			clients.outboundPrepare(
				outboundPrepare({
					conversationToken: token,
					turnConversationRef: recipientTurn,
				}),
			),
		).rejects.toThrow("outbound turn authority mismatch");

		const revokedTurn = mintWhatsappTurn(token, "turn-required-revoked");
		createRelayConversationStore().revokeInboundTurn(revokedTurn, "test revoked");
		await expect(
			clients.outboundPrepare(
				outboundPrepare({
					conversationToken: token,
					turnConversationRef: revokedTurn,
				}),
			),
		).rejects.toThrow("outbound turn authority unavailable or unauthorized");

		const expiredTurn = mintWhatsappTurn(token, "turn-required-expired", {
			expiresAtMs: Date.now() - 1,
		});
		await expect(
			clients.outboundPrepare(
				outboundPrepare({
					conversationToken: token,
					turnConversationRef: expiredTurn,
				}),
			),
		).rejects.toThrow("outbound turn authority unavailable or unauthorized");

		expect(ledger.list()).toEqual([]);
		expect(mediaResolutions).toBe(0);
		expect(edgeRuntime.prepareOutboundCalls).toBe(0);
	});

	it("derives pairedProvenance false for first-contact conversations", async () => {
		const ledger = testLedger();
		const clients = createTelclaudeLiveMcpRelayClients({
			ledger,
			makeApprovalRequestId: makeApprovalIds(),
			outboundApproverActorId: "operator:outbound-approver",
		});
		const { token } = mintWhatsappConversation("first-contact");
		const turnConversationRef = mintWhatsappTurn(token, "first-contact");

		const prepared = (await clients.outboundPrepare(
			outboundPrepare({ conversationToken: token, turnConversationRef }),
		)) as { outboundRef: string };

		expect(ledger.get(prepared.outboundRef)).toMatchObject({
			kind: "outbound",
			approvalMetadata: expect.objectContaining({
				pairedProvenance: false,
				replyCapableActorSeat: true,
			}),
		});
	});

	it("derives replyCapableActorSeat false when the live actor seat lacks message:reply", async () => {
		const ledger = testLedger();
		const clients = createTelclaudeLiveMcpRelayClients({
			ledger,
			makeApprovalRequestId: makeApprovalIds(),
			outboundApproverActorId: "operator:outbound-approver",
		});
		const { token } = mintWhatsappConversation("no-reply-seat", {
			humanPairingProvenance: true,
			members: [
				{
					actorId: "operator",
					principalId: "+15557654321",
					role: "sender",
				},
				{
					actorId: "actor:no-reply-seat:recipient",
					principalId: "+15551234567",
					role: "recipient",
				},
			],
		});
		const turnConversationRef = mintWhatsappTurn(token, "no-reply-seat");

		const prepared = (await clients.outboundPrepare(
			outboundPrepare({ conversationToken: token, turnConversationRef }),
		)) as { outboundRef: string };

		expect(ledger.get(prepared.outboundRef)).toMatchObject({
			kind: "outbound",
			approvalMetadata: expect.objectContaining({
				pairedProvenance: true,
				replyCapableActorSeat: false,
			}),
		});
	});

	it("fails outbound preparation closed for unauthorized channels and non-targetable intents", async () => {
		const ledger = testLedger();
		const clients = createTelclaudeLiveMcpRelayClients({
			ledger,
			makeApprovalRequestId: makeApprovalIds(),
			outboundApproverActorId: "operator:outbound-approver",
		});
		const { token } = mintWhatsappConversation("scope");

		await expect(
			clients.outboundPrepare(
				outboundPrepare({
					conversationToken: token,
					outboundChannels: ["email"],
				}),
			),
		).rejects.toThrow("outbound channel denied: whatsapp");
		await expect(
			clients.outboundPrepare(
				outboundPrepare({
					conversationToken: token,
					replyIntent: { kind: "address", addressRef: "+15550000000" },
				}),
			),
		).rejects.toThrow("reply intent address is not targetable");
		expect(ledger.list()).toEqual([]);
	});

	it("fails provider write preparation closed without a distinct relay-side approver", async () => {
		const missingApproverLedger = testLedger();
		const missingApproverClients = createTelclaudeLiveMcpRelayClients({
			ledger: missingApproverLedger,
		});
		await expect(missingApproverClients.providerPrepareWrite(providerPrepare())).rejects.toThrow(
			"provider write approval denied: providerWriteApproverActorId is not configured",
		);
		expect(missingApproverLedger.list()).toEqual([]);

		const selfApproverLedger = testLedger();
		const selfApproverClients = createTelclaudeLiveMcpRelayClients({
			ledger: selfApproverLedger,
			providerWriteApproverActorId: "operator",
		});
		await expect(selfApproverClients.providerPrepareWrite(providerPrepare())).rejects.toThrow(
			"provider write approval denied: providerWriteApproverActorId must differ from actorId",
		);
		expect(selfApproverLedger.list()).toEqual([]);
	});

	it("fails outbound preparation closed without a distinct relay-side approver", async () => {
		const missingApproverLedger = testLedger();
		const missingApproverEdgeRuntime = new CountingEdgeRuntime();
		let missingMediaResolutions = 0;
		const missingApproverClients = createTelclaudeLiveMcpRelayClients({
			ledger: missingApproverLedger,
			edgeRuntime: missingApproverEdgeRuntime,
			resolveOutboundMediaRefs: () => {
				missingMediaResolutions += 1;
				return [];
			},
		});
		const { token: missingToken } = mintWhatsappConversation("missing-outbound-approver");
		await expect(
			missingApproverClients.outboundPrepare(
				outboundPrepare({
					conversationToken: missingToken,
					mediaRefs: ["att_should_not_resolve_missing"],
				}),
			),
		).rejects.toThrow("outbound approval denied: outboundApproverActorId is not configured");
		expect(missingApproverLedger.list()).toEqual([]);
		expect(missingMediaResolutions).toBe(0);
		expect(missingApproverEdgeRuntime.prepareOutboundCalls).toBe(0);

		const selfApproverLedger = testLedger();
		const selfApproverEdgeRuntime = new CountingEdgeRuntime();
		let selfMediaResolutions = 0;
		const selfApproverClients = createTelclaudeLiveMcpRelayClients({
			ledger: selfApproverLedger,
			edgeRuntime: selfApproverEdgeRuntime,
			outboundApproverActorId: "operator",
			resolveOutboundMediaRefs: () => {
				selfMediaResolutions += 1;
				return [];
			},
		});
		const { token: selfToken } = mintWhatsappConversation("self-outbound-approver");
		await expect(
			selfApproverClients.outboundPrepare(
				outboundPrepare({
					conversationToken: selfToken,
					mediaRefs: ["att_should_not_resolve_self"],
				}),
			),
		).rejects.toThrow("outbound approval denied: outboundApproverActorId must differ from actorId");
		expect(selfApproverLedger.list()).toEqual([]);
		expect(selfMediaResolutions).toBe(0);
		expect(selfApproverEdgeRuntime.prepareOutboundCalls).toBe(0);
	});

	it("returns attachment metadata only and validates refs against the authority actor", async () => {
		const clients = createTelclaudeLiveMcpRelayClients({
			ledger: testLedger(),
			validateAttachment: (ref, options) => {
				if (options?.actorUserId !== "operator") {
					return { valid: false, reason: "Actor mismatch" };
				}
				return {
					valid: true,
					attachment: {
						ref,
						actorUserId: "operator",
						providerId: "bank",
						filepath: "/private/provider/raw.pdf",
						filename: "statement.pdf",
						mimeType: "application/pdf",
						size: 1234,
						createdAt: 1000,
						expiresAt: 2000,
					} satisfies AttachmentRef,
				};
			},
		});

		const result = await clients.attachmentGet(attachmentGet({ ref: "att_statement" }));
		expect(result).toEqual({
			ref: "att_statement",
			providerId: "bank",
			filename: "statement.pdf",
			mimeType: "application/pdf",
			size: 1234,
			createdAt: 1000,
			expiresAt: 2000,
		});
		expect(result).not.toHaveProperty("filepath");
		expect(result).not.toHaveProperty("actorUserId");
	});

	it("redacts audit payloads before handing them to the audit sink", async () => {
		const auditEntries: unknown[] = [];
		const clients = createTelclaudeLiveMcpRelayClients({
			ledger: testLedger(),
			auditNote: (entry) => {
				auditEntries.push(entry);
			},
		});

		await expect(
			clients.auditNote({
				...privateStamp(),
				kind: "provider.debug",
				payload: {
					message: "token sk-proj-abcdefghijklmnopqrstuvwxyz1234567890",
				},
			}),
		).resolves.toEqual({ stored: true });
		expect(JSON.stringify(auditEntries)).not.toContain("sk-proj-abcdefghijklmnopqrstuvwxyz");
	});

	it("uses a real default audit sink instead of silently faking storage", async () => {
		const clients = createTelclaudeLiveMcpRelayClients({ ledger: testLedger() });

		await expect(
			clients.auditNote({
				...privateStamp(),
				kind: "memory.review",
				payload: { summary: "operator-visible event" },
			}),
		).resolves.toEqual({ stored: true });
	});

	it("runtime factory wires adapters to the same ledger used for execute authorization", async () => {
		const runtime = await startTelclaudeLiveMcpRuntime({
			nowMs: () => 2_000,
			config: {
				enabled: true,
				host: "127.0.0.1",
				port: 0,
				path: "/mcp",
				networkName: "telclaude-hermes-private",
				runtimeTransportToken: "tc-live-mcp-runtime-token",
			},
			createRelayClients: ({ ledger }) =>
				createTelclaudeLiveMcpRelayClients({
					ledger,
					makeApprovalRequestId: () => "runtime-approval",
					providerWriteApproverActorId: "operator:provider-approver",
					outboundApproverActorId: "operator:outbound-approver",
				}),
		});
		try {
			const prepared = await runtime.issueProbeTokenBundle({
				privateConnection: {
					sessionKey: "telegram:ops",
					profileId: "ops",
					endpointId: "endpoint-private",
					networkNamespace: "netns-private",
				},
				wrongConnection: {
					sessionKey: "telegram:social",
					profileId: "social",
					endpointId: "endpoint-social",
					networkNamespace: "netns-social",
				},
				privateAuthority: {
					...privateStamp(),
					providerScopes: ["bank"],
					outboundChannels: ["whatsapp"],
				},
				nowMs: 1_000,
				ttlMs: 60_000,
				peerAddress: "127.0.0.1",
			});
			const response = await postRpc(runtime.endpoint?.url, prepared.allowed.authorizationHeader, {
				jsonrpc: "2.0",
				id: "prepare",
				method: "tools/call",
				params: {
					name: "tc_provider_prepare_write",
					arguments: {
						service: "bank",
						action: "transfer.execute",
						params: { amount: 10 },
					},
				},
			});
			// tools/call returns an MCP CallToolResult; the bridge payload is in structuredContent.
			const body = response.body as { result?: { structuredContent?: { actionRef?: string } } };
			expect(response.httpStatus).toBe(200);
			expect(runtime.ledger?.get(body.result?.structuredContent?.actionRef ?? "")).toMatchObject({
				kind: "provider",
				status: "prepared",
				params: { amount: 10 },
			});
		} finally {
			await runtime.stop();
		}
	});
});

function testLedger() {
	return createTelclaudeMcpSideEffectLedger({
		makeRef: makeRefs(),
		verifyApproval: async () => ({
			ok: false,
			code: "approval_required",
			reason: "test verifier not used by prepare",
		}),
	});
}

function makeRefs(): () => string {
	let ref = 0;
	return () => `effect-test-${++ref}`;
}

function makeApprovalIds(): () => string {
	let id = 0;
	return () => `approval-${++id}`;
}

const mediaGateOwner = {
	actorId: "household:whatsapp:parent-a",
	subjectUserId: "household:parent-a",
	profileId: "parent-a",
	bindingId: "parent-a",
	conversationId: "whatsapp:household:parent-a",
	senderPrincipalHash: `sha256:${"c".repeat(64)}` as const,
};

function eligibleMediaGate(turnRef: string) {
	const gate = createMediaActionConfirmationStore({
		encryptionKey: "media-confirmation-test-key-32-chars",
		makeConfirmationId: () => `media-confirmation-${turnRef.slice(-8)}`,
		makeJti: () => `jti-${turnRef.slice(-8)}`,
	});
	gate.registerTurnDerivation({
		turnRef,
		owner: mediaGateOwner,
		envelopes: [
			{
				kind: "document_extract",
				text: "נא לחדש את המרשם",
				sourceSha256: "d".repeat(64),
				sourceMediaType: "image/jpeg",
				sourcePageCount: 1,
				extractor: "openai_responses_document_extract_v1",
				confidenceSource: "document_confidence_unavailable_v1",
				confirmed: false,
				confidencePolicyVersion: "media-confidence.v1",
				lowConfidence: true,
				lowConfidenceReasonCodes: ["document_confidence_unavailable"],
				classifierVersion: "derived-media-action-classifier.v1",
				actionBearing: true,
				actionBearingReasonCodes: ["action_verb"],
			},
		],
	});
	return gate;
}

function futureJerusalemMinute(minutesFromNow: number): string {
	const parts = new Intl.DateTimeFormat("en-CA", {
		timeZone: "Asia/Jerusalem",
		year: "numeric",
		month: "2-digit",
		day: "2-digit",
		hour: "2-digit",
		minute: "2-digit",
		hourCycle: "h23",
	}).formatToParts(Date.now() + minutesFromNow * 60_000);
	const value = (name: string) => parts.find((part) => part.type === name)?.value;
	return `${value("year")}-${value("month")}-${value("day")}T${value("hour")}:${value("minute")}`;
}

const mediaConfirmationHouseholdConfig = {
	householdReminders: { enabled: true },
	profiles: [
		{
			id: "parent-a",
			label: "Parent A",
			allowedSkills: [],
			providerScopes: ["clalit"],
			capabilityScopes: ["schedule.read", "schedule.write"],
			outboundChannels: ["whatsapp"],
			whatsappHouseholdBindings: [
				{
					bindingId: "parent-a",
					remindersEnabled: true,
					addresseeGender: "f",
					address: "whatsapp:+15557654321",
					replyAddress: "whatsapp:+15557654321",
					displayName: "Parent A",
					subjectUserId: "household:parent-a",
					reminderConsent: {
						state: "granted",
						ceremonyVersion: "phase0.v1",
						ceremonyHash: `sha256:${"a".repeat(64)}`,
						verifiedChannelHash:
							"sha256:a0237ae1db3c517ae525a8b60cb1b956bf87d4369f0b7533204cd7706236bce6",
						categories: {
							proactiveDelivery: true,
							scheduleManagement: true,
							retentionDisclosure: true,
						},
						recordedAt: "2026-07-17T09:00:00.000Z",
						operatorId: "operator:phase0-admin",
					},
				},
			],
		},
	],
} as TelclaudeConfig;

class CountingEdgeRuntime extends TelclaudeEdgeRuntime {
	prepareOutboundCalls = 0;

	override prepareOutbound(
		input: Parameters<TelclaudeEdgeRuntime["prepareOutbound"]>[0],
	): ReturnType<TelclaudeEdgeRuntime["prepareOutbound"]> {
		this.prepareOutboundCalls += 1;
		return super.prepareOutbound(input);
	}
}

function privateStamp(
	overrides: Partial<TelclaudeMcpAuthorityStamp> = {},
): TelclaudeMcpAuthorityStamp {
	return {
		actorId: "operator",
		profileId: "ops",
		domain: "private",
		memorySource: "telegram:ops",
		writableNamespace: "private:ops",
		endpointId: "endpoint-private",
		networkNamespace: "netns-private",
		...overrides,
	};
}

function socialStamp(
	overrides: Partial<TelclaudeMcpAuthorityStamp> = {},
): TelclaudeMcpAuthorityStamp {
	return {
		actorId: "social-agent",
		profileId: "social",
		domain: "social",
		memorySource: "social",
		writableNamespace: "social:public",
		endpointId: "endpoint-social",
		networkNamespace: "netns-social",
		...overrides,
	};
}

function householdStamp(
	overrides: Partial<TelclaudeMcpAuthorityStamp> = {},
): TelclaudeMcpAuthorityStamp {
	return {
		actorId: "household:whatsapp:parent-a",
		subjectUserId: "household:parent-a",
		profileId: "parent-a",
		domain: "household",
		memorySource: "household:parent-a",
		writableNamespace: "household:parent-a",
		providerScopes: ["clalit"],
		outboundChannels: ["whatsapp"],
		endpointId: "endpoint-household",
		networkNamespace: "netns-household",
		...overrides,
	};
}

function householdReplyBindingResolver(principalId: string) {
	return (input: { actorId: string; subjectUserId: string; profileId: string }) => ({
		bindingId: "parent-a",
		actorId: input.actorId,
		subjectUserId: input.subjectUserId,
		profileId: input.profileId,
		principalId,
		replyPrincipalId: principalId,
		identityAssurance: "strong_link" as const,
		pairingAttested: true as const,
		revoked: false as const,
	});
}

function memorySearch(
	overrides: Partial<TelclaudeMcpMemorySearchRequest> = {},
): TelclaudeMcpMemorySearchRequest {
	return {
		...privateStamp(),
		query: "operator",
		limit: 10,
		...overrides,
	};
}

function memoryWrite(
	overrides: Partial<TelclaudeMcpMemoryWriteRequest> = {},
): TelclaudeMcpMemoryWriteRequest {
	return {
		...privateStamp(),
		id: "private-1",
		category: "profile",
		content: "operator memory",
		trust: "trusted",
		...overrides,
	};
}

function providerRead(
	overrides: Partial<TelclaudeMcpProviderReadRequest> = {},
): TelclaudeMcpProviderReadRequest {
	return {
		...privateStamp(),
		providerId: "bank",
		service: "bank",
		action: "balances.list",
		params: {},
		...overrides,
	};
}

function providerPrepare(
	overrides: Partial<TelclaudeMcpProviderPrepareWriteRequest> = {},
): TelclaudeMcpProviderPrepareWriteRequest {
	return {
		...privateStamp(),
		providerId: "bank",
		service: "bank",
		action: "transfer.execute",
		params: { amount: 10 },
		...overrides,
	};
}

function outboundPrepare(
	overrides: Partial<TelclaudeMcpOutboundPrepareRequest> = {},
): TelclaudeMcpOutboundPrepareRequest {
	return {
		...privateStamp(),
		conversationToken: `conv_${"1".repeat(32)}`,
		body: "hello",
		mediaRefs: [],
		outboundChannels: ["whatsapp"],
		...overrides,
	};
}

function mintWhatsappConversation(
	suffix: string,
	overrides: Partial<Parameters<ReturnType<typeof createRelayConversationStore>["mint"]>[0]> = {},
): { token: string } {
	const store = createRelayConversationStore();
	return store.mint({
		channel: "whatsapp",
		conversationId: `conversation-${suffix}`,
		threadId: `thread-${suffix}`,
		profileId: "ops",
		domain: "private",
		routingSession: {
			sessionId: `session-${suffix}`,
			routeKey: `route-${suffix}`,
		},
		members: [
			{
				actorId: "operator",
				principalId: "+15557654321",
				role: "sender",
				scopes: ["message:reply"],
			},
			{
				actorId: `actor:${suffix}:recipient`,
				principalId: "+15551234567",
				role: "recipient",
			},
		],
		...overrides,
	});
}

function mintWhatsappTurn(
	conversationToken: string,
	suffix: string,
	overrides: Partial<
		Parameters<ReturnType<typeof createRelayConversationStore>["mintInboundTurn"]>[0]
	> = {},
): string {
	const { turnRef } = createRelayConversationStore().mintInboundTurn({
		conversationToken,
		inboundMessageId: `message-${suffix}`,
		senderActorId: "operator",
		...overrides,
	});
	return turnRef;
}

function attachmentGet(
	overrides: Partial<TelclaudeMcpAttachmentGetRequest> = {},
): TelclaudeMcpAttachmentGetRequest {
	return {
		...privateStamp(),
		ref: "att_123",
		...overrides,
	};
}

async function postRpc(
	url: string | undefined,
	authorizationHeader: string,
	body: Record<string, unknown>,
): Promise<{ httpStatus: number; body: unknown }> {
	if (!url) throw new Error("runtime endpoint URL missing");
	const response = await fetch(url, {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			Authorization: authorizationHeader,
		},
		body: JSON.stringify(body),
	});
	return {
		httpStatus: response.status,
		body: (await response.json()) as unknown,
	};
}
