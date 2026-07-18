import { describe, expect, it, vi } from "vitest";
import { edgePreparedPayloadHash } from "../../src/hermes/edge-adapter-runtime.js";
import { createSideEffectHumanApprovalController } from "../../src/hermes/mcp/side-effect-human-approval.js";
import {
	createTelclaudeMcpSideEffectLedger,
	getTelclaudeMcpSideEffectApprovalBinding,
	type TelclaudeMcpOutboundSideEffectPrepareInput,
} from "../../src/hermes/mcp/side-effect-ledger.js";
import { createHouseholdMetricsDigestExecutor } from "../../src/household-metrics/digest.js";
import {
	HOUSEHOLD_REMINDER_CONFIRMATION_COPY,
	householdReminderProposalPrompt,
} from "../../src/household-reminders/copy.js";
import type { HouseholdReminder } from "../../src/household-reminders/types.js";
import { HOUSEHOLD_EMERGENCY_COPY } from "../../src/relay/household-emergency-copy.js";
import { createHouseholdEmergencyNotifier } from "../../src/relay/household-emergency-notifier.js";
import { MEDIA_ACTION_CONFIRMATION_COPY } from "../../src/relay/media-action-confirmation-copy.js";
import { redactHouseholdSinkText } from "../../src/security/household-redactor.js";
import { redactSecrets } from "../../src/security/output-filter.js";
import { approvalRenderer } from "../../src/telegram/cards/renderers/approval.js";
import { approvalScopeRenderer } from "../../src/telegram/cards/renderers/approval-scope.js";
import { type CardInstance, CardKind } from "../../src/telegram/cards/types.js";

const NOW_MS = Date.parse("2026-07-18T12:00:00.000Z");

const SENSITIVE_CASES = [
	{ name: "checksum-valid Israeli ID / Clalit member ID", raw: "123456782" },
	{ name: "Hebrew OTP", raw: "קוד 654321" },
	{ name: "English OTP", raw: "OTP: 765432" },
	{ name: "local mobile", raw: "050-123-4567" },
	{ name: "international mobile", raw: "+972 50-123-4567" },
	{ name: "local landline", raw: "03-123-4567" },
	{ name: "compact E.164", raw: "+972501234567" },
	{ name: "API key shape", raw: "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345" },
] as const;

const HOUSEHOLD_SINKS = [
	{ name: "household outbound approval display", probe: probeHouseholdApprovalDisplay },
	{ name: "approval card render and explain", probe: probeApprovalCard },
	{ name: "emergency trigger preview", probe: probeEmergencyTriggerPreview },
	{ name: "reminder proposal prompt", probe: probeReminderProposalPrompt },
] as const;

describe("household sink DLP coverage matrix", () => {
	for (const sink of HOUSEHOLD_SINKS) {
		it.each(SENSITIVE_CASES)(`${sink.name} removes $name`, async ({ raw }) => {
			const output = await sink.probe(raw);
			expect(output).not.toContain(raw);
		});
	}

	it.each(SENSITIVE_CASES)("household redactor removes $name", ({ raw }) => {
		expect(redactHouseholdSinkText(raw)).not.toContain(raw);
	});

	it("generic approval explain independently removes CORE secrets", async () => {
		const raw = "ת.ז. 123456782, קוד 654321";
		const sent = vi.fn(async () => undefined);

		await approvalRenderer.execute({
			action: { type: "explain" },
			card: approvalCard(raw),
			ctx: { api: { sendMessage: sent } },
		} as never);

		expect(sent.mock.calls[0]?.[1]).not.toContain("123456782");
		expect(sent.mock.calls[0]?.[1]).not.toContain("654321");
	});

	it("generic approval-scope rendering removes CORE secrets", () => {
		const raw = "ת.ז. 123456782, קוד 654321";
		const rendered = approvalScopeRenderer.render(approvalScopeCard(raw));

		expect(rendered.text).not.toContain("123456782");
		expect(rendered.text).not.toContain("654321");
	});
});

describe("household sink DLP controls", () => {
	it("redacts the approval display without mutating the signed household binding", async () => {
		const raw = "פרטי קשר 050-123-4567";
		const { approvalBody, record } = await requestHouseholdApproval(raw);
		const binding = getTelclaudeMcpSideEffectApprovalBinding(record);

		expect(binding.kind).toBe("outbound");
		if (binding.kind !== "outbound") throw new Error("expected outbound binding");
		expect(binding.requestedBody).toContain(raw);
		expect(approvalBody).not.toContain(raw);
	});

	it("keeps the global CORE filter unchanged for Israeli phone numbers", () => {
		for (const phone of SENSITIVE_CASES.filter(({ name }) => name.includes("mobile"))) {
			expect(redactSecrets(phone.raw)).toBe(phone.raw);
		}
	});

	it("[WARN known gap] preserves address-like Hebrew text", () => {
		const address = "רחוב הרצל 12, תל אביב";
		expect(redactHouseholdSinkText(address)).toBe(address);
	});

	it("keeps fixed emergency, media, and reminder copy byte-stable", () => {
		expect(HOUSEHOLD_EMERGENCY_COPY).toEqual({
			f: "אם זה מצב חירום רפואי, חייגי עכשיו 101. אני לא שירות חירום ואי אפשר להסתמך עליי במצב חירום.",
			m: "אם זה מצב חירום רפואי, חייג עכשיו 101. אני לא שירות חירום ואי אפשר להסתמך עליי במצב חירום.",
		});
		expect(MEDIA_ACTION_CONFIRMATION_COPY.f.confirmed).toBe("האישור התקבל. הפעולה ממשיכה עכשיו.");
		expect(MEDIA_ACTION_CONFIRMATION_COPY.m.rejected).toBe(
			"הפעולה בוטלה. המידע מהקובץ לא ישמש לביצוע הפעולה.",
		);
		expect(HOUSEHOLD_REMINDER_CONFIRMATION_COPY.f.confirmed).toBe("התזכורת נקבעה.");
		expect(HOUSEHOLD_REMINDER_CONFIRMATION_COPY.m.rejected).toBe("התזכורת בוטלה.");
	});

	it("keeps the W2 metrics digest content-free", async () => {
		const sendAdminAlert = vi.fn(async () => undefined);
		const execute = createHouseholdMetricsDigestExecutor({
			nowMs: () => Date.parse("2026-07-18T05:00:00.000Z"),
			collectRollups: () => [{ bindingKey: "parent-a", metricKind: "inbound_received", count: 4 }],
			sendAdminAlert,
		});

		await execute();
		const alert = sendAdminAlert.mock.calls[0]?.[0];
		expect(alert).toEqual({
			level: "info",
			title: "Household metrics — 2026-07-17",
			message: "parent-a · inbound_received: 4",
		});
		for (const { raw } of SENSITIVE_CASES) {
			expect(`${alert?.title}\n${alert?.message}`).not.toContain(raw);
		}
	});
});

async function probeHouseholdApprovalDisplay(raw: string): Promise<string> {
	return (await requestHouseholdApproval(raw)).approvalBody;
}

async function requestHouseholdApproval(raw: string) {
	const body = `פרטי הבקשה: ${raw}`;
	const resolvedDestination = {
		kind: "address" as const,
		addressRef: "whatsapp:household:parent-a",
		conversationId: "whatsapp:household:parent-a",
	};
	const input: TelclaudeMcpOutboundSideEffectPrepareInput = {
		kind: "outbound",
		actorId: "household:whatsapp:parent-a",
		approverActorId: "telegram:operator",
		profileId: "parent-a",
		domain: "household",
		subjectUserId: "household:parent-a",
		channel: "whatsapp",
		destination: "parent-a",
		resolvedDestination,
		requestedBody: body,
		renderedBody: body,
		mediaRefs: [],
		preparedMediaRefs: [],
		conversationRef: `conv_${"1".repeat(32)}`,
		authorizationState: "authorized",
		edgePreparedRef: "edge-household-dlp-matrix",
		edgePreparedHash: edgePreparedPayloadHash({
			channel: "whatsapp",
			resolvedDestination,
			body,
			mediaRefs: [],
		}),
		approvalRequestId: "approval-household-dlp-matrix",
		approvalRevision: 1,
		approvalMetadata: {
			source: "hermes-live-mcp",
			pairedProvenance: true,
			replyCapableActorSeat: true,
		},
		turnConversationRef: `turn_${"2".repeat(32)}`,
		idempotencyKey: "idem-household-dlp-matrix",
		householdReplyBinding: {
			bindingId: "parent-a",
			subjectUserId: "household:parent-a",
			senderPrincipalHash: `sha256:${"a".repeat(64)}`,
			recipientPrincipalHash: `sha256:${"a".repeat(64)}`,
			identityAssurance: "strong_link",
		},
	};
	const ledger = createTelclaudeMcpSideEffectLedger({
		nowMs: () => 100_000,
		makeRef: () => "effect-household-dlp-matrix",
		defaultTtlMs: 300_000,
		verifyApproval: async () => ({ ok: false, code: "approval_required", reason: "unused" }),
	});
	const record = ledger.prepare(input);
	let capturedBody = "";
	const controller = createSideEffectHumanApprovalController({
		nowMs: () => 100_000,
		createApproval: (entry) => {
			capturedBody = entry.body;
			return { nonce: "approval1", createdAt: 100_000, expiresAt: 400_000 };
		},
		mintApprovalToken: async () => "unused",
	});

	const result = await controller.request({ record, chatId: 111 });
	if (!result.ok) throw new Error(result.reason);
	return { approvalBody: capturedBody, record };
}

async function probeApprovalCard(raw: string): Promise<string> {
	const body = redactHouseholdSinkText(`פרטי הבקשה: ${raw}`);
	const card = approvalCard(body);
	const rendered = approvalRenderer.render(card);
	const sent = vi.fn(async () => undefined);
	await approvalRenderer.execute({
		action: { type: "explain" },
		card,
		ctx: { api: { sendMessage: sent } },
	} as never);
	return `${rendered.text}\n${sent.mock.calls[0]?.[1] ?? ""}`;
}

async function probeEmergencyTriggerPreview(raw: string): Promise<string> {
	const sendAdminAlert = vi.fn(async () => undefined);
	const notify = createHouseholdEmergencyNotifier({
		sendControl: vi.fn(async () => true),
		sendAdminAlert,
		nowMs: () => NOW_MS,
	});
	await notify({
		event: {
			schemaVersion: "telclaude.edge.whatsapp.inbound.v1",
			eventId: "wa-event-dlp-matrix",
			messageId: "wa-message-dlp-matrix",
			cursorSequence: 1,
			chatKind: "direct",
			senderAddressRef: "whatsapp:parent-a",
			conversationKey: "parent-a@s.whatsapp.net",
			text: `כאב בחזה, פרטים: ${raw}`,
			attachments: [],
			receivedAtMs: NOW_MS,
		},
		identity: {
			actorId: "household:whatsapp:parent-a",
			profileId: "parent-a",
			principalId: "whatsapp:parent-a",
			displayName: "Parent A",
			identityAssurance: "strong_link",
			authorizationScopes: ["message:read", "message:reply"],
			actorScopes: [
				{ scope: "message:reply", actions: ["reply"], grantedAt: new Date(0).toISOString() },
			],
			humanPairingProvenance: true,
			domain: "household",
			bindingId: "parent-a",
			addresseeGender: "f",
			subjectUserId: "household:parent-a",
			memorySource: "household:parent-a",
			writableNamespace: "household:parent-a",
			replyAddressRef: "whatsapp:parent-a",
			expectedConversationKey: "parent-a@s.whatsapp.net",
			conversationId: "whatsapp:household:parent-a",
		},
		ensureConversation: () => undefined,
	});
	return sendAdminAlert.mock.calls[0]?.[0]?.message ?? "";
}

function probeReminderProposalPrompt(raw: string): string {
	const reminder = {
		id: "reminder-household-dlp-matrix",
		revision: 1,
		text: `פרטי תזכורת: ${raw}`,
		schedule: { localDateTime: "2026-07-20T10:00:00" },
	} as HouseholdReminder;
	return householdReminderProposalPrompt("create", reminder, "f");
}

function approvalCard(body: string): CardInstance<typeof CardKind.Approval> {
	return {
		cardId: "card-approval-dlp-matrix",
		shortId: "a1b2c3d4",
		kind: CardKind.Approval,
		version: 1,
		chatId: 111,
		messageId: 222,
		actorScope: "user:111",
		entityRef: "approval:dlp-matrix",
		revision: 1,
		state: { kind: CardKind.Approval, title: "אישור", body },
		expiresAt: NOW_MS + 60_000,
		status: "active",
		createdAt: NOW_MS,
		updatedAt: NOW_MS,
	};
}

function approvalScopeCard(body: string): CardInstance<typeof CardKind.ApprovalScope> {
	return {
		cardId: "card-approval-scope-dlp-matrix",
		shortId: "b1c2d3e4",
		kind: CardKind.ApprovalScope,
		version: 1,
		chatId: 111,
		messageId: 223,
		actorScope: "user:111",
		entityRef: "approval:scope-dlp-matrix",
		revision: 1,
		state: {
			kind: CardKind.ApprovalScope,
			title: "אישור",
			body,
			toolKey: "household:test",
			riskTier: "high",
			scopesEnabled: ["once"],
		},
		expiresAt: NOW_MS + 60_000,
		status: "active",
		createdAt: NOW_MS,
		updatedAt: NOW_MS,
	};
}
