import {
	denyApproval,
	type PendingApproval,
	peekPendingApprovalByNonce,
} from "../../security/approvals.js";
import type { StepUpVerificationMetadata } from "../../security/totp-session.js";
import {
	type SideEffectHumanApprovalController,
	TELCLAUDE_MCP_SIDE_EFFECT_HUMAN_APPROVAL_TOOL_KEY_PREFIX,
} from "./side-effect-human-approval.js";
import type {
	TelclaudeMcpSideEffectLedger,
	TelclaudeMcpSideEffectRecord,
} from "./side-effect-ledger.js";

export type TelclaudeLiveMcpSideEffectApprovalBinding = {
	readonly ledger: TelclaudeMcpSideEffectLedger;
	readonly controller: SideEffectHumanApprovalController;
};

export type TelclaudeLiveMcpSideEffectApprovalPublisher = (input: {
	readonly record: Extract<TelclaudeMcpSideEffectRecord, { kind: "provider" }>;
	readonly nonce: string;
	readonly chatId: number;
	readonly createdAt: number;
	readonly expiresAt: number;
}) => void | Promise<void>;

export type TelclaudeLiveMcpSideEffectApprovalConsumeInput = {
	readonly nonce: string;
	readonly chatId: number;
	readonly stepUp?: StepUpVerificationMetadata;
};

export type TelclaudeLiveMcpSideEffectApprovalConsumeResult =
	| {
			readonly handled: true;
			readonly ok: true;
			readonly actionRef: string;
			readonly approvalId: string;
	  }
	| {
			readonly handled: true;
			readonly ok: false;
			readonly reason: string;
	  }
	| { readonly handled: false };

let activeBinding: TelclaudeLiveMcpSideEffectApprovalBinding | null = null;

export function setTelclaudeLiveMcpSideEffectApprovalBinding(
	binding: TelclaudeLiveMcpSideEffectApprovalBinding | null,
): void {
	activeBinding = binding;
}

export function requestTelclaudeLiveMcpSideEffectApproval(
	controller: SideEffectHumanApprovalController,
	record: TelclaudeMcpSideEffectRecord,
	publish?: TelclaudeLiveMcpSideEffectApprovalPublisher,
): Promise<void> {
	if (record.kind === "scheduled-outbound") {
		throw new Error("scheduled outbound cannot enter the live human approval lane");
	}
	const chatId = chatIdFromTelegramActor(record.approverActorId);
	if (chatId === null) {
		throw new Error("live MCP side-effect approverActorId must be formatted as telegram:<chat-id>");
	}
	return controller.request({ record, chatId }).then(async (requested) => {
		if (!requested.ok) {
			throw new Error(requested.reason);
		}
		if (
			publish &&
			record.kind === "provider" &&
			record.domain === "household" &&
			requested.autoGranted !== true
		) {
			try {
				await publish({
					record,
					nonce: requested.nonce,
					chatId,
					createdAt: requested.createdAt,
					expiresAt: requested.expiresAt,
				});
			} catch {
				denyApproval(requested.nonce, chatId);
				throw new Error("household provider approval notification failed");
			}
		}
	});
}

export async function consumeTelclaudeLiveMcpSideEffectApproval(
	input: TelclaudeLiveMcpSideEffectApprovalConsumeInput,
): Promise<TelclaudeLiveMcpSideEffectApprovalConsumeResult> {
	const approvalNonce = input.nonce.trim().toLowerCase();
	const pending = peekPendingApprovalByNonce(approvalNonce);
	if (!pending.success) return { handled: false };
	if (!isTelclaudeLiveMcpSideEffectApproval(pending.data)) {
		return { handled: false };
	}
	if (pending.data.chatId !== input.chatId) {
		return {
			handled: true,
			ok: false,
			reason: "This approval code belongs to a different chat.",
		};
	}
	if (!activeBinding) {
		return {
			handled: true,
			ok: false,
			reason: "Hermes side-effect approval runtime is unavailable; re-request approval.",
		};
	}
	const actionRef = pending.data.sessionKey ?? pending.data.messageId;
	const record = activeBinding.ledger.get(actionRef);
	if (!record) {
		return {
			handled: true,
			ok: false,
			reason: "Hermes side-effect approval record is unavailable; re-request approval.",
		};
	}
	// The Telegram /approve handler derives this only from trusted TOTP session
	// state. If the proof is absent or stale, the controller leaves the pending
	// approval intact and fails closed before minting side-effect tokens.
	const consumed = await activeBinding.controller.consume({
		record,
		chatId: input.chatId,
		approverActorId: telegramActorForChat(input.chatId),
		approvalNonce,
		stepUp: input.stepUp,
	});
	if (!consumed.ok) {
		return { handled: true, ok: false, reason: consumed.reason };
	}
	return {
		handled: true,
		ok: true,
		actionRef: consumed.actionRef,
		approvalId: consumed.approvalId,
	};
}

function isTelclaudeLiveMcpSideEffectApproval(approval: PendingApproval): boolean {
	return (
		approval.toolKey?.startsWith(`${TELCLAUDE_MCP_SIDE_EFFECT_HUMAN_APPROVAL_TOOL_KEY_PREFIX}:`) ??
		false
	);
}

function telegramActorForChat(chatId: number): string {
	return `telegram:${chatId}`;
}

function chatIdFromTelegramActor(actorId: string): number | null {
	const match = /^telegram:(-?\d+)$/.exec(actorId.trim());
	if (!match?.[1]) return null;
	const chatId = Number.parseInt(match[1], 10);
	return Number.isSafeInteger(chatId) ? chatId : null;
}
