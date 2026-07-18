import crypto from "node:crypto";
import { type PreparedOutbound, PreparedOutboundSchema } from "../hermes/edge-adapter-contract.js";
import type { RelayConversationStore } from "../hermes/relay-conversation-store.js";
import { householdEmergencyCopy } from "./household-emergency-copy.js";
import type { OutboundConversationContext } from "./outbound-delivery-dispatcher.js";

const RECORD_TTL_MS = 5 * 60_000;

export type HouseholdEmergencyControlPolicyRecord = {
	readonly ref: string;
	readonly origin: "relay_system_household_emergency_control";
	readonly bindingId: string;
	readonly conversationToken: string;
	readonly preparedOutboundRef: string;
	readonly preparedOutboundHash: string;
	readonly idempotencyKey: string;
	readonly bodyHash: `sha256:${string}`;
	readonly destinationHash: `sha256:${string}`;
	readonly status: "authorized" | "executing" | "sent" | "failed";
	readonly createdAtMs: number;
	readonly expiresAtMs: number;
};

export type HouseholdEmergencyControlPolicyStore = ReturnType<
	typeof createHouseholdEmergencyControlPolicyStore
>;

export function createHouseholdEmergencyControlPolicyStore(options: {
	readonly conversationStore: RelayConversationStore;
	readonly nowMs?: () => number;
}) {
	const records = new Map<string, HouseholdEmergencyControlPolicyRecord>();
	const nowMs = options.nowMs ?? Date.now;

	function validRecord(prepared: PreparedOutbound) {
		const record = records.get(prepared.sideEffectLedgerRef);
		if (!record || record.expiresAtMs <= nowMs()) return null;
		if (
			record.preparedOutboundRef !== prepared.outboundRef ||
			record.preparedOutboundHash !== prepared.edgePreparedHash ||
			record.idempotencyKey !== prepared.idempotencyKey ||
			record.bodyHash !== digest(prepared.finalRenderedBody) ||
			record.destinationHash !== digest(JSON.stringify(prepared.resolvedDestination))
		)
			return null;
		return record;
	}

	return {
		authorize(input: {
			readonly prepared: PreparedOutbound;
			readonly bindingId: string;
			readonly addresseeGender: "f" | "m";
			readonly conversationToken: string;
			readonly eventMessageId: string;
			readonly expectedAddress: string;
		}) {
			const prepared = PreparedOutboundSchema.parse(input.prepared);
			if (prepared.channel !== "whatsapp") throw new Error("emergency control channel denied");
			if (prepared.finalRenderedBody !== householdEmergencyCopy(input.addresseeGender)) {
				throw new Error("emergency control body is not fixed emergency copy");
			}
			if (
				prepared.resolvedDestination.kind !== "address" ||
				prepared.resolvedDestination.addressRef !== input.expectedAddress
			)
				throw new Error("emergency control destination is not binding-owned");
			const ref = `emergency-control-${crypto.createHash("sha256").update(`${input.bindingId}\0${input.eventMessageId}`).digest("hex")}`;
			const authorized = PreparedOutboundSchema.parse({
				...prepared,
				outboundRef: `system-control-out:${ref}`,
				idempotencyKey: `system-control-idem:${ref}`,
				sideEffectLedgerRef: ref,
			});
			if (!records.has(ref)) {
				const now = nowMs();
				records.set(ref, {
					ref,
					origin: "relay_system_household_emergency_control",
					bindingId: input.bindingId,
					conversationToken: input.conversationToken,
					preparedOutboundRef: authorized.outboundRef,
					preparedOutboundHash: authorized.edgePreparedHash,
					idempotencyKey: authorized.idempotencyKey,
					bodyHash: digest(authorized.finalRenderedBody),
					destinationHash: digest(JSON.stringify(authorized.resolvedDestination)),
					status: "authorized",
					createdAtMs: now,
					expiresAtMs: now + RECORD_TTL_MS,
				});
			}
			return authorized;
		},
		claim(prepared: PreparedOutbound) {
			const record = validRecord(prepared);
			if (record?.status !== "authorized") return false;
			records.set(record.ref, { ...record, status: "executing" });
			return true;
		},
		complete(prepared: PreparedOutbound, sent: boolean) {
			const record = validRecord(prepared);
			if (record?.status === "executing") {
				records.set(record.ref, { ...record, status: sent ? "sent" : "failed" });
			}
		},
		async resolveConversation(
			prepared: PreparedOutbound,
		): Promise<OutboundConversationContext | null> {
			const record = validRecord(prepared);
			if (record?.status !== "executing") return null;
			const conversation = options.conversationStore.resolveAuthorized(record.conversationToken);
			if (
				conversation?.channel !== "whatsapp" ||
				conversation.domain !== "household" ||
				conversation.conversationId !== `whatsapp:household:${record.bindingId}`
			)
				return null;
			return {
				conversationToken: conversation.token,
				threadMessageIds: conversation.threadMessageIds,
			};
		},
		list() {
			return [...records.values()].map((record) => ({ ...record }));
		},
	};
}

function digest(value: string): `sha256:${string}` {
	return `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
}
