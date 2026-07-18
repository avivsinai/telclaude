export type Sha256Ref = `sha256:${string}`;

export type HouseholdReminderAuthority = {
	readonly actorId: string;
	readonly subjectUserId: string;
	readonly profileId: string;
};

export type HouseholdReminderBinding = {
	readonly bindingId: string;
	readonly conversationId: string;
	readonly senderPrincipalHash: Sha256Ref;
	readonly recipientPrincipalHash: Sha256Ref;
};

export type HouseholdReminderConsentReceipt = {
	readonly state: "granted";
	readonly ceremonyVersion: "phase0.v1";
	readonly ceremonyHash: Sha256Ref;
	readonly verifiedChannelHash: Sha256Ref;
	readonly categories: {
		readonly proactiveDelivery: true;
		readonly scheduleManagement: true;
		readonly retentionDisclosure: true;
	};
	readonly recordedAt: string;
	readonly operatorId: string;
};

export type HouseholdReminderOneShotSchedule = {
	readonly timeZone: "Asia/Jerusalem";
	readonly localDateTime: string;
	readonly resolvedAtMs: number;
	readonly resolvedAt: string;
	readonly offsetMinutes: number;
};

export type HouseholdReminderSource =
	| { readonly kind: "parent" }
	| {
			readonly kind: "clalit-appointment";
			readonly observationHash: Sha256Ref;
	  };

export type HouseholdReminderStatus =
	| "pending_confirmation"
	| "scheduled"
	| "paused_confirmation"
	| "superseded"
	| "cancelled"
	| "revoked"
	| "completed"
	| "failed_terminal";

export type HouseholdReminder = {
	readonly id: string;
	readonly revision: number;
	readonly authority: HouseholdReminderAuthority;
	readonly binding: HouseholdReminderBinding;
	readonly bindingFingerprint: Sha256Ref;
	readonly consentHash: Sha256Ref;
	readonly text: string;
	readonly label?: string;
	readonly locale: "he-IL";
	readonly source: HouseholdReminderSource;
	readonly schedule: HouseholdReminderOneShotSchedule;
	readonly contentHash: Sha256Ref;
	readonly scheduleHash: Sha256Ref;
	readonly status: HouseholdReminderStatus;
	readonly confirmedAtMs?: number;
	readonly createdAtMs: number;
	readonly updatedAtMs: number;
};

export type HouseholdReminderProposalAction = "create" | "update" | "cancel";
export type HouseholdReminderProposalStatus = "pending" | "confirmed" | "rejected" | "expired";

export type HouseholdReminderProposal = {
	readonly ref: string;
	readonly action: HouseholdReminderProposalAction;
	readonly reminderId: string;
	readonly baseRevision: number;
	readonly proposedRevision: number;
	readonly authority: HouseholdReminderAuthority;
	readonly binding: HouseholdReminderBinding;
	readonly bindingFingerprint: Sha256Ref;
	readonly consentHash: Sha256Ref;
	readonly proposalHash: Sha256Ref;
	readonly status: HouseholdReminderProposalStatus;
	readonly createdAtMs: number;
	readonly expiresAtMs: number;
};

export type HouseholdReminderFireState =
	| "claimed"
	| "prepared"
	| "dispatched"
	| "delivered"
	| "retryable_failed"
	| "dead_lettered"
	| "cancelled";

export type HouseholdReminderFire = {
	readonly fireId: string;
	readonly reminderId: string;
	readonly revision: number;
	readonly scheduledForMs: number;
	readonly state: HouseholdReminderFireState;
	readonly attemptCount: number;
	readonly leaseExpiresAtMs?: number;
	readonly outboundRef?: string;
	readonly edgePreparedHash?: string;
	readonly idempotencyKey?: string;
	readonly whatsappMessageId?: string;
	readonly receiptStatus?: string;
	readonly platformMessageIdHash?: Sha256Ref;
	readonly failureClass?: string;
	readonly createdAtMs: number;
	readonly updatedAtMs: number;
};
