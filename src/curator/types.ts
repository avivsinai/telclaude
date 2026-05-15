export type CuratorItemKind =
	| "cron_hardening"
	| "background_attention"
	| "memory_queue"
	| "skill_review";

export type CuratorItemStatus = "open" | "accepted" | "rejected" | "expired";
export type CuratorSeverity = "info" | "low" | "medium" | "high";
export type CuratorProducerKind = "system" | "claude-code" | "codex";

export type CuratorItem = {
	id: string;
	shortId: string;
	fingerprint: string;
	kind: CuratorItemKind;
	status: CuratorItemStatus;
	severity: CuratorSeverity;
	source: string;
	title: string;
	summary: string;
	rationale: string | null;
	entityRef: string;
	proposedAction: Record<string, unknown>;
	evidence: Record<string, unknown>;
	producerKind: CuratorProducerKind;
	producerId: string | null;
	createdAtMs: number;
	updatedAtMs: number;
	expiresAtMs: number | null;
	decidedAtMs: number | null;
	decidedBy: string | null;
	decisionReason: string | null;
};

export type CuratorItemInput = {
	fingerprint: string;
	kind: CuratorItemKind;
	severity: CuratorSeverity;
	source: string;
	title: string;
	summary: string;
	rationale?: string;
	entityRef: string;
	proposedAction: Record<string, unknown>;
	evidence: Record<string, unknown>;
	producerKind?: CuratorProducerKind;
	producerId?: string;
	expiresAtMs?: number;
};

export type CuratorScanResult = {
	createdOrUpdated: number;
	openItems: number;
	byKind: Record<string, number>;
};
