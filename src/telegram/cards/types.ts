import type { CallbackQueryContext, Context, InlineKeyboard } from "grammy";

export enum CardKind {
	Approval = "Approval",
	ApprovalScope = "ApprovalScope",
	PendingQueue = "PendingQueue",
	Status = "Status",
	Auth = "Auth",
	Heartbeat = "Heartbeat",
	SkillDraft = "SkillDraft",
	SkillsMenu = "SkillsMenu",
	SocialMenu = "SocialMenu",
	Session = "Session",
	BackgroundJob = "BackgroundJob",
	BackgroundJobList = "BackgroundJobList",
	SystemHealth = "SystemHealth",
	ModelPicker = "ModelPicker",
	ProviderList = "ProviderList",
	SkillPicker = "SkillPicker",
	SkillReview = "SkillReview",
}

export type CardStatus = "active" | "consumed" | "expired" | "superseded";

export type CardActorScope = `user:${number}` | `chat:${number}` | "admin" | string;

export type CardListEntry = {
	id: string;
	label: string;
	summary?: string;
};

export type ApprovalCardState = {
	kind: CardKind.Approval;
	title: string;
	body: string;
	explanation?: string;
	approved?: boolean;
	denied?: boolean;
};

/**
 * W1 — Graduated approval card. Four buttons: once / session / always / deny.
 * The chosen scope is reflected back to the UI before the card enters the
 * terminal (consumed) state.
 */
export type ApprovalScopeCardState = {
	kind: CardKind.ApprovalScope;
	title: string;
	body: string;
	toolKey: string;
	riskTier: "low" | "medium" | "high";
	scopesEnabled: Array<"once" | "session" | "always">;
	scopeChosen?: "once" | "session" | "always";
	denied?: boolean;
	explanation?: string;
};

export type PendingQueueCardState = {
	kind: CardKind.PendingQueue;
	title: string;
	entries: CardListEntry[];
	page?: number;
	total?: number;
	selectedEntryId?: string;
};

export type StatusCardView = "overview" | "sessions" | "cron";

export type StatusCardState = {
	kind: CardKind.Status;
	title: string;
	summary: string;
	details?: string[];
	lastRefreshedAt?: number;
	view?: StatusCardView;
	sessionKey?: string;
};

export type AuthCardState = {
	kind: CardKind.Auth;
	title: string;
	step: "setup" | "verify" | "complete" | "skipped";
	summary?: string;
	localUserId?: string;
};

export type HeartbeatCardState = {
	kind: CardKind.Heartbeat;
	title: string;
	services: CardListEntry[];
	lastRunAt?: number;
};

export type SkillDraftCardState = {
	kind: CardKind.SkillDraft;
	title: string;
	drafts: CardListEntry[];
	page?: number;
	selectedDraftName?: string;
};

export type SkillsMenuCardState = {
	kind: CardKind.SkillsMenu;
	title: string;
	activeSkills: CardListEntry[];
	draftCount: number;
	adminControlsEnabled: boolean;
	sessionKey?: string;
	lastRefreshedAt?: number;
};

export type SocialMenuCardState = {
	kind: CardKind.SocialMenu;
	title: string;
	services: CardListEntry[];
	queueCount?: number;
	adminControlsEnabled: boolean;
	lastRefreshedAt?: number;
};

export type SessionCardState = {
	kind: CardKind.Session;
	title: string;
	summary: string;
	sessionKey?: string;
	historyPreview?: string[];
};

export type BackgroundJobCardState = {
	kind: CardKind.BackgroundJob;
	title: string;
	description?: string;
	/** Short id surfaced in Telegram text + callback entity ref. */
	shortId: string;
	/** Payload kind for header icon. */
	payloadKind: string;
	status: "queued" | "running" | "completed" | "failed" | "cancelled" | "interrupted";
	/** One-line summary of the terminal result. */
	resultSummary?: string;
	/** Truncated stdout/stderr preview. */
	outputPreview?: string;
	errorMessage?: string;
	createdAtMs: number;
	startedAtMs?: number;
	completedAtMs?: number;
	lastRefreshedAtMs?: number;
};

export type BackgroundJobListCardState = {
	kind: CardKind.BackgroundJobList;
	title: string;
	entries: Array<{
		shortId: string;
		label: string;
		status: BackgroundJobCardState["status"];
		createdAtMs: number;
	}>;
	lastRefreshedAtMs?: number;
};

/**
 * W10 — `/system health` live snapshot card.
 *
 * Two view modes: "list" shows all health items with inline status icons;
 * "remediation" shows a single item's remediation command plus "back" nav.
 */
export type SystemHealthView = "list" | "remediation";

export type SystemHealthStatus = "ok" | "degraded" | "auth_expired" | "unreachable" | "unknown";

export type SystemHealthCardItem = {
	id: string;
	label: string;
	status: SystemHealthStatus;
	detail?: string;
	/** Remediation key (from `remediation-commands.ts`); undefined means no fix surfaced. */
	remediationKey?: string;
	/** Monotonic ms when the probe completed (for "fresh" indicator). */
	observedAtMs?: number;
};

export type SystemHealthCardState = {
	kind: CardKind.SystemHealth;
	title: string;
	view: SystemHealthView;
	overallStatus: SystemHealthStatus;
	items: SystemHealthCardItem[];
	issueCount: number;
	collectedAtMs: number;
	/** When view="remediation", the selected item id. */
	selectedItemId?: string;
};

/**
 * W2 — Shared list pagination metadata for interactive pickers.
 *
 * Pagination cursor is kept entirely in server-side state; callback
 * tokens only carry action verbs (page-next / page-prev / select-N).
 */
export type PickerListEntry = {
	id: string;
	label: string;
	summary?: string;
	icon?: string;
};

export type ModelPickerEntry = {
	id: string;
	label: string;
	/** Marketing tier (e.g. "frontier", "fast"). */
	tier?: string;
	/** One-line description. */
	summary?: string;
};

export type ModelPickerProvider = {
	id: string;
	label: string;
	models: ModelPickerEntry[];
};

export type ModelPickerView = "providers" | "models";

export type ModelPickerCardState = {
	kind: CardKind.ModelPicker;
	title: string;
	providers: ModelPickerProvider[];
	/** Active provider for the models view. */
	selectedProviderId?: string;
	/** View-level pagination cursor (persisted server-side). */
	page?: number;
	view: ModelPickerView;
	/** Currently active model (persisted selection). */
	currentModelId?: string;
	currentProviderId?: string;
	/** Permission tier for the viewer (rendered in header). */
	viewerTier?: string;
	/** Whether write actions are permitted (WRITE_LOCAL+). */
	canMutate: boolean;
	/** Human-readable fallback state (e.g. "primary"|"fallback"). */
	fallbackState?: string;
	lastRefreshedAtMs?: number;
};

export type ProviderHealthIcon = "ok" | "degraded" | "auth_expired" | "unknown";

export type ProviderListEntry = {
	id: string;
	label: string;
	description?: string;
	/** When unknown, the icon rendering falls back to question-mark. */
	health: ProviderHealthIcon;
	/** Rate-limit pressure, auth expiry, or last-error summary. */
	detail?: string;
	/** OAuth service id (for remediation hints). */
	oauthServiceId?: string;
	/** Setup command path shown in detail view. */
	setupCommand?: string;
	/** Base URL for health tap-through. */
	baseUrl?: string;
};

export type ProviderListView = "list" | "detail";

export type ProviderListCardState = {
	kind: CardKind.ProviderList;
	title: string;
	providers: ProviderListEntry[];
	selectedProviderId?: string;
	page?: number;
	view: ProviderListView;
	canMutate: boolean;
	lastRefreshedAtMs?: number;
};

export type SkillPickerEntry = {
	id: string;
	label: string;
	/** Draft skills are one-tap promotable; active skills only reloadable. */
	status: "active" | "draft";
	summary?: string;
	/**
	 * Signature badge — "trusted" when the skill ships with a verified
	 * `SKILL.md.sig`, "community" when no signature is present. The picker
	 * surfaces this as a text badge so the operator knows whether a skill
	 * is vault-signed before a tap.
	 */
	trust?: "trusted" | "community";
};

/**
 * W9 — Skill review card. Shown before promote so the operator sees the
 * scanner findings, signature state, and auto-install pattern hits all
 * in one surface. Operator taps Promote / Reject. Reject is UI-only; the
 * draft file is left in place for further editing.
 */
export type SkillReviewTrust = "trusted" | "community" | "unknown";

export type SkillReviewFindingSummary = {
	severity: "critical" | "high" | "medium" | "info";
	count: number;
};

export type SkillReviewCardState = {
	kind: CardKind.SkillReview;
	title: string;
	skillName: string;
	/** Short description extracted from frontmatter. */
	description?: string;
	/** Pre-aggregated severity counts so the renderer stays sync. */
	findingSummary: SkillReviewFindingSummary[];
	/** Total findings (sum of all severities), rendered inline in the header. */
	totalFindings: number;
	/** Blocked means critical/high findings — Promote is disabled. */
	scannerBlocked: boolean;
	/** First few finding messages, for at-a-glance review. */
	topFindings: Array<{ severity: string; message: string; file?: string }>;
	/** Signature trust badge. "unknown" means vault verification wasn't attempted. */
	trust: SkillReviewTrust;
	/** Optional detail text for the trust badge (e.g. "sha256:abcd…"). */
	trustDetail?: string;
	/** Auto-install patterns matched (brew/npm/pip/etc). */
	autoInstallPatterns: string[];
	/** True when operator (admin) can promote; false disables Promote button. */
	adminControlsEnabled: boolean;
	/** Diff summary vs prior active version (one-line counts). */
	diffSummary?: string;
	/** Promote outcome for terminal render. */
	decision?: "promoted" | "rejected";
	decisionError?: string;
};

export type SkillPickerView = "list";

export type SkillPickerCardState = {
	kind: CardKind.SkillPicker;
	title: string;
	entries: SkillPickerEntry[];
	page?: number;
	view: SkillPickerView;
	adminControlsEnabled: boolean;
	sessionKey?: string;
	lastRefreshedAtMs?: number;
};

export type CardStateMap = {
	[CardKind.Approval]: ApprovalCardState;
	[CardKind.ApprovalScope]: ApprovalScopeCardState;
	[CardKind.PendingQueue]: PendingQueueCardState;
	[CardKind.Status]: StatusCardState;
	[CardKind.Auth]: AuthCardState;
	[CardKind.Heartbeat]: HeartbeatCardState;
	[CardKind.SkillDraft]: SkillDraftCardState;
	[CardKind.SkillsMenu]: SkillsMenuCardState;
	[CardKind.SocialMenu]: SocialMenuCardState;
	[CardKind.Session]: SessionCardState;
	[CardKind.BackgroundJob]: BackgroundJobCardState;
	[CardKind.BackgroundJobList]: BackgroundJobListCardState;
	[CardKind.SystemHealth]: SystemHealthCardState;
	[CardKind.ModelPicker]: ModelPickerCardState;
	[CardKind.ProviderList]: ProviderListCardState;
	[CardKind.SkillPicker]: SkillPickerCardState;
	[CardKind.SkillReview]: SkillReviewCardState;
};

export type CardState<K extends CardKind = CardKind> = CardStateMap[K];

export type ApprovalCardAction =
	| { type: "approve" }
	| { type: "deny" }
	| { type: "explain" }
	| { type: "refresh" };

export type ApprovalScopeCardAction =
	| { type: "approve-once" }
	| { type: "approve-session" }
	| { type: "approve-always" }
	| { type: "deny" }
	| { type: "refresh" };

export type PendingQueueCardAction =
	| { type: "promote" }
	| { type: "dismiss" }
	| { type: "next" }
	| { type: "prev" }
	| { type: "refresh" };

export type StatusCardAction =
	| { type: "refresh" }
	| { type: "run-health-check" }
	| { type: "reset-session" }
	| { type: "view-sessions" }
	| { type: "view-cron" }
	| { type: "view-overview" };

export type AuthCardAction =
	| { type: "setup-2fa" }
	| { type: "verify" }
	| { type: "skip" }
	| { type: "logout" }
	| { type: "disable" };

export type HeartbeatCardAction = { type: "view-log" } | { type: "refresh" };

export type SkillDraftCardAction = { type: "promote" } | { type: "reject" } | { type: "refresh" };

export type SkillsMenuCardAction =
	| { type: "open-drafts" }
	| { type: "reload" }
	| { type: "refresh" };

export type SocialMenuCardAction =
	| { type: "queue" }
	| { type: "run" }
	| { type: "log" }
	| { type: "ask" }
	| { type: "refresh" };

export type SessionCardAction = { type: "reset" } | { type: "view-history" } | { type: "refresh" };

export type BackgroundJobCardAction = { type: "cancel-background-job" } | { type: "refresh" };

export type BackgroundJobListCardAction = { type: "refresh" };

/**
 * W10 — System health card actions.
 *
 * `fix-0`..`fix-9` open a remediation view for up to 10 issue items. The
 * button set is rendered in order of `items` — the reducer resolves N to the
 * item at that index. More than 10 issues is rare in practice; extras fall
 * back to a plain "see docs" line without a button.
 */
export type SystemHealthCardAction =
	| { type: "refresh" }
	| { type: "view-list" }
	| { type: "fix-0" }
	| { type: "fix-1" }
	| { type: "fix-2" }
	| { type: "fix-3" }
	| { type: "fix-4" }
	| { type: "fix-5" }
	| { type: "fix-6" }
	| { type: "fix-7" }
	| { type: "fix-8" }
	| { type: "fix-9" };

/** Max issues that get an inline "fix" button — must match `fix-N` action count. */
export const SYSTEM_HEALTH_MAX_FIX_BUTTONS = 10;

/**
 * W2 — Picker page size is fixed at 8 so `select-0` .. `select-7` stay
 * enumerable in CARD_ACTIONS_BY_KIND and each page fits comfortably in an
 * inline keyboard without scrolling on mobile.
 */
export const PICKER_PAGE_SIZE = 8;

export type PickerSelectAction =
	| { type: "select-0" }
	| { type: "select-1" }
	| { type: "select-2" }
	| { type: "select-3" }
	| { type: "select-4" }
	| { type: "select-5" }
	| { type: "select-6" }
	| { type: "select-7" };

export type ModelPickerCardAction =
	| PickerSelectAction
	| { type: "page-next" }
	| { type: "page-prev" }
	| { type: "back" }
	| { type: "cancel" }
	| { type: "refresh" };

export type ProviderListCardAction =
	| PickerSelectAction
	| { type: "page-next" }
	| { type: "page-prev" }
	| { type: "back" }
	| { type: "cancel" }
	| { type: "refresh" };

export type SkillPickerCardAction =
	| PickerSelectAction
	| { type: "page-next" }
	| { type: "page-prev" }
	| { type: "promote" }
	| { type: "reload" }
	| { type: "cancel" }
	| { type: "refresh" };

export type SkillReviewCardAction = { type: "promote" } | { type: "reject" } | { type: "refresh" };

export type CardActionMap = {
	[CardKind.Approval]: ApprovalCardAction;
	[CardKind.ApprovalScope]: ApprovalScopeCardAction;
	[CardKind.PendingQueue]: PendingQueueCardAction;
	[CardKind.Status]: StatusCardAction;
	[CardKind.Auth]: AuthCardAction;
	[CardKind.Heartbeat]: HeartbeatCardAction;
	[CardKind.SkillDraft]: SkillDraftCardAction;
	[CardKind.SkillsMenu]: SkillsMenuCardAction;
	[CardKind.SocialMenu]: SocialMenuCardAction;
	[CardKind.Session]: SessionCardAction;
	[CardKind.BackgroundJob]: BackgroundJobCardAction;
	[CardKind.BackgroundJobList]: BackgroundJobListCardAction;
	[CardKind.SystemHealth]: SystemHealthCardAction;
	[CardKind.ModelPicker]: ModelPickerCardAction;
	[CardKind.ProviderList]: ProviderListCardAction;
	[CardKind.SkillPicker]: SkillPickerCardAction;
	[CardKind.SkillReview]: SkillReviewCardAction;
};

export type CardAction<K extends CardKind = CardKind> = CardActionMap[K];
export type CardActionType<K extends CardKind = CardKind> = CardAction<K>["type"];

const PICKER_SELECT_ACTIONS = [
	"select-0",
	"select-1",
	"select-2",
	"select-3",
	"select-4",
	"select-5",
	"select-6",
	"select-7",
] as const;

const CARD_ACTIONS_BY_KIND = {
	[CardKind.Approval]: ["approve", "deny", "explain", "refresh"],
	[CardKind.ApprovalScope]: [
		"approve-once",
		"approve-session",
		"approve-always",
		"deny",
		"refresh",
	],
	[CardKind.PendingQueue]: ["promote", "dismiss", "next", "prev", "refresh"],
	[CardKind.Status]: [
		"refresh",
		"run-health-check",
		"reset-session",
		"view-sessions",
		"view-cron",
		"view-overview",
	],
	[CardKind.Auth]: ["setup-2fa", "verify", "skip", "logout", "disable"],
	[CardKind.Heartbeat]: ["view-log", "refresh"],
	[CardKind.SkillDraft]: ["promote", "reject", "refresh"],
	[CardKind.SkillsMenu]: ["open-drafts", "reload", "refresh"],
	[CardKind.SocialMenu]: ["queue", "run", "log", "ask", "refresh"],
	[CardKind.Session]: ["reset", "view-history", "refresh"],
	[CardKind.BackgroundJob]: ["cancel-background-job", "refresh"],
	[CardKind.BackgroundJobList]: ["refresh"],
	[CardKind.SystemHealth]: [
		"refresh",
		"view-list",
		"fix-0",
		"fix-1",
		"fix-2",
		"fix-3",
		"fix-4",
		"fix-5",
		"fix-6",
		"fix-7",
		"fix-8",
		"fix-9",
	],
	[CardKind.ModelPicker]: [
		...PICKER_SELECT_ACTIONS,
		"page-next",
		"page-prev",
		"back",
		"cancel",
		"refresh",
	],
	[CardKind.ProviderList]: [
		...PICKER_SELECT_ACTIONS,
		"page-next",
		"page-prev",
		"back",
		"cancel",
		"refresh",
	],
	[CardKind.SkillPicker]: [
		...PICKER_SELECT_ACTIONS,
		"page-next",
		"page-prev",
		"promote",
		"reload",
		"cancel",
		"refresh",
	],
	[CardKind.SkillReview]: ["promote", "reject", "refresh"],
} as const satisfies { [K in CardKind]: readonly CardActionType<K>[] };

export interface CardInstance<K extends CardKind = CardKind> {
	cardId: string;
	shortId: string;
	kind: K;
	version: number;
	chatId: number;
	messageId: number;
	threadId?: number;
	actorScope: CardActorScope;
	entityRef: string;
	revision: number;
	state: CardState<K>;
	expiresAt: number;
	status: CardStatus;
	createdAt: number;
	updatedAt: number;
}

export type CardRenderResult = {
	text: string;
	keyboard?: InlineKeyboard | null;
	parseMode?: "Markdown" | "MarkdownV2" | "HTML";
};

export type CardExecutionResult<K extends CardKind> = {
	state?: CardState<K>;
	status?: CardStatus;
	expiresAt?: number;
	callbackText?: string;
	callbackAlert?: boolean;
	rerender?: boolean;
	afterCommit?: () => Promise<void> | void;
};

export type CardExecutionContext<K extends CardKind> = {
	ctx: CallbackQueryContext<Context>;
	card: CardInstance<K>;
	action: CardAction<K>;
};

export interface CardRenderer<K extends CardKind> {
	render(card: CardInstance<K>): CardRenderResult;
	reduce(card: CardInstance<K>, action: CardAction<K>): CardState<K>;
	execute(context: CardExecutionContext<K>): Promise<CardExecutionResult<K>>;
}

export function getCardActionTypes<K extends CardKind>(kind: K): readonly CardActionType<K>[] {
	return CARD_ACTIONS_BY_KIND[kind];
}

export function parseCardAction<K extends CardKind>(kind: K, action: string): CardAction<K> | null {
	const actions = CARD_ACTIONS_BY_KIND[kind] as readonly string[];
	if (!actions.includes(action)) {
		return null;
	}
	return { type: action } as CardAction<K>;
}

export function serializeCardAction<K extends CardKind>(action: CardAction<K>): CardActionType<K> {
	return action.type;
}
