import type { CallbackQueryContext, Context, InlineKeyboard } from "grammy";

export enum CardKind {
	Approval = "Approval",
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
	ModelPicker = "ModelPicker",
	ProviderList = "ProviderList",
	SkillPicker = "SkillPicker",
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
 * Shared list pagination metadata for interactive pickers.
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
	[CardKind.ModelPicker]: ModelPickerCardState;
	[CardKind.ProviderList]: ProviderListCardState;
	[CardKind.SkillPicker]: SkillPickerCardState;
};

export type CardState<K extends CardKind = CardKind> = CardStateMap[K];

export type ApprovalCardAction =
	| { type: "approve" }
	| { type: "deny" }
	| { type: "explain" }
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
 * Picker page size is fixed at 8 so `select-0` .. `select-7` stay enumerable
 * in CARD_ACTIONS_BY_KIND and each page fits comfortably in an inline
 * keyboard without scrolling on mobile.
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

export type CardActionMap = {
	[CardKind.Approval]: ApprovalCardAction;
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
	[CardKind.ModelPicker]: ModelPickerCardAction;
	[CardKind.ProviderList]: ProviderListCardAction;
	[CardKind.SkillPicker]: SkillPickerCardAction;
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
