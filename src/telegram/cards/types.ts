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
};

export type CardAction<K extends CardKind = CardKind> = CardActionMap[K];
export type CardActionType<K extends CardKind = CardKind> = CardAction<K>["type"];

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
