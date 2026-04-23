import { getEntries, promoteEntryTrust } from "../../../memory/store.js";
import {
	dismissSocialDraft,
	getSocialDraft,
	isActiveSocialDraftStatus,
	markSocialDraftApproved,
	markSocialDraftManuallyPosted,
	parseSocialDraftMetadata,
	parseSocialQuoteProposalMetadata,
	resolveSocialDraftStatus,
	updateSocialDraftText,
} from "../../../social/proposal-metadata.js";
import {
	createWizardPrompter,
	WizardCancelledError,
	WizardTimeoutError,
} from "../../wizard/index.js";
import type {
	CardExecutionContext,
	CardExecutionResult,
	CardInstance,
	CardKind,
	CardRenderer,
	CardRenderResult,
	PendingQueueCardAction,
	PendingQueueCardState,
	SocialDraftListEntry,
} from "../types.js";
import { btn, esc, keyboard, renderTerminalState } from "./helpers.js";

type K = typeof CardKind.PendingQueue;

const PAGE_SIZE = 4;
const MAX_DRAFT_TEXT_LENGTH = 4000;

function pageSlice(entries: SocialDraftListEntry[], page: number) {
	const start = page * PAGE_SIZE;
	return entries.slice(start, start + PAGE_SIZE);
}

function totalPages(total: number): number {
	return Math.max(1, Math.ceil(total / PAGE_SIZE));
}

/** Clamp page index to valid range after entries change. */
function clampPage(page: number, total: number): number {
	const maxPage = Math.max(0, totalPages(total) - 1);
	return Math.min(page, maxPage);
}

function draftStatusLabel(status: SocialDraftListEntry["status"]): string {
	switch (status) {
		case "queued":
			return "Ready";
		case "drafted":
			return "Drafted";
		case "needs_review":
			return "Needs review";
		case "manual_action_needed":
			return "Manual action";
		case "posted_via_api":
			return "Posted via API";
		case "marked_posted":
			return "Marked posted";
		case "dismissed":
			return "Dismissed";
		case "failed":
			return "Failed";
	}
}

function draftBadge(status: SocialDraftListEntry["status"]): string {
	switch (status) {
		case "queued":
			return "READY";
		case "drafted":
			return "DRAFT";
		case "needs_review":
			return "REVIEW";
		case "manual_action_needed":
			return "MANUAL";
		case "failed":
			return "FAILED";
		case "posted_via_api":
			return "POSTED";
		case "marked_posted":
			return "POSTED";
		case "dismissed":
			return "DISMISSED";
	}
}

function formatAgeLabel(createdAt: number): string {
	const age = Math.max(0, Math.round((Date.now() - createdAt) / 60000));
	if (age < 60) return `${age}m ago`;
	return `${Math.round(age / 60)}h ago`;
}

function previewText(content: string, maxLength: number): string {
	const collapsed = content.replace(/\s+/g, " ").trim();
	if (collapsed.length <= maxLength) return collapsed;
	return `${collapsed.slice(0, maxLength - 3)}...`;
}

function normalizeUrl(value: string | undefined): string | undefined {
	if (!value) return undefined;
	try {
		const url = new URL(value);
		if (url.protocol !== "http:" && url.protocol !== "https:") return undefined;
		return url.toString();
	} catch {
		return undefined;
	}
}

function entryFromDraftId(id: string): SocialDraftListEntry | null {
	const draft = getSocialDraft(id);
	if (!draft) return null;
	const metadata = parseSocialDraftMetadata(draft.metadata);
	const status = draft.status;
	return {
		id: draft.id,
		label: `"${previewText(draft.content, 60)}" - ${formatAgeLabel(draft.createdAt)}`,
		status,
		source: draft.source,
		ageLabel: formatAgeLabel(draft.createdAt),
		draftText: draft.content,
		...(metadata.serviceId ? { serviceId: metadata.serviceId } : {}),
		...(metadata.targetPostId ? { targetPostId: metadata.targetPostId } : {}),
		...(metadata.targetAuthor ? { targetAuthor: metadata.targetAuthor } : {}),
		...(metadata.targetExcerpt ? { targetExcerpt: metadata.targetExcerpt } : {}),
		...(normalizeUrl(metadata.targetUrl) ? { targetUrl: normalizeUrl(metadata.targetUrl) } : {}),
		...(metadata.manualActionReason ? { manualActionReason: metadata.manualActionReason } : {}),
		...(metadata.lastError ? { lastError: metadata.lastError } : {}),
		...(metadata.postedPostId ? { postedPostId: metadata.postedPostId } : {}),
		approved: Boolean(draft.promotedAt && draft.trust === "trusted"),
		canRetryApi: status === "failed" || status === "manual_action_needed",
	};
}

function refreshEntries(chatId: number | string): SocialDraftListEntry[] {
	return loadPendingQueueEntries(String(chatId));
}

function replaceEntry(
	entries: SocialDraftListEntry[],
	nextEntry: SocialDraftListEntry | null,
	targetId: string,
): SocialDraftListEntry[] {
	if (!nextEntry || !isActiveSocialDraftStatus(nextEntry.status)) {
		return entries.filter((entry) => entry.id !== targetId);
	}
	return entries.map((entry) => (entry.id === targetId ? nextEntry : entry));
}

function selectedEntry(s: PendingQueueCardState): SocialDraftListEntry | undefined {
	return s.entries.find((entry) => entry.id === s.selectedEntryId);
}

function firstVisibleEntry(s: PendingQueueCardState): SocialDraftListEntry | undefined {
	return pageSlice(s.entries, s.page ?? 0)[0];
}

function selectedOrFirstVisible(s: PendingQueueCardState): SocialDraftListEntry | undefined {
	return selectedEntry(s) ?? firstVisibleEntry(s);
}

function renderList(card: CardInstance<K>, s: PendingQueueCardState): CardRenderResult {
	const page = s.page ?? 0;
	const entries = s.entries;
	const total = s.total ?? entries.length;
	const pages = totalPages(total);
	const visible = pageSlice(entries, page);

	let text = `📋 *${esc(s.title)}*\n`;

	if (visible.length === 0) {
		text += `\n_No pending entries_`;
	} else {
		for (let i = 0; i < visible.length; i++) {
			const entry = visible[i];
			const marker = i === 0 ? "▶" : "•";
			text += `\n${marker} *${esc(entry.label)}*`;
			text += `\n  ${esc(`[${draftBadge(entry.status)}] ${entry.source}${entry.serviceId ? `/${entry.serviceId}` : ""}`)}`;
			if (entry.summary) {
				text += `\n  ${esc(entry.summary)}`;
			}
		}
	}

	if (pages > 1) {
		text += `\n\n_Page ${page + 1}/${pages}_`;
	}

	const kb = keyboard();
	if (visible.length > 0) {
		kb.text("View ▶", btn(card, "view"))
			.text("Approve ▶", btn(card, "promote"))
			.row()
			.text("Dismiss ▶", btn(card, "dismiss"))
			.text("Refresh", btn(card, "refresh"))
			.row();
	}

	if (page > 0) {
		kb.text("◀ Prev", btn(card, "prev"));
	}
	if (page < pages - 1) {
		kb.text("Next ▶", btn(card, "next"));
	}

	if (visible.length === 0) {
		kb.text("Refresh", btn(card, "refresh"));
	}

	return { text, parseMode: "MarkdownV2", keyboard: kb };
}

function renderDetail(card: CardInstance<K>, s: PendingQueueCardState): CardRenderResult {
	const entry = selectedEntry(s);
	if (!entry) {
		return renderList(card, { ...s, view: "list", selectedEntryId: undefined });
	}

	let text = `📝 *${esc(s.title)}*\n\n`;
	text += `*${esc(draftStatusLabel(entry.status))}* · ${esc(entry.source)} · ${esc(entry.ageLabel)}`;
	if (entry.serviceId) {
		text += `\nService: \`${esc(entry.serviceId)}\``;
	}
	if (entry.targetPostId || entry.targetAuthor) {
		text += `\nTarget: ${esc([entry.targetAuthor, entry.targetPostId].filter(Boolean).join(" "))}`;
	}
	if (entry.targetExcerpt) {
		text += `\nSource: ${esc(previewText(entry.targetExcerpt, 140))}`;
	}
	if (entry.manualActionReason) {
		text += `\n\n*Manual action needed:* ${esc(entry.manualActionReason)}`;
	}
	if (entry.lastError && entry.lastError !== entry.manualActionReason) {
		text += `\n\n*Last error:* ${esc(entry.lastError)}`;
	}
	if (entry.postedPostId) {
		text += `\n\nPosted id: \`${esc(entry.postedPostId)}\``;
	}

	text += `\n\n*Copy-ready text:*\n\`\`\`\n${esc(entry.draftText)}\n\`\`\``;

	const kb = keyboard();
	kb.text("Edit", btn(card, "edit")).text("Refine", btn(card, "refine")).row();
	if (entry.status !== "queued") {
		kb.text("Approve", btn(card, "promote"));
	}
	if (entry.canRetryApi) {
		kb.text("Retry API", btn(card, "retry-api"));
	}
	kb.row().text("Mark posted", btn(card, "mark-posted")).text("Dismiss", btn(card, "dismiss"));
	if (entry.targetUrl) {
		kb.row().url("Open target", entry.targetUrl);
	}
	kb.row().text("Back", btn(card, "back")).text("Refresh", btn(card, "refresh"));

	return { text, parseMode: "MarkdownV2", keyboard: kb };
}

/**
 * Load pending queue entries from memory store.
 * Shared between the initial `/social queue` command and the card's refresh action.
 */
export function loadPendingQueueEntries(chatId?: string): SocialDraftListEntry[] {
	const entries = getEntries({
		categories: ["posts"],
		sources: ["telegram", "social"],
		posted: false,
		limit: 100,
		order: "desc",
	});

	return entries
		.filter((entry) => {
			const source = entry._provenance.source;
			if (source === "telegram" && chatId && entry._provenance.chatId !== chatId) {
				return false;
			}
			if (source === "telegram" && entry._provenance.trust !== "quarantined") {
				return Boolean(entry._provenance.promotedAt);
			}
			if (source === "social" && entry._provenance.trust !== "untrusted") {
				return Boolean(entry._provenance.promotedAt);
			}
			return true;
		})
		.map((entry) => {
			const status = resolveSocialDraftStatus(entry);
			const metadata = parseSocialDraftMetadata(entry.metadata);
			const quoteMetadata = parseSocialQuoteProposalMetadata(entry.metadata);
			const summary = quoteMetadata
				? `quote${quoteMetadata.targetAuthor ? ` ${quoteMetadata.targetAuthor}` : ""}${
						quoteMetadata.targetExcerpt ? `: "${previewText(quoteMetadata.targetExcerpt, 40)}"` : ""
					}`
				: metadata.action === "thread"
					? "thread draft"
					: undefined;
			return {
				id: entry.id,
				label: `"${previewText(entry.content, 60)}" - ${formatAgeLabel(entry._provenance.createdAt)}`,
				...(summary ? { summary } : {}),
				status,
				source: entry._provenance.source,
				ageLabel: formatAgeLabel(entry._provenance.createdAt),
				draftText: entry.content,
				...(metadata.serviceId ? { serviceId: metadata.serviceId } : {}),
				...(metadata.targetPostId ? { targetPostId: metadata.targetPostId } : {}),
				...(metadata.targetAuthor ? { targetAuthor: metadata.targetAuthor } : {}),
				...(metadata.targetExcerpt ? { targetExcerpt: metadata.targetExcerpt } : {}),
				...(normalizeUrl(metadata.targetUrl)
					? { targetUrl: normalizeUrl(metadata.targetUrl) }
					: {}),
				...(metadata.manualActionReason ? { manualActionReason: metadata.manualActionReason } : {}),
				...(metadata.lastError ? { lastError: metadata.lastError } : {}),
				...(metadata.postedPostId ? { postedPostId: metadata.postedPostId } : {}),
				approved: Boolean(entry._provenance.promotedAt && entry._provenance.trust === "trusted"),
				canRetryApi: status === "failed" || status === "manual_action_needed",
			};
		})
		.filter((entry) => isActiveSocialDraftStatus(entry.status))
		.sort((a, b) => {
			const statusRank = (status: SocialDraftListEntry["status"]) =>
				status === "manual_action_needed"
					? 0
					: status === "failed"
						? 1
						: status === "needs_review"
							? 2
							: status === "drafted"
								? 3
								: 4;
			return statusRank(a.status) - statusRank(b.status);
		})
		.slice(0, 20);
}

async function runEditDraftFlow(
	context: CardExecutionContext<K>,
	entry: SocialDraftListEntry,
): Promise<void> {
	const wizard = createWizardPrompter({
		api: context.ctx.api,
		actorId: context.ctx.from.id,
		chatId: context.card.chatId,
		threadId: context.card.threadId,
	});
	try {
		const text = await wizard.text({
			message: `Send edited draft text for ${entry.id}:`,
			placeholder: entry.draftText,
			validate: (value) => {
				const trimmed = value.trim();
				if (!trimmed) return "Draft text cannot be empty.";
				if (trimmed.length > MAX_DRAFT_TEXT_LENGTH) return "Draft text is too long.";
				return undefined;
			},
		});
		const actor = `telegram:${context.card.chatId}:${context.ctx.from.id}`;
		const result = updateSocialDraftText({ id: entry.id, text, actor });
		await context.ctx.api.sendMessage(
			context.card.chatId,
			result.ok
				? `Draft ${entry.id} updated. Tap Refresh.`
				: `Draft update failed: ${result.reason}`,
			context.card.threadId === undefined
				? {}
				: {
						message_thread_id: context.card.threadId,
					},
		);
	} catch (error) {
		if (error instanceof WizardTimeoutError || error instanceof WizardCancelledError) {
			return;
		}
		await context.ctx.api.sendMessage(
			context.card.chatId,
			`Draft edit failed: ${String(error)}`,
			context.card.threadId === undefined
				? {}
				: {
						message_thread_id: context.card.threadId,
					},
		);
	} finally {
		await wizard.dismiss().catch(() => {});
	}
}

async function runRefineDraftFlow(
	context: CardExecutionContext<K>,
	entry: SocialDraftListEntry,
): Promise<void> {
	const wizard = createWizardPrompter({
		api: context.ctx.api,
		actorId: context.ctx.from.id,
		chatId: context.card.chatId,
		threadId: context.card.threadId,
	});
	try {
		const instruction = await wizard.text({
			message: `Send refinement instruction for ${entry.id}:`,
			placeholder: "make it sharper, shorter, more concrete",
			validate: (value) => (value.trim() ? undefined : "Instruction cannot be empty."),
		});
		await context.ctx.api.sendMessage(
			context.card.chatId,
			`Refining ${entry.id}...`,
			context.card.threadId === undefined
				? {}
				: {
						message_thread_id: context.card.threadId,
					},
		);
		const { refineSocialDraftText } = await import("../../../social/handler.js");
		const actor = `telegram:${context.card.chatId}:${context.ctx.from.id}`;
		const result = await refineSocialDraftText({
			id: entry.id,
			instruction: instruction.trim(),
			actor,
			serviceId: entry.serviceId,
		});
		await context.ctx.api.sendMessage(
			context.card.chatId,
			result.ok
				? `Draft ${entry.id} refined. Tap Refresh.`
				: `Draft refine failed: ${result.reason}`,
			context.card.threadId === undefined
				? {}
				: {
						message_thread_id: context.card.threadId,
					},
		);
	} catch (error) {
		if (error instanceof WizardTimeoutError || error instanceof WizardCancelledError) {
			return;
		}
		await context.ctx.api.sendMessage(
			context.card.chatId,
			`Draft refine failed: ${String(error)}`,
			context.card.threadId === undefined
				? {}
				: {
						message_thread_id: context.card.threadId,
					},
		);
	} finally {
		await wizard.dismiss().catch(() => {});
	}
}

export const pendingQueueRenderer: CardRenderer<K> = {
	render(card: CardInstance<K>): CardRenderResult {
		const s = card.state;

		const terminal = renderTerminalState(card, s.title);
		if (terminal) return terminal;

		return s.view === "detail" ? renderDetail(card, s) : renderList(card, s);
	},

	reduce(card: CardInstance<K>, action: PendingQueueCardAction): PendingQueueCardState {
		const s = { ...card.state };
		const total = s.total ?? s.entries.length;
		const pages = totalPages(total);
		const currentPage = s.page ?? 0;

		switch (action.type) {
			case "view": {
				const visible = pageSlice(s.entries, currentPage);
				return { ...s, view: "detail", selectedEntryId: visible[0]?.id };
			}
			case "back":
				return { ...s, view: "list", selectedEntryId: undefined };
			case "next":
				return {
					...s,
					view: "list",
					page: Math.min(currentPage + 1, pages - 1),
					selectedEntryId: undefined,
				};
			case "prev":
				return {
					...s,
					view: "list",
					page: Math.max(currentPage - 1, 0),
					selectedEntryId: undefined,
				};
			case "promote":
			case "dismiss":
			case "edit":
			case "refine":
			case "mark-posted":
			case "retry-api": {
				const target = selectedOrFirstVisible(s);
				return { ...s, selectedEntryId: target?.id };
			}
			case "refresh":
				return s;
		}
	},

	async execute(context: CardExecutionContext<K>): Promise<CardExecutionResult<K>> {
		const { action, card, ctx } = context;
		const s = card.state;
		const currentPage = s.page ?? 0;
		const target = selectedOrFirstVisible(s);
		const actor = `telegram:${card.chatId}:${ctx.from.id}`;

		switch (action.type) {
			case "view": {
				const visible = pageSlice(s.entries, currentPage);
				if (!visible[0]) {
					return { callbackText: "No draft to view", callbackAlert: true };
				}
				return {
					state: { ...s, view: "detail", selectedEntryId: visible[0].id },
					callbackText: "Opened draft",
					rerender: true,
				};
			}

			case "back":
				return {
					state: { ...s, view: "list", selectedEntryId: undefined },
					callbackText: "Back to queue",
					rerender: true,
				};

			case "promote": {
				if (!target) {
					return { callbackText: "No draft to approve", callbackAlert: true };
				}

				const current = getSocialDraft(target.id);
				if (!current) {
					return { callbackText: "Draft not found", callbackAlert: true };
				}
				if (!(current.trust === "trusted" && current.promotedAt)) {
					const promoteResult = promoteEntryTrust(target.id, actor);
					if (!promoteResult.ok) {
						return { callbackText: promoteResult.reason, callbackAlert: true };
					}
				}

				const approved = markSocialDraftApproved({
					id: target.id,
					actor,
					serviceId: target.serviceId,
				});
				if (!approved.ok) {
					return { callbackText: approved.reason, callbackAlert: true };
				}
				const nextEntry = entryFromDraftId(target.id);
				const nextEntries = replaceEntry(s.entries, nextEntry, target.id);
				return {
					state: {
						...s,
						entries: nextEntries,
						total: nextEntries.length,
						page: clampPage(currentPage, nextEntries.length),
						view: s.view === "detail" ? "detail" : "list",
						selectedEntryId: nextEntry?.id,
					},
					callbackText: "Approved",
					rerender: true,
				};
			}

			case "dismiss": {
				if (!target) {
					return { callbackText: "No draft to dismiss", callbackAlert: true };
				}
				const result = dismissSocialDraft({ id: target.id, actor, serviceId: target.serviceId });
				if (!result.ok) {
					return { callbackText: result.reason, callbackAlert: true };
				}
				const nextEntries = s.entries.filter((entry) => entry.id !== target.id);
				return {
					state: {
						...s,
						entries: nextEntries,
						total: nextEntries.length,
						page: clampPage(currentPage, nextEntries.length),
						view: "list",
						selectedEntryId: undefined,
					},
					callbackText: "Dismissed",
					rerender: true,
				};
			}

			case "mark-posted": {
				if (!target) {
					return { callbackText: "No draft to mark posted", callbackAlert: true };
				}
				const result = markSocialDraftManuallyPosted({
					id: target.id,
					actor,
					serviceId: target.serviceId,
				});
				if (!result.ok) {
					return { callbackText: result.reason, callbackAlert: true };
				}
				const nextEntries = s.entries.filter((entry) => entry.id !== target.id);
				return {
					state: {
						...s,
						entries: nextEntries,
						total: nextEntries.length,
						page: clampPage(currentPage, nextEntries.length),
						view: "list",
						selectedEntryId: undefined,
					},
					callbackText: "Marked posted",
					rerender: true,
				};
			}

			case "edit": {
				if (!target) {
					return { callbackText: "No draft to edit", callbackAlert: true };
				}
				return {
					state: { ...s, selectedEntryId: target.id },
					callbackText: "Reply with edited text",
					rerender: false,
					afterCommit: () => runEditDraftFlow(context, target),
				};
			}

			case "refine": {
				if (!target) {
					return { callbackText: "No draft to refine", callbackAlert: true };
				}
				return {
					state: { ...s, selectedEntryId: target.id },
					callbackText: "Reply with refinement instruction",
					rerender: false,
					afterCommit: () => runRefineDraftFlow(context, target),
				};
			}

			case "retry-api":
				if (!target) {
					return { callbackText: "No draft to retry", callbackAlert: true };
				}
				{
					const current = getSocialDraft(target.id);
					if (!current) {
						return { callbackText: "Draft not found", callbackAlert: true };
					}
					if (!(current.trust === "trusted" && current.promotedAt)) {
						const promoteResult = promoteEntryTrust(target.id, actor);
						if (!promoteResult.ok) {
							return { callbackText: promoteResult.reason, callbackAlert: true };
						}
					}
					const approved = markSocialDraftApproved({
						id: target.id,
						actor,
						serviceId: target.serviceId,
					});
					if (!approved.ok) {
						return { callbackText: approved.reason, callbackAlert: true };
					}
					const nextEntry = entryFromDraftId(target.id);
					const nextEntries = replaceEntry(s.entries, nextEntry, target.id);
					return {
						state: {
							...s,
							entries: nextEntries,
							total: nextEntries.length,
							page: clampPage(currentPage, nextEntries.length),
							view: s.view === "detail" ? "detail" : "list",
							selectedEntryId: nextEntry?.id,
						},
						callbackText: "Queued for API retry",
						rerender: true,
					};
				}

			case "next":
				return {
					state: {
						...s,
						view: "list",
						page: Math.min(currentPage + 1, totalPages(s.total ?? s.entries.length) - 1),
						selectedEntryId: undefined,
					},
					callbackText: `Page ${Math.min(currentPage + 2, totalPages(s.total ?? s.entries.length))}`,
					rerender: true,
				};

			case "prev":
				return {
					state: {
						...s,
						view: "list",
						page: Math.max(currentPage - 1, 0),
						selectedEntryId: undefined,
					},
					callbackText: `Page ${Math.max(currentPage, 1)}`,
					rerender: true,
				};

			case "refresh": {
				const refreshedEntries = refreshEntries(card.chatId);
				const selectedId =
					s.selectedEntryId && refreshedEntries.some((entry) => entry.id === s.selectedEntryId)
						? s.selectedEntryId
						: undefined;
				return {
					state: {
						...s,
						entries: refreshedEntries,
						total: refreshedEntries.length,
						page: 0,
						view: selectedId && s.view === "detail" ? "detail" : "list",
						selectedEntryId: selectedId,
					},
					callbackText: "Refreshed",
					rerender: true,
				};
			}
		}
	},
};
