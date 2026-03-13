import type { Api } from "grammy";
import { collectCronOverview } from "../commands/cron.js";
import { listCronJobs } from "../cron/store.js";
import { getChildLogger } from "../logging.js";
import { getEntries } from "../memory/store.js";
import {
	getMostRecentPendingPlanApproval,
	getPendingApprovalsForChat,
} from "../security/approvals.js";
import { getIdentityLink, listIdentityLinks } from "../security/linking.js";
import { hasTOTP } from "../security/totp.js";
import { getTOTPSessionForChat } from "../security/totp-session.js";
import { normalizeTelegramId, stringToChatId } from "../utils.js";
import {
	sendApprovalCard,
	sendAuthCard,
	sendHeartbeatCard,
	sendStatusCard,
} from "./cards/create-helpers.js";
import { collectProviderHealthIssues } from "./status-overview.js";

const logger = getChildLogger({ module: "telegram-nudges" });

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;
const DEDUP_TTL_MS = 10 * 60 * 1000;
const APPROVAL_WAIT_MS = 2 * 60 * 1000;
const HEARTBEAT_FAILURE_WINDOW_MS = 30 * 60 * 1000;

export type NudgeKind =
	| "auth_expired"
	| "approval_waiting"
	| "heartbeat_failure"
	| "provider_degraded"
	| "digest";

export interface NudgeEngine {
	tick(): Promise<void>;
	startDigest(): void;
	stopDigest(): void;
}

export interface NudgeCoordinator {
	tick(): Promise<void>;
	start(): void;
	stop(): void;
}

const DEFAULT_ENABLED_KINDS: readonly NudgeKind[] = [
	"auth_expired",
	"approval_waiting",
	"heartbeat_failure",
	"provider_degraded",
	"digest",
];

function trimSummary(text: string, limit = 180): string {
	return text.length > limit ? `${text.slice(0, limit - 3)}...` : text;
}

function resolveActorScope(chatId: number): `chat:${number}` {
	return `chat:${chatId}`;
}

function isWithinQuietHours(
	hour: number,
	quietHoursStart?: number,
	quietHoursEnd?: number,
): boolean {
	if (
		quietHoursStart === undefined ||
		quietHoursEnd === undefined ||
		quietHoursStart === quietHoursEnd
	) {
		return false;
	}

	if (quietHoursStart < quietHoursEnd) {
		return hour >= quietHoursStart && hour < quietHoursEnd;
	}

	return hour >= quietHoursStart || hour < quietHoursEnd;
}

export function createNudgeEngine(opts: {
	api: Api;
	chatId: number;
	quietHoursStart?: number;
	quietHoursEnd?: number;
	maxPerHour?: number;
	digestIntervalMs?: number;
	enabledKinds?: readonly NudgeKind[];
}): NudgeEngine {
	const actorScope = resolveActorScope(opts.chatId);
	const sentAt: number[] = [];
	const dedupe = new Map<string, number>();
	const maxPerHour = opts.maxPerHour ?? 5;
	const digestIntervalMs = opts.digestIntervalMs ?? DAY_MS;
	const enabledKinds = new Set(opts.enabledKinds ?? DEFAULT_ENABLED_KINDS);
	let digestTimer: NodeJS.Timeout | null = null;

	function cleanup(now = Date.now()): void {
		for (const [key, expiresAt] of dedupe.entries()) {
			if (expiresAt <= now) {
				dedupe.delete(key);
			}
		}

		while (sentAt.length > 0 && sentAt[0] <= now - HOUR_MS) {
			sentAt.shift();
		}
	}

	function canSend(kind: NudgeKind, now = Date.now()): boolean {
		cleanup(now);

		if (
			kind !== "auth_expired" &&
			isWithinQuietHours(new Date(now).getHours(), opts.quietHoursStart, opts.quietHoursEnd)
		) {
			return false;
		}

		return sentAt.length < maxPerHour;
	}

	function dedupeKey(kind: NudgeKind, entity: string): string {
		return `${kind}:${entity}`;
	}

	async function maybeSend(
		kind: NudgeKind,
		entity: string,
		send: () => Promise<void>,
	): Promise<boolean> {
		const now = Date.now();
		const key = dedupeKey(kind, entity);

		cleanup(now);
		if ((dedupe.get(key) ?? 0) > now) {
			return false;
		}
		if (!canSend(kind, now)) {
			return false;
		}

		await send();
		dedupe.set(key, now + DEDUP_TTL_MS);
		sentAt.push(now);
		return true;
	}

	async function nudgeAuthExpired(): Promise<void> {
		const link = getIdentityLink(opts.chatId);
		if (!link || getTOTPSessionForChat(opts.chatId)) {
			return;
		}

		const totpStatus = await hasTOTP(opts.chatId);
		if ("error" in totpStatus || !totpStatus.hasTOTP) {
			return;
		}

		await maybeSend("auth_expired", link.localUserId, async () => {
			await sendAuthCard(opts.api, opts.chatId, {
				step: "verify",
				summary: "Your 2FA session expired. Verify again with /auth verify <6-digit-code>.",
				localUserId: link.localUserId,
				actorScope,
			});
		});
	}

	async function nudgeApprovalWaiting(): Promise<void> {
		const now = Date.now();
		const planApproval = getMostRecentPendingPlanApproval(opts.chatId);
		const regularApprovals = getPendingApprovalsForChat(opts.chatId);
		const candidates = [
			...regularApprovals.map((approval) => ({
				nonce: approval.nonce,
				body: approval.body,
				title: "Approval waiting",
				createdAt: approval.createdAt,
			})),
			...(planApproval
				? [
						{
							nonce: planApproval.nonce,
							body: planApproval.originalBody,
							title: "Plan approval waiting",
							createdAt: planApproval.createdAt,
						},
					]
				: []),
		].filter((candidate) => candidate.createdAt <= now - APPROVAL_WAIT_MS);

		if (candidates.length === 0) {
			return;
		}

		candidates.sort((a, b) => a.createdAt - b.createdAt);
		const pending = candidates[0];

		await maybeSend("approval_waiting", pending.nonce, async () => {
			await sendApprovalCard(opts.api, opts.chatId, {
				title: pending.title,
				body: trimSummary(pending.body),
				nonce: pending.nonce,
				actorScope,
			});
		});
	}

	async function nudgeHeartbeatFailure(): Promise<void> {
		const now = Date.now();
		const failingJobs = listCronJobs({ includeDisabled: false }).filter(
			(job) =>
				job.action.kind.endsWith("heartbeat") &&
				job.lastStatus === "error" &&
				typeof job.lastRunAtMs === "number" &&
				job.lastRunAtMs >= now - HEARTBEAT_FAILURE_WINDOW_MS,
		);

		if (failingJobs.length === 0) {
			return;
		}

		const entity = failingJobs
			.map((job) => job.id)
			.sort()
			.join(",");
		await maybeSend("heartbeat_failure", entity, async () => {
			await sendHeartbeatCard(opts.api, opts.chatId, {
				services: failingJobs.map((job) => ({
					id: job.id,
					label:
						job.action.kind === "private-heartbeat"
							? "Private heartbeat"
							: (job.action.serviceId ?? "Social heartbeat"),
					summary: trimSummary(job.lastError ?? "error"),
				})),
				lastRunAt: Math.max(...failingJobs.map((job) => job.lastRunAtMs ?? 0)),
				actorScope,
			});
		});
	}

	async function nudgeProviderDegraded(): Promise<void> {
		const issues = await collectProviderHealthIssues();
		if (issues.length === 0) {
			return;
		}

		const entity = issues
			.map((issue) => issue.providerId)
			.sort()
			.join(",");
		await maybeSend("provider_degraded", entity, async () => {
			await sendStatusCard(opts.api, opts.chatId, {
				title: "Provider Health",
				summary: `Provider health degraded: ${issues.length} issue${issues.length === 1 ? "" : "s"}.`,
				details: issues.map(
					(issue) =>
						`${issue.providerId}: ${issue.response?.status ?? issue.error ?? "unreachable"}`,
				),
				actorScope,
				entityRef: `status:provider:${entity}`,
			});
		});
	}

	async function sendDigest(): Promise<void> {
		const now = Date.now();
		const since = now - digestIntervalMs;
		const heartbeatJobs = listCronJobs({ includeDisabled: true }).filter(
			(job) =>
				job.action.kind.endsWith("heartbeat") &&
				typeof job.lastRunAtMs === "number" &&
				job.lastRunAtMs >= since,
		);
		const promotedPosts = getEntries({
			categories: ["posts"],
			promoted: true,
			order: "desc",
			limit: 200,
		}).filter(
			(entry) =>
				typeof entry._provenance.promotedAt === "number" && entry._provenance.promotedAt >= since,
		).length;
		const cronOverview = collectCronOverview({ includeDisabled: true, limit: 5 });
		const pendingApprovals =
			getPendingApprovalsForChat(opts.chatId).length +
			(getMostRecentPendingPlanApproval(opts.chatId) ? 1 : 0);
		const bucket = Math.floor(now / digestIntervalMs);

		await maybeSend("digest", String(bucket), async () => {
			await sendStatusCard(opts.api, opts.chatId, {
				title: "Daily Digest",
				summary: "Periodic summary ready.",
				details: [
					`Posts promoted: ${promotedPosts}`,
					`Heartbeat jobs run: ${heartbeatJobs.length}`,
					`Cron health: ${cronOverview.summary.runningJobs} running, next ${
						cronOverview.summary.nextRunAtMs
							? new Date(cronOverview.summary.nextRunAtMs).toISOString()
							: "not scheduled"
					}`,
					`Pending approvals: ${pendingApprovals}`,
				],
				actorScope,
				entityRef: `status:digest:${bucket}`,
			});
		});
	}

	return {
		async tick(): Promise<void> {
			try {
				if (enabledKinds.has("auth_expired")) {
					await nudgeAuthExpired();
				}
				if (enabledKinds.has("approval_waiting")) {
					await nudgeApprovalWaiting();
				}
				if (enabledKinds.has("heartbeat_failure")) {
					await nudgeHeartbeatFailure();
				}
				if (enabledKinds.has("provider_degraded")) {
					await nudgeProviderDegraded();
				}
			} catch (error) {
				logger.warn({ chatId: opts.chatId, error: String(error) }, "nudge tick failed");
			}
		},

		startDigest(): void {
			if (!enabledKinds.has("digest")) {
				return;
			}
			if (digestTimer) {
				clearInterval(digestTimer);
			}

			digestTimer = setInterval(() => {
				void sendDigest().catch((error) => {
					logger.warn({ chatId: opts.chatId, error: String(error) }, "scheduled digest failed");
				});
			}, digestIntervalMs);
			digestTimer.unref();
		},

		stopDigest(): void {
			if (digestTimer) {
				clearInterval(digestTimer);
				digestTimer = null;
			}
		},
	};
}

function normalizePrivateChatIds(values?: Array<number | string>): number[] {
	const chatIds = new Set<number>();

	for (const value of values ?? []) {
		const normalized = normalizeTelegramId(value);
		if (!normalized) {
			continue;
		}

		const chatId = stringToChatId(normalized);
		if (!Number.isNaN(chatId) && chatId > 0) {
			chatIds.add(chatId);
		}
	}

	return Array.from(chatIds);
}

function buildKindsKey(kinds: Iterable<NudgeKind>): string {
	return Array.from(new Set(kinds)).sort().join(",");
}

function resolveNudgeTargets(allowedChats?: Array<number | string>): Map<number, Set<NudgeKind>> {
	const targets = new Map<number, Set<NudgeKind>>();

	for (const link of listIdentityLinks()) {
		if (link.chatId <= 0) {
			continue;
		}

		const kinds = targets.get(link.chatId) ?? new Set<NudgeKind>();
		kinds.add("auth_expired");
		targets.set(link.chatId, kinds);
	}

	const adminChatIds = listIdentityLinks()
		.filter((link) => link.localUserId === "admin" && link.chatId > 0)
		.map((link) => link.chatId);
	const operatorChatIds =
		adminChatIds.length > 0 ? adminChatIds : normalizePrivateChatIds(allowedChats);

	for (const chatId of operatorChatIds) {
		const kinds = targets.get(chatId) ?? new Set<NudgeKind>();
		kinds.add("approval_waiting");
		kinds.add("heartbeat_failure");
		kinds.add("provider_degraded");
		kinds.add("digest");
		targets.set(chatId, kinds);
	}

	return targets;
}

export function createNudgeCoordinator(opts: {
	api: Api;
	allowedChats?: Array<number | string>;
	intervalMs?: number;
	quietHoursStart?: number;
	quietHoursEnd?: number;
	maxPerHour?: number;
	digestIntervalMs?: number;
}): NudgeCoordinator {
	const intervalMs = opts.intervalMs ?? 5 * 60 * 1000;
	const engines = new Map<number, { kindsKey: string; engine: NudgeEngine }>();
	let tickTimer: NodeJS.Timeout | null = null;

	function syncTargets(): void {
		const targets = resolveNudgeTargets(opts.allowedChats);

		for (const [chatId, targetKinds] of targets.entries()) {
			const kindsKey = buildKindsKey(targetKinds);
			const current = engines.get(chatId);

			if (current?.kindsKey === kindsKey) {
				continue;
			}

			current?.engine.stopDigest();

			const engine = createNudgeEngine({
				api: opts.api,
				chatId,
				quietHoursStart: opts.quietHoursStart,
				quietHoursEnd: opts.quietHoursEnd,
				maxPerHour: opts.maxPerHour,
				digestIntervalMs: opts.digestIntervalMs,
				enabledKinds: Array.from(targetKinds),
			});

			if (targetKinds.has("digest")) {
				engine.startDigest();
			}

			engines.set(chatId, { kindsKey, engine });
		}

		for (const [chatId, current] of engines.entries()) {
			if (targets.has(chatId)) {
				continue;
			}

			current.engine.stopDigest();
			engines.delete(chatId);
		}
	}

	async function tick(): Promise<void> {
		syncTargets();
		await Promise.all(Array.from(engines.values(), ({ engine }) => engine.tick()));
	}

	return {
		async tick(): Promise<void> {
			await tick();
		},

		start(): void {
			syncTargets();
			void tick().catch((error) => {
				logger.warn({ error: String(error) }, "initial nudge tick failed");
			});

			if (tickTimer) {
				clearInterval(tickTimer);
			}

			tickTimer = setInterval(() => {
				void tick().catch((error) => {
					logger.warn({ error: String(error) }, "scheduled nudge tick failed");
				});
			}, intervalMs);
			tickTimer.unref();
		},

		stop(): void {
			if (tickTimer) {
				clearInterval(tickTimer);
				tickTimer = null;
			}

			for (const current of engines.values()) {
				current.engine.stopDigest();
			}
			engines.clear();
		},
	};
}
