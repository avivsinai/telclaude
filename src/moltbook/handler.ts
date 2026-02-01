import { getChildLogger } from "../logging.js";
import { getEntries } from "../memory/store.js";
import type { MemoryEntry, MemorySource, TrustLevel } from "../memory/types.js";
import { buildMoltbookIdentityPreamble } from "./identity.js";
import { formatSocialContextForPrompt } from "./social-context.js";

const logger = getChildLogger({ module: "moltbook-handler" });

export type MoltbookHeartbeatPayload = {
	timestamp?: number;
	eventId?: string;
};

export type MoltbookNotificationPayload = {
	timestamp?: number;
	notificationId?: string;
	type?: string;
};

export type MoltbookHandlerResult = {
	ok: boolean;
	message?: string;
};

export type MoltbookPromptBundle = {
	prompt: string;
	systemPromptAppend: string;
};

const SOCIAL_CONTEXT_SOURCES: MemorySource[] = ["telegram", "moltbook"];
const SOCIAL_CONTEXT_TRUST: TrustLevel[] = ["trusted"];
const SOCIAL_CONTEXT_LIMIT = 200;

const IDENTITY_CATEGORIES: Array<MemoryEntry["category"]> = ["profile", "interests", "meta"];

function getTrustedSocialEntries(categories?: Array<MemoryEntry["category"]>): MemoryEntry[] {
	return getEntries({
		categories,
		sources: SOCIAL_CONTEXT_SOURCES,
		trust: SOCIAL_CONTEXT_TRUST,
		limit: SOCIAL_CONTEXT_LIMIT,
		order: "desc",
	});
}

export function buildMoltbookPromptBundle(message: string): MoltbookPromptBundle {
	const socialEntries = getTrustedSocialEntries();
	const identityEntries = getTrustedSocialEntries(IDENTITY_CATEGORIES);

	const systemPromptAppend = buildMoltbookIdentityPreamble(identityEntries);
	const socialContext = formatSocialContextForPrompt({ entries: socialEntries });
	const prompt = `${socialContext}\n\n---\n\n${message}`;

	return { prompt, systemPromptAppend };
}

export async function handleMoltbookHeartbeat(
	payload?: MoltbookHeartbeatPayload,
): Promise<MoltbookHandlerResult> {
	logger.info({ payload }, "moltbook heartbeat received (stub)");
	return { ok: true, message: "heartbeat acknowledged" };
}

export async function handleMoltbookNotification(
	payload?: MoltbookNotificationPayload,
): Promise<MoltbookHandlerResult> {
	logger.info({ payload }, "moltbook notification received (stub)");
	return { ok: true, message: "notification acknowledged" };
}
