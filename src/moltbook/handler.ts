import { getChildLogger } from "../logging.js";

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
