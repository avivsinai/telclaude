export type CronSuppression = "none" | "idle" | "silent";

/**
 * Scheduled automations use terse sentinel tokens because they often run
 * unattended. [IDLE] means nothing happened; [SILENT] means work happened but
 * no Telegram message should be sent.
 */
export function detectCronSuppression(text: string): CronSuppression {
	const normalized = text.trim().toUpperCase();
	if (normalized.includes("[SILENT]")) {
		return "silent";
	}
	if (normalized.includes("[IDLE]")) {
		return "idle";
	}
	return "none";
}
