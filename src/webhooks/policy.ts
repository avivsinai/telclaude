import type { CronJob } from "../cron/types.js";

export function getWebhookCronTargetRejection(job: CronJob): string | null {
	if (!job.enabled) {
		return "target_cron_job_disabled";
	}
	if (job.action.kind === "social-heartbeat" || job.ownerId?.startsWith("social:") === true) {
		return "target_cron_job_social_not_allowed";
	}
	return null;
}

export function assertWebhookCronTargetAllowed(job: CronJob): void {
	const reason = getWebhookCronTargetRejection(job);
	if (reason === "target_cron_job_disabled") {
		throw new Error(`cron job '${job.id}' is disabled`);
	}
	if (reason) {
		throw new Error(`cron job '${job.id}' is not an allowed webhook target: ${reason}`);
	}
}
