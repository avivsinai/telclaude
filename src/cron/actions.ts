import type { TelclaudeConfig } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import { createSocialClient, handleSocialHeartbeat } from "../social/index.js";
import { handlePrivateHeartbeat } from "../telegram/heartbeat.js";
import type { CronActionResult, CronJob } from "./types.js";

const logger = getChildLogger({ module: "cron-actions" });

export async function executeCronAction(
	job: CronJob,
	cfg: TelclaudeConfig,
	_signal?: AbortSignal,
): Promise<CronActionResult> {
	switch (job.action.kind) {
		case "private-heartbeat": {
			if (!cfg.telegram?.heartbeat?.enabled) {
				return {
					ok: false,
					message: "private heartbeat is disabled in config (telegram.heartbeat.enabled=false)",
				};
			}
			try {
				const result = await handlePrivateHeartbeat(cfg);
				if (result.acted) {
					return {
						ok: true,
						message: `private heartbeat acted: ${result.summary}`,
					};
				}
				return {
					ok: true,
					message: "private heartbeat completed (no action needed)",
				};
			} catch (err) {
				logger.warn({ error: String(err), jobId: job.id }, "private heartbeat cron action failed");
				return {
					ok: false,
					message: `private heartbeat failed: ${String(err)}`,
				};
			}
		}
		case "social-heartbeat": {
			const action = job.action;
			const enabledServices = cfg.socialServices.filter((service) => service.enabled);
			if (enabledServices.length === 0) {
				return {
					ok: false,
					message: "no enabled social services",
				};
			}
			const targets = action.serviceId
				? enabledServices.filter((service) => service.id === action.serviceId)
				: enabledServices;
			if (targets.length === 0) {
				return {
					ok: false,
					message: `service '${action.serviceId}' is not enabled`,
				};
			}

			const results = await Promise.allSettled(
				targets.map(async (service) => {
					const client = await createSocialClient(service);
					if (!client) {
						return {
							serviceId: service.id,
							ok: false,
							message: "client not configured",
						};
					}
					const result = await handleSocialHeartbeat(service.id, client, service);
					return {
						serviceId: service.id,
						ok: result.ok,
						message: result.message ?? (result.ok ? "ok" : "failed"),
					};
				}),
			);

			const lines: string[] = [];
			let allOk = true;
			for (const result of results) {
				if (result.status === "rejected") {
					allOk = false;
					lines.push(`unknown: rejected - ${String(result.reason)}`);
					continue;
				}
				const line = `${result.value.serviceId}: ${result.value.message}`;
				lines.push(line);
				if (!result.value.ok) {
					allOk = false;
				}
			}
			return {
				ok: allOk,
				message: lines.join("; "),
			};
		}
		default: {
			const exhaustiveCheck: never = job.action;
			return {
				ok: false,
				message: `unsupported cron action: ${String(exhaustiveCheck)}`,
			};
		}
	}
}
