import { getChildLogger } from "../logging.js";

const logger = getChildLogger({ module: "social-scheduler" });

export type SocialScheduler = {
	stop: () => void;
};

export function startSocialScheduler(options: {
	serviceId: string;
	intervalMs: number;
	onHeartbeat: () => Promise<void>;
}): SocialScheduler {
	const intervalMs = Math.max(options.intervalMs, 60_000);
	let running = false;

	const runHeartbeat = async () => {
		if (running) {
			logger.warn({ serviceId: options.serviceId }, "social heartbeat already running; skipping");
			return;
		}
		running = true;
		try {
			await options.onHeartbeat();
		} catch (err) {
			logger.error({ error: String(err), serviceId: options.serviceId }, "social heartbeat failed");
		} finally {
			running = false;
		}
	};

	const timer = setInterval(() => void runHeartbeat(), intervalMs);
	timer.unref();

	void runHeartbeat();

	return {
		stop: () => {
			clearInterval(timer);
		},
	};
}
