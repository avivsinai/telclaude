import { getChildLogger } from "../logging.js";

const logger = getChildLogger({ module: "moltbook-scheduler" });

export type MoltbookScheduler = {
	stop: () => void;
};

export function startMoltbookScheduler(options: {
	intervalMs: number;
	onHeartbeat: () => Promise<void>;
}): MoltbookScheduler {
	const intervalMs = Math.max(options.intervalMs, 60_000);
	let running = false;

	const runHeartbeat = async () => {
		if (running) {
			logger.warn("moltbook heartbeat already running; skipping");
			return;
		}
		running = true;
		try {
			await options.onHeartbeat();
		} catch (err) {
			logger.error({ error: String(err) }, "moltbook heartbeat failed");
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
