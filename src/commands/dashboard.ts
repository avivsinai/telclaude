/**
 * `telclaude dashboard` CLI.
 *
 *   telclaude dashboard start  [--port N]   — run the local dashboard in the foreground
 *   telclaude dashboard status               — report whether a pid file is live
 *   telclaude dashboard stop                 — signal the pid recorded in the pidfile
 *
 * Design notes:
 *   - `start` runs in the foreground so the operator sees listen errors and
 *     can Ctrl-C the process (matches `telclaude totp-daemon`). Running it
 *     headlessly is out of scope — operators who want that should wrap this
 *     command with their own supervisor (systemd, launchd, tmux, etc.).
 *   - We write a pidfile to make `status`/`stop` useful for those who do wrap
 *     the command. The pidfile is advisory — if the process dies without
 *     cleanup, `status` will report "stale pidfile".
 */

import fs from "node:fs";
import path from "node:path";
import type { Command } from "commander";
import { loadConfig } from "../config/config.js";
import { buildDashboardServer } from "../dashboard/server.js";
import { getChildLogger } from "../logging.js";
import { CONFIG_DIR } from "../utils.js";
import { runDaemon } from "./cli-utils.js";

const logger = getChildLogger({ module: "cmd-dashboard" });

const PIDFILE_PATH = path.join(CONFIG_DIR, "dashboard.pid");

type StartOptions = {
	port?: string;
	verbose?: boolean;
};

function resolvePort(explicit: string | undefined): number {
	if (explicit) {
		const parsed = Number.parseInt(explicit, 10);
		if (Number.isNaN(parsed) || parsed <= 0 || parsed > 65535) {
			throw new Error(`Invalid --port: ${explicit}`);
		}
		return parsed;
	}
	const cfg = loadConfig();
	return cfg.dashboard?.port ?? 3005;
}

function writePidfile(pid: number): void {
	try {
		fs.mkdirSync(path.dirname(PIDFILE_PATH), { recursive: true, mode: 0o700 });
		fs.writeFileSync(PIDFILE_PATH, String(pid), { mode: 0o600 });
	} catch (err) {
		logger.warn({ error: String(err) }, "failed to write dashboard pidfile");
	}
}

function removePidfile(): void {
	try {
		fs.unlinkSync(PIDFILE_PATH);
	} catch {
		// ignore — best effort
	}
}

type PidStatus =
	| { state: "running"; pid: number }
	| { state: "stale"; pid: number }
	| { state: "missing" };

function readPidStatus(): PidStatus {
	if (!fs.existsSync(PIDFILE_PATH)) return { state: "missing" };
	const raw = fs.readFileSync(PIDFILE_PATH, "utf-8").trim();
	const pid = Number.parseInt(raw, 10);
	if (!Number.isFinite(pid) || pid <= 0) return { state: "missing" };
	try {
		// Signal 0 tests whether the pid is alive without delivering a signal.
		process.kill(pid, 0);
		return { state: "running", pid };
	} catch {
		return { state: "stale", pid };
	}
}

export function registerDashboardCommand(program: Command): void {
	const dashboard = program
		.command("dashboard")
		.description("Local web dashboard (loopback-only, TOTP-gated)");

	dashboard
		.command("start")
		.description("Start the dashboard server in the foreground")
		.option("--port <n>", "Override the configured dashboard port")
		.action(async (opts: StartOptions) => {
			const cfg = loadConfig();
			if (cfg.dashboard?.enabled === false && !opts.port) {
				// Still allow opt-in via explicit --port so operators can
				// try it without editing config first.
				console.warn(
					"dashboard is disabled in config (dashboard.enabled=false); starting anyway because this is a foreground command",
				);
			}
			const port = resolvePort(opts.port);
			try {
				const handle = await buildDashboardServer({ port });
				writePidfile(process.pid);
				console.log(`telclaude dashboard listening on http://${handle.host}:${handle.port}`);
				console.log("Press Ctrl+C to stop.");
				await runDaemon({
					onShutdown: async () => {
						await handle.close();
						removePidfile();
					},
				});
			} catch (err) {
				logger.error({ error: String(err) }, "dashboard start failed");
				console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
				process.exit(1);
			}
		});

	dashboard
		.command("status")
		.description("Report whether a recorded dashboard pid is alive")
		.action(() => {
			const cfg = loadConfig();
			const status = readPidStatus();
			const port = cfg.dashboard?.port ?? 3005;
			const enabled = cfg.dashboard?.enabled ?? false;
			console.log(`Config: enabled=${enabled} port=${port}`);
			switch (status.state) {
				case "running":
					console.log(`State:  running (pid ${status.pid})`);
					break;
				case "stale":
					console.log(`State:  stale pidfile (pid ${status.pid} not alive)`);
					process.exitCode = 1;
					break;
				case "missing":
					console.log("State:  not running");
					process.exitCode = 1;
					break;
			}
		});

	dashboard
		.command("stop")
		.description("Signal the pid recorded in the dashboard pidfile")
		.action(() => {
			const status = readPidStatus();
			switch (status.state) {
				case "running":
					try {
						process.kill(status.pid, "SIGTERM");
						console.log(`Sent SIGTERM to pid ${status.pid}`);
					} catch (err) {
						console.error(`Failed to signal pid ${status.pid}: ${String(err)}`);
						process.exitCode = 1;
					}
					break;
				case "stale":
					console.log(`Stale pidfile for pid ${status.pid}; cleaning up`);
					removePidfile();
					break;
				case "missing":
					console.log("No dashboard pidfile — nothing to stop");
					break;
			}
		});
}
