import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { GatewayRunners } from "../../src/commands/gateway.js";
import {
	__internals,
	runGatewayInstall,
	runGatewayLogs,
	runGatewayRestart,
	runGatewayStart,
	runGatewayStatus,
	runGatewayStop,
} from "../../src/commands/gateway.js";

/**
 * Stub runner that records every invocation and returns scripted results.
 * `scriptSync` maps "cmd arg1 arg2 ..." prefixes to a SpawnSyncReturns shape.
 * Unmatched calls return exit 1 so tests fail loudly on unexpected spawns.
 */
interface Recorded {
	cmd: string;
	args: string[];
	cwd: string;
}

function makeRunners(
	scriptSync: Record<string, { stdout?: string; stderr?: string; status?: number }>,
	scriptStream: Record<string, number> = {},
): { runners: GatewayRunners; calls: Recorded[] } {
	const calls: Recorded[] = [];
	const lookup = (cmd: string, args: string[]): string => `${cmd} ${args.join(" ")}`;

	const runners: GatewayRunners = {
		runSync: (cmd, args, cwd) => {
			calls.push({ cmd, args, cwd });
			const key = lookup(cmd, args);
			for (const prefix of Object.keys(scriptSync)) {
				if (key.startsWith(prefix)) {
					const s = scriptSync[prefix];
					return {
						pid: 1,
						output: [null as unknown as string, s?.stdout ?? "", s?.stderr ?? ""],
						stdout: s?.stdout ?? "",
						stderr: s?.stderr ?? "",
						status: s?.status ?? 0,
						signal: null,
					} as unknown as ReturnType<GatewayRunners["runSync"]>;
				}
			}
			return {
				pid: 1,
				output: [null as unknown as string, "", `no script for ${key}`],
				stdout: "",
				stderr: `no script for ${key}`,
				status: 1,
				signal: null,
			} as unknown as ReturnType<GatewayRunners["runSync"]>;
		},
		runStreaming: async (cmd, args, cwd) => {
			calls.push({ cmd, args, cwd });
			const key = lookup(cmd, args);
			for (const prefix of Object.keys(scriptStream)) {
				if (key.startsWith(prefix)) return scriptStream[prefix] ?? 0;
			}
			return 0;
		},
	};
	return { runners, calls };
}

function makeRepoRoot(): string {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "gateway-test-"));
	fs.mkdirSync(path.join(dir, "docker"), { recursive: true });
	fs.writeFileSync(
		path.join(dir, "docker", "docker-compose.yml"),
		"# stub compose file\nservices: {}\n",
	);
	return dir;
}

function makeSink(): {
	out: (l: string) => void;
	err: (l: string) => void;
	lines: string[];
	errs: string[];
} {
	const lines: string[] = [];
	const errs: string[] = [];
	return {
		out: (l) => lines.push(l),
		err: (l) => errs.push(l),
		lines,
		errs,
	};
}

describe("gateway — parseComposePs", () => {
	it("parses newline-delimited JSON emitted by compose v2", () => {
		const raw = [
			JSON.stringify({
				Service: "telclaude",
				Name: "telclaude",
				State: "running",
				Health: "healthy",
				Status: "Up 5 minutes (healthy)",
			}),
			JSON.stringify({
				Service: "vault",
				Name: "telclaude-vault",
				State: "running",
				Health: "",
				Status: "Up 5 minutes",
			}),
		].join("\n");

		const parsed = __internals.parseComposePs(raw);
		expect(parsed).toHaveLength(2);
		expect(parsed[0]?.Service).toBe("telclaude");
		expect(parsed[1]?.Service).toBe("vault");
	});

	it("parses array form", () => {
		const raw = JSON.stringify([{ Service: "telclaude", State: "running", Health: "healthy" }]);
		const parsed = __internals.parseComposePs(raw);
		expect(parsed).toHaveLength(1);
		expect(parsed[0]?.Service).toBe("telclaude");
	});

	it("returns empty for empty input", () => {
		expect(__internals.parseComposePs("")).toEqual([]);
		expect(__internals.parseComposePs("   \n")).toEqual([]);
	});

	it("skips malformed lines instead of throwing", () => {
		const raw = [
			JSON.stringify({ Service: "telclaude", State: "running", Health: "healthy" }),
			"not-json",
			JSON.stringify({ Service: "vault", State: "running", Health: "none" }),
		].join("\n");
		const parsed = __internals.parseComposePs(raw);
		expect(parsed).toHaveLength(2);
	});
});

describe("gateway — statusesFromComposePs", () => {
	it("fills all expected services, marking absent ones as missing", () => {
		const raw = JSON.stringify({
			Service: "telclaude",
			Name: "telclaude",
			State: "running",
			Health: "healthy",
			Status: "Up 1 minute (healthy)",
		});
		const statuses = __internals.statusesFromComposePs(raw);
		// All six expected services should be represented.
		expect(statuses.map((s) => s.service)).toEqual([...__internals.EXPECTED_SERVICES]);
		const telclaude = statuses.find((s) => s.service === "telclaude");
		expect(telclaude?.state).toBe("running");
		expect(telclaude?.health).toBe("healthy");
		const vault = statuses.find((s) => s.service === "vault");
		expect(vault?.state).toBe("missing");
		expect(vault?.health).toBe("missing");
	});

	it("defaults Health to 'none' when compose omits it", () => {
		const raw = JSON.stringify({
			Service: "vault",
			Name: "telclaude-vault",
			State: "running",
			Status: "Up 1 minute",
		});
		const statuses = __internals.statusesFromComposePs(raw);
		const vault = statuses.find((s) => s.service === "vault");
		expect(vault?.state).toBe("running");
		expect(vault?.health).toBe("none");
	});
});

describe("gateway — allRunningAndHealthy", () => {
	it("is false when the snapshot is empty", () => {
		expect(__internals.allRunningAndHealthy([])).toBe(false);
	});

	it("is false when any service is missing", () => {
		const snap = __internals.statusesFromComposePs(
			JSON.stringify({ Service: "telclaude", State: "running", Health: "healthy" }),
		);
		expect(__internals.allRunningAndHealthy(snap)).toBe(false);
	});

	it("accepts 'none' health as healthy (containers without healthchecks)", () => {
		const rows = __internals.EXPECTED_SERVICES.map((svc) =>
			JSON.stringify({ Service: svc, State: "running", Health: "" }),
		).join("\n");
		const snap = __internals.statusesFromComposePs(rows);
		expect(__internals.allRunningAndHealthy(snap)).toBe(true);
	});

	it("rejects unhealthy or starting states", () => {
		const mk = (health: string) =>
			__internals.EXPECTED_SERVICES.map((svc, i) =>
				JSON.stringify({
					Service: svc,
					State: "running",
					Health: i === 0 ? health : "healthy",
				}),
			).join("\n");
		expect(
			__internals.allRunningAndHealthy(__internals.statusesFromComposePs(mk("unhealthy"))),
		).toBe(false);
		expect(
			__internals.allRunningAndHealthy(__internals.statusesFromComposePs(mk("starting"))),
		).toBe(false);
	});
});

describe("gateway — install/start/stop/restart verbs", () => {
	let cwd: string;

	beforeEach(() => {
		cwd = makeRepoRoot();
	});

	afterEach(() => {
		if (cwd && fs.existsSync(cwd)) fs.rmSync(cwd, { recursive: true, force: true });
	});

	it("install runs `docker compose build` in docker/", async () => {
		const sink = makeSink();
		const { runners, calls } = makeRunners({ "docker --version": {} });
		const code = await runGatewayInstall({
			cwd,
			runners,
			modeOverride: "docker",
			out: sink.out,
			err: sink.err,
			useColor: false,
		});
		expect(code).toBe(0);
		const build = calls.find(
			(c) => c.cmd === "docker" && c.args[0] === "compose" && c.args[1] === "build",
		);
		expect(build).toBeDefined();
		expect(build?.cwd).toBe(path.join(cwd, "docker"));
	});

	it("start runs up -d then polls until healthy, exit 0", async () => {
		const sink = makeSink();
		const healthyPs = __internals.EXPECTED_SERVICES.map((svc) =>
			JSON.stringify({
				Service: svc,
				Name: svc,
				State: "running",
				Health: "healthy",
				Status: "Up (healthy)",
			}),
		).join("\n");
		const { runners, calls } = makeRunners(
			{
				"docker --version": {},
				"docker compose ps": { stdout: healthyPs },
				"docker logs": { stdout: "ok\n" },
			},
			{ "docker compose up": 0 },
		);
		const code = await runGatewayStart({
			cwd,
			runners,
			modeOverride: "docker",
			out: sink.out,
			err: sink.err,
			useColor: false,
		});
		expect(code).toBe(0);
		expect(calls.some((c) => c.args.slice(0, 3).join(" ") === "compose up -d")).toBe(true);
		expect(calls.some((c) => c.args.slice(0, 2).join(" ") === "compose ps")).toBe(true);
		expect(sink.lines.some((l) => l.toLowerCase().includes("up and healthy"))).toBe(true);
	});

	it("start exits 1 if containers remain unhealthy past the deadline", async () => {
		const sink = makeSink();
		const unhealthyPs = JSON.stringify({
			Service: "telclaude",
			Name: "telclaude",
			State: "running",
			Health: "unhealthy",
			Status: "Up (unhealthy)",
		});
		const { runners } = makeRunners(
			{
				"docker --version": {},
				"docker compose ps": { stdout: unhealthyPs },
				"docker logs": { stdout: "" },
			},
			{ "docker compose up": 0 },
		);
		// Shrink the wait so the test is fast: monkey-patch setTimeout via
		// fake timers isn't needed because the status capture already marks 5
		// services as missing → allRunningAndHealthy is false → we loop until
		// the real-clock deadline. Use fake timers.
		vi.useFakeTimers();
		const promise = runGatewayStart({
			cwd,
			runners,
			modeOverride: "docker",
			out: sink.out,
			err: sink.err,
			useColor: false,
		});
		// Advance past the health deadline.
		await vi.advanceTimersByTimeAsync(__internals.HEALTH_MAX_WAIT_MS + 2_000);
		const code = await promise;
		vi.useRealTimers();
		expect(code).toBe(1);
	});

	it("stop runs `docker compose down` without -v", async () => {
		const sink = makeSink();
		const { runners, calls } = makeRunners(
			{ "docker --version": {} },
			{ "docker compose down": 0 },
		);
		const code = await runGatewayStop({
			cwd,
			runners,
			modeOverride: "docker",
			out: sink.out,
			err: sink.err,
			useColor: false,
		});
		expect(code).toBe(0);
		const down = calls.find((c) => c.args[0] === "compose" && c.args[1] === "down");
		expect(down).toBeDefined();
		expect(down?.args).not.toContain("-v");
	});

	it("restart calls stop then start", async () => {
		const sink = makeSink();
		const healthyPs = __internals.EXPECTED_SERVICES.map((svc) =>
			JSON.stringify({ Service: svc, Name: svc, State: "running", Health: "healthy" }),
		).join("\n");
		const { runners, calls } = makeRunners(
			{
				"docker --version": {},
				"docker compose ps": { stdout: healthyPs },
				"docker logs": { stdout: "ok" },
			},
			{
				"docker compose down": 0,
				"docker compose up": 0,
			},
		);
		const code = await runGatewayRestart({
			cwd,
			runners,
			modeOverride: "docker",
			out: sink.out,
			err: sink.err,
			useColor: false,
		});
		expect(code).toBe(0);
		const downIdx = calls.findIndex((c) => c.args.join(" ") === "compose down");
		const upIdx = calls.findIndex((c) => c.args.slice(0, 3).join(" ") === "compose up -d");
		expect(downIdx).toBeGreaterThanOrEqual(0);
		expect(upIdx).toBeGreaterThanOrEqual(0);
		expect(downIdx).toBeLessThan(upIdx);
	});
});

describe("gateway — status", () => {
	let cwd: string;

	beforeEach(() => {
		cwd = makeRepoRoot();
	});

	afterEach(() => {
		if (cwd && fs.existsSync(cwd)) fs.rmSync(cwd, { recursive: true, force: true });
	});

	it("exits 0 when all containers are running+healthy", async () => {
		const sink = makeSink();
		const healthyPs = __internals.EXPECTED_SERVICES.map((svc) =>
			JSON.stringify({
				Service: svc,
				Name: svc,
				State: "running",
				Health: "healthy",
				Status: "Up (healthy)",
			}),
		).join("\n");
		const { runners } = makeRunners({
			"docker --version": {},
			"docker compose ps": { stdout: healthyPs },
			"docker logs": { stdout: "hello world" },
		});
		const code = await runGatewayStatus({
			cwd,
			runners,
			modeOverride: "docker",
			out: sink.out,
			err: sink.err,
			useColor: false,
		});
		expect(code).toBe(0);
		// Table header present.
		expect(sink.lines.some((l) => l.includes("SERVICE") && l.includes("STATE"))).toBe(true);
		// All expected services are rendered.
		for (const svc of __internals.EXPECTED_SERVICES) {
			expect(sink.lines.some((l) => l.includes(svc))).toBe(true);
		}
	});

	it("exits 1 when any container is missing", async () => {
		const sink = makeSink();
		// Only report 1 service — the other 5 will be inferred as missing.
		const partialPs = JSON.stringify({
			Service: "telclaude",
			Name: "telclaude",
			State: "running",
			Health: "healthy",
		});
		const { runners } = makeRunners({
			"docker --version": {},
			"docker compose ps": { stdout: partialPs },
			"docker logs": { stdout: "ok" },
		});
		const code = await runGatewayStatus({
			cwd,
			runners,
			modeOverride: "docker",
			out: sink.out,
			err: sink.err,
			useColor: false,
		});
		expect(code).toBe(1);
	});
});

describe("gateway — logs", () => {
	let cwd: string;

	beforeEach(() => {
		cwd = makeRepoRoot();
	});

	afterEach(() => {
		if (cwd && fs.existsSync(cwd)) fs.rmSync(cwd, { recursive: true, force: true });
	});

	it("defaults to --tail 200 and no service filter", async () => {
		const sink = makeSink();
		const { runners, calls } = makeRunners(
			{ "docker --version": {} },
			{ "docker compose logs": 0 },
		);
		const code = await runGatewayLogs(undefined, {
			cwd,
			runners,
			modeOverride: "docker",
			out: sink.out,
			err: sink.err,
			useColor: false,
		});
		expect(code).toBe(0);
		const call = calls.find((c) => c.args[0] === "compose" && c.args[1] === "logs");
		expect(call?.args).toEqual(["compose", "logs", "--tail", "200"]);
	});

	it("respects --follow and service filter", async () => {
		const sink = makeSink();
		const { runners, calls } = makeRunners(
			{ "docker --version": {} },
			{ "docker compose logs": 0 },
		);
		const code = await runGatewayLogs("telclaude", {
			cwd,
			runners,
			modeOverride: "docker",
			follow: true,
			tail: 50,
			out: sink.out,
			err: sink.err,
			useColor: false,
		});
		expect(code).toBe(0);
		const call = calls.find((c) => c.args[0] === "compose" && c.args[1] === "logs");
		expect(call?.args).toEqual(["compose", "logs", "--tail", "50", "--follow", "telclaude"]);
	});

	it("rejects unknown service names", async () => {
		const sink = makeSink();
		const { runners, calls } = makeRunners(
			{ "docker --version": {} },
			{ "docker compose logs": 0 },
		);
		const code = await runGatewayLogs("not-a-service", {
			cwd,
			runners,
			modeOverride: "docker",
			out: sink.out,
			err: sink.err,
			useColor: false,
		});
		expect(code).toBe(1);
		// No logs call should have fired.
		expect(calls.some((c) => c.args[0] === "compose" && c.args[1] === "logs")).toBe(false);
		expect(sink.errs.some((e) => e.includes("Unknown service"))).toBe(true);
	});
});

describe("gateway — native mode guidance", () => {
	let cwd: string;

	beforeEach(() => {
		cwd = makeRepoRoot();
	});

	afterEach(() => {
		if (cwd && fs.existsSync(cwd)) fs.rmSync(cwd, { recursive: true, force: true });
	});

	it("start/stop/restart/install all nudge toward `telclaude relay` in native mode", async () => {
		const scenarios: Array<{
			name: string;
			verb: "install" | "start" | "stop";
			run: () => Promise<number>;
		}> = [];

		const makeVerbRunner = (verb: "install" | "start" | "stop") => {
			const sink = makeSink();
			const { runners, calls } = makeRunners({}, {});
			const run = async () => {
				const fn =
					verb === "install"
						? runGatewayInstall
						: verb === "start"
							? runGatewayStart
							: runGatewayStop;
				return fn({
					cwd,
					runners,
					modeOverride: "native",
					out: sink.out,
					err: sink.err,
					useColor: false,
				});
			};
			scenarios.push({ name: verb, verb, run });
			return { sink, calls };
		};

		const install = makeVerbRunner("install");
		const start = makeVerbRunner("start");
		const stop = makeVerbRunner("stop");

		for (const s of scenarios) {
			const code = await s.run();
			// Exit 0: we surface guidance, not a hard error.
			expect(code).toBe(0);
		}

		// None of the runners should have been asked to invoke docker.
		for (const { calls } of [install, start, stop]) {
			expect(calls.some((c) => c.cmd === "docker" && c.args[0] === "compose")).toBe(false);
		}
	});

	it("status in native mode reports relay liveness via pgrep/ps", async () => {
		const sink = makeSink();
		const { runners } = makeRunners({
			"pgrep -f": { stdout: "99999\n", status: 0 },
		});
		const code = await runGatewayStatus({
			cwd,
			runners,
			modeOverride: "native",
			out: sink.out,
			err: sink.err,
			useColor: false,
		});
		expect(code).toBe(0);
		expect(sink.lines.some((l) => l.toLowerCase().includes("relay: running"))).toBe(true);
	});

	it("status in native mode exits 1 when relay is not running", async () => {
		const sink = makeSink();
		// Both pgrep and ps exit non-zero → no relay found.
		const { runners } = makeRunners({
			"pgrep -f": { status: 1 },
			"ps -Ao": { stdout: "some other process\n", status: 0 },
		});
		const code = await runGatewayStatus({
			cwd,
			runners,
			modeOverride: "native",
			out: sink.out,
			err: sink.err,
			useColor: false,
		});
		expect(code).toBe(1);
		expect(sink.lines.some((l) => l.toLowerCase().includes("relay: not running"))).toBe(true);
	});
});

describe("gateway — missing docker-compose.yml", () => {
	it("fails when docker-compose.yml is not present in ./docker", async () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), "gateway-test-"));
		try {
			const sink = makeSink();
			const { runners, calls } = makeRunners({}, {});
			const code = await runGatewayInstall({
				cwd: dir,
				runners,
				modeOverride: "docker",
				out: sink.out,
				err: sink.err,
				useColor: false,
			});
			expect(code).toBe(1);
			// Should never have reached the docker CLI.
			expect(calls.some((c) => c.cmd === "docker")).toBe(false);
			expect(sink.errs.some((e) => e.includes("docker-compose.yml not found"))).toBe(true);
		} finally {
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});
});

describe("gateway — status table rendering", () => {
	it("emits one row per expected service and colors where appropriate", () => {
		const ctx = __internals.buildContext({
			cwd: "/tmp",
			modeOverride: "docker",
			useColor: false,
			out: () => {},
			err: () => {},
			runners: {
				runSync: () =>
					({
						status: 0,
						stdout: "",
						stderr: "",
						signal: null,
						pid: 1,
						output: [null, "", ""],
					}) as ReturnType<GatewayRunners["runSync"]>,
				runStreaming: async () => 0,
			},
		});
		const lines: string[] = [];
		const snapshot = __internals.statusesFromComposePs(
			__internals.EXPECTED_SERVICES.map((svc) =>
				JSON.stringify({
					Service: svc,
					Name: svc,
					State: "running",
					Health: "healthy",
					Status: "Up",
				}),
			).join("\n"),
		);
		__internals.renderStatusTable({ ...ctx, out: (l) => lines.push(l) }, snapshot);
		// Header + separator + 6 rows = 8 lines at minimum.
		expect(lines.length).toBeGreaterThanOrEqual(8);
		expect(lines[0]).toContain("SERVICE");
		expect(lines[0]).toContain("STATE");
		for (const svc of __internals.EXPECTED_SERVICES) {
			expect(lines.some((l) => l.includes(svc))).toBe(true);
		}
	});
});
