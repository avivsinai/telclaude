import { describe, expect, it } from "vitest";
import {
	HOSTILE_PEER_REQUIRED_CHECKS,
	hostilePeerProbeEvidenceFailure,
	runHermesHostilePeerProbe,
	type HostilePeerProbeRunner,
} from "../../src/hermes/hostile-peer-probes.js";

function passingRunner(): HostilePeerProbeRunner {
	return {
		"hostile-peer.live-mcp-auth": async () => ({
			status: "pass",
			detail: "forged, wrong-connection, off-domain, unauthenticated, and no-authority calls denied",
		}),
		"hostile-peer.model-proxy-token-isolation": async () => ({
			status: "pass",
			detail: "root token absent, peer-bound auth.json token rejected on wrong peer/bad path",
		}),
		"hostile-peer.relay-internal-surface-inventory": async () => ({
			status: "pass",
			detail: "only live MCP and Codex proxy reachable; no admin/vault/provider surfaces exposed",
		}),
		"hostile-peer.token-abuse-canary": async () => ({
			status: "pass",
			detail: "env/profile tokens cannot broaden scope or survive authority-window closure",
		}),
		"hostile-peer.runtime-self-modification-canary": async () => ({
			status: "pass",
			detail: "modified HERMES_HOME config/auth/memory cannot broaden relay authority",
		}),
	};
}

describe("Hermes hostile-peer probe evidence", () => {
	it("passes only after all five hostile in-container boundary probes pass", async () => {
		const evidence = await runHermesHostilePeerProbe({
			allowRun: true,
			runner: passingRunner(),
			observedAt: "2026-06-17T13:30:00.000Z",
		});

		expect(evidence.status).toBe("pass");
		expect(evidence.ran).toBe(true);
		expect(evidence.checks.map((check) => check.name)).toEqual([...HOSTILE_PEER_REQUIRED_CHECKS]);
		expect(hostilePeerProbeEvidenceFailure("runtime.hostile-peer", evidence)).toBeNull();
	});

	it("rejects pass-looking evidence missing a required hostile-peer control", async () => {
		const evidence = await runHermesHostilePeerProbe({
			allowRun: true,
			runner: passingRunner(),
			observedAt: "2026-06-17T13:30:00.000Z",
		});

		expect(
			hostilePeerProbeEvidenceFailure("runtime.hostile-peer", {
				...evidence,
				checks: evidence.checks.filter(
					(check) => check.name !== "hostile-peer.token-abuse-canary",
				),
			}),
		).toContain("check hostile-peer.token-abuse-canary is missing");
	});

	it("fails closed when a broad-boundary probe fails", async () => {
		const runner = passingRunner();
		runner["hostile-peer.model-proxy-token-isolation"] = async () => ({
			status: "fail",
			detail: "auth.json token accepted from wrong peer",
		});

		const evidence = await runHermesHostilePeerProbe({
			allowRun: true,
			runner,
			observedAt: "2026-06-17T13:30:00.000Z",
		});

		expect(evidence.status).toBe("fail");
		expect(hostilePeerProbeEvidenceFailure("runtime.hostile-peer", evidence)).toContain(
			"check hostile-peer.model-proxy-token-isolation is fail",
		);
	});

	it("does not certify runtime hostility without --allow-run and a runner", async () => {
		const evidence = await runHermesHostilePeerProbe({
			allowRun: false,
			observedAt: "2026-06-17T13:30:00.000Z",
		});

		expect(evidence.status).toBe("fail");
		expect(evidence.ran).toBe(false);
		expect(hostilePeerProbeEvidenceFailure("runtime.hostile-peer", evidence)).toContain(
			"harness did not run",
		);
	});
});
