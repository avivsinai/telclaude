import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const repoRoot = path.resolve(import.meta.dirname, "../..");

function readDockerFile(relativePath: string): string {
	return fs.readFileSync(path.join(repoRoot, relativePath), "utf8");
}

function serviceBlock(compose: string, serviceName: string): string | null {
	const anchor = `\n  ${serviceName}:\n`;
	const start = compose.indexOf(anchor);
	if (start < 0) return null;
	const rest = compose.slice(start + anchor.length);
	const nextService = rest.search(/\n {2}[a-zA-Z0-9_-]+:\n/);
	return nextService < 0 ? rest : rest.slice(0, nextService);
}

describe("Tailscale broker Serve overlay", () => {
	it("keeps the base relay unpublished and binds localhost:8790 only in the overlay", () => {
		const base = serviceBlock(readDockerFile("docker/docker-compose.yml"), "telclaude");
		const deploy = serviceBlock(readDockerFile("docker/docker-compose.deploy.yml"), "telclaude");
		const overlay = readDockerFile("docker/docker-compose.tailscale-broker.yml");
		const overlayRelay = serviceBlock(overlay, "telclaude");

		expect(base).not.toContain("ports:");
		expect(deploy).not.toContain("ports:");
		expect(overlayRelay).toContain("127.0.0.1:8790:8790");
		expect(overlayRelay).toContain("TELCLAUDE_TAILSCALED_SOCKET=/run/tailscale/tailscaled.sock");
		expect(overlayRelay).toContain(
			"${TELCLAUDE_TAILSCALED_SOCKET_HOST:-/var/run/tailscale/tailscaled.sock}:/run/tailscale/tailscaled.sock:ro",
		);
		expect(overlay).toContain("set-path=/v1/broker");
		expect(overlay).not.toContain("docker.sock");
	});

	it("wires the overlay into William Deploy and leaves GitHub-hosted Verify off the socket", () => {
		const workflow = readDockerFile(".github/workflows/ci.yml");
		const deployStart = workflow.indexOf("  deploy:");
		expect(deployStart).toBeGreaterThan(-1);
		const deployJob = workflow.slice(deployStart);
		const verifyStart = workflow.indexOf("  verify:");
		const verifyJob = verifyStart < 0 ? "" : workflow.slice(verifyStart, deployStart);

		expect(deployJob).toContain("-f docker-compose.tailscale-broker.yml");
		expect(deployJob).toContain("-f docker-compose.browser.yml -f docker-compose.tailscale-broker.yml");
		expect(verifyJob).not.toContain("docker-compose.tailscale-broker.yml");
	});

	it("allows the relay AppArmor profile to connect to tailscaled.sock", () => {
		const profile = readDockerFile("docker/apparmor/telclaude-relay");
		expect(profile).toContain("/run/tailscale/** rw,");
	});
});
