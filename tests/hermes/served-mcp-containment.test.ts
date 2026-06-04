import fs from "node:fs";
import type http from "node:http";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
	createTelclaudeMcpAuthorityRegistry,
	type TelclaudeMcpAuthorityConnection,
} from "../../src/hermes/mcp/authority-registry.js";
import type { TelclaudeMcpAuthority } from "../../src/hermes/mcp/bridge.js";
import { createTelclaudeLiveMcpConnectionResolver } from "../../src/hermes/mcp/live-connection-resolver.js";
import { createTelclaudeLiveMcpProbeTokenBundle } from "../../src/hermes/mcp/live-probe-tokens.js";
import {
	createTelclaudeLiveMcpNodeHttpServer,
	createTelclaudeLiveMcpRelayHttpServer,
	type TelclaudeLiveMcpRelayClients,
} from "../../src/hermes/mcp/live-server.js";
import { createTelclaudeMcpSideEffectLedger } from "../../src/hermes/mcp/side-effect-ledger.js";
import {
	evaluateServedMcpContainmentEvidence,
	runServedMcpContainmentProbe,
	SERVED_MCP_REQUIRED_PROPERTY_NAMES,
	writeServedMcpContainmentEvidence,
} from "../../src/hermes/served-mcp-containment.js";

describe("Hermes served-MCP containment probe", () => {
	const cleanup: Array<() => void | Promise<void>> = [];

	afterEach(async () => {
		for (const clean of cleanup.splice(0).reverse()) {
			await clean();
		}
	});

	it("passes only after observing a working served MCP instance and specific denials", async () => {
		const harness = await startHarness(cleanup);
		const report = await runServedMcpContainmentProbe({
			allowRun: true,
			endpoint: harness.endpoint("private"),
			offDomainPeerEndpoint: harness.endpoint("off-domain"),
			forgedAuthorityEndpoint: harness.endpoint("forged"),
			wrongConnectionEndpoint: harness.endpoint("wrong"),
			unauthenticatedEndpoint: { url: harness.url },
			origin: containedPeerOrigin(),
		});

		expect(report).toMatchObject({
			status: "pass",
			ran: true,
			probeId: "execution.served_mcp_containment",
			origin: {
				kind: "contained-peer",
				containerName: "tc-hermes-contained",
				observedPeerAddress: "127.0.0.1",
				observedPeerSource: "server-peer-echo",
				expectedPeerAddress: "127.0.0.1",
				expectedPeerSource: "configured-contained-ip",
			},
		});
		for (const property of SERVED_MCP_REQUIRED_PROPERTY_NAMES) {
			expect(report.properties[property]).toBe(true);
		}
		const serialized = JSON.stringify(report);
		expect(serialized).not.toContain(harness.privateHandle);
		expect(serialized).not.toContain("probe-private");
		expect(serialized).not.toContain("probe-forged");
		expect(serialized).not.toContain("tc_probe_provider_without_ledger_token");
		expect(serialized).not.toContain("approvalToken");
		expect(serialized).not.toContain(new URL(harness.url).host);
	});

	it("passes with the real bearer resolver denying forged and wrong-connection tokens at HTTP auth", async () => {
		const harness = await startBearerHarness(cleanup);
		const report = await runServedMcpContainmentProbe({
			allowRun: true,
			endpoint: harness.endpoint("private"),
			offDomainPeerEndpoint: harness.endpoint("off-domain"),
			forgedAuthorityEndpoint: harness.endpoint("forged"),
			wrongConnectionEndpoint: harness.endpoint("wrong"),
			unauthenticatedEndpoint: { url: harness.url },
			origin: containedPeerOrigin(),
		});

		expect(report.status).toBe("pass");
		expect(report.properties.handle_forgery_denied).toBe(true);
		expect(report.properties.wrong_connection_denied).toBe(true);
		expect(report.properties.off_domain_peer_denied).toBe(true);
		expect(report.checks.find((check) => check.name === "handle_forgery_denied")).toMatchObject({
			status: "pass",
			httpStatus: 403,
			rpcErrorCode: -32001,
			rpcErrorMessage: expect.stringContaining("not authorized"),
		});
		expect(report.checks.find((check) => check.name === "wrong_connection_denied")).toMatchObject({
			status: "pass",
			httpStatus: 403,
			rpcErrorCode: -32001,
			rpcErrorMessage: expect.stringContaining("not authorized"),
		});
		const serialized = JSON.stringify(report);
		for (const token of harness.tokens) {
			expect(serialized).not.toContain(token);
		}
		expect(serialized).not.toContain("tc_mcp_conn_");
	});

	it("fails the forged-handle property when a weakened resolver maps forged context to a valid authority", async () => {
		const harness = await startHarness(cleanup, { forgedResolvesAsPrivate: true });
		const report = await runServedMcpContainmentProbe({
			allowRun: true,
			endpoint: harness.endpoint("private"),
			offDomainPeerEndpoint: harness.endpoint("off-domain"),
			forgedAuthorityEndpoint: harness.endpoint("forged"),
			wrongConnectionEndpoint: harness.endpoint("wrong"),
			unauthenticatedEndpoint: { url: harness.url },
			origin: containedPeerOrigin(),
		});

		expect(report.status).toBe("fail");
		expect(report.properties.handle_forgery_denied).toBe(false);
		expect(report.checks.find((check) => check.name === "handle_forgery_denied")).toMatchObject({
			status: "fail",
		});
	});

	it("writes sanitized evidence without raw transport handles, headers, or probe tokens", async () => {
		const harness = await startHarness(cleanup);
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tc-served-mcp-evidence-"));
		const evidencePath = path.join(tempDir, "execution-served-mcp-containment.json");
		cleanup.push(() => fs.rmSync(tempDir, { recursive: true, force: true }));
		const report = await runServedMcpContainmentProbe({
			allowRun: true,
			endpoint: harness.endpoint("private"),
			offDomainPeerEndpoint: harness.endpoint("off-domain"),
			forgedAuthorityEndpoint: harness.endpoint("forged"),
			wrongConnectionEndpoint: harness.endpoint("wrong"),
			unauthenticatedEndpoint: { url: harness.url },
			origin: containedPeerOrigin(),
		});

		writeServedMcpContainmentEvidence(report, evidencePath);
		const artifact = fs.readFileSync(evidencePath, "utf8");

		expect(JSON.parse(artifact)).toMatchObject({ status: "pass", ran: true });
		expect(artifact).not.toContain(harness.privateHandle);
		expect(artifact).not.toContain("probe-private");
		expect(artifact).not.toContain("probe-off-domain");
		expect(artifact).not.toContain("probe-forged");
		expect(artifact).not.toContain("probe-wrong");
		expect(artifact).not.toContain("tc_probe_provider_without_ledger_token");
		expect(artifact).not.toContain("approvalToken");
		expect(artifact).not.toContain(new URL(harness.url).host);
	});

	it("classifies relay-self evidence as smoke-only and not production containment", async () => {
		const harness = await startHarness(cleanup);
		const evidence = await runServedMcpContainmentProbe({
			allowRun: true,
			endpoint: harness.endpoint("private"),
			offDomainPeerEndpoint: harness.endpoint("off-domain"),
			forgedAuthorityEndpoint: harness.endpoint("forged"),
			wrongConnectionEndpoint: harness.endpoint("wrong"),
			unauthenticatedEndpoint: { url: harness.url },
			origin: {
				containerName: "telclaude",
				expectedPeerAddress: "192.0.2.11",
				relayPeerAddress: "127.0.0.1",
			},
		});

		const report = evaluateServedMcpContainmentEvidence(evidence);

		expect(evidence.status).toBe("pass");
		expect(report.productionEnable).toBe(false);
		expect(report.gates.find((gate) => gate.name === "servedMcp.origin")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("smoke"),
		});
	});

	it("rejects self-declared or malformed contained-peer origin evidence", async () => {
		const harness = await startHarness(cleanup);
		const evidence = await runServedMcpContainmentProbe({
			allowRun: true,
			endpoint: harness.endpoint("private"),
			offDomainPeerEndpoint: harness.endpoint("off-domain"),
			forgedAuthorityEndpoint: harness.endpoint("forged"),
			wrongConnectionEndpoint: harness.endpoint("wrong"),
			unauthenticatedEndpoint: { url: harness.url },
			origin: containedPeerOrigin(),
		});
		const selfDeclaredOrigin = {
			kind: evidence.origin.kind,
			containerName: evidence.origin.containerName,
			observedPeerAddress: evidence.origin.observedPeerAddress,
			expectedPeerAddress: evidence.origin.expectedPeerAddress,
			expectedPeerSource: evidence.origin.expectedPeerSource,
			detail: evidence.origin.detail,
		};

		for (const origin of [
			selfDeclaredOrigin,
			{ ...evidence.origin, observedPeerAddress: "tc-hermes-contained" },
			{ ...evidence.origin, observedPeerAddress: "127.0.0.1", expectedPeerAddress: "127.0.0.2" },
		]) {
			const report = evaluateServedMcpContainmentEvidence({ ...evidence, origin });
			expect(report.productionEnable).toBe(false);
			expect(report.gates.find((gate) => gate.name === "servedMcp.origin")).toMatchObject({
				status: "fail",
				detail: expect.stringContaining("server-observed contained peer IP"),
			});
		}
	});

	it("fails production evaluation when negative controls are absent or false", async () => {
		const harness = await startHarness(cleanup);
		const evidence = await runServedMcpContainmentProbe({
			allowRun: true,
			endpoint: harness.endpoint("private"),
			offDomainPeerEndpoint: harness.endpoint("off-domain"),
			forgedAuthorityEndpoint: harness.endpoint("forged"),
			wrongConnectionEndpoint: harness.endpoint("wrong"),
			unauthenticatedEndpoint: { url: harness.url },
			origin: containedPeerOrigin(),
		});

		const absent = evaluateServedMcpContainmentEvidence({
			...evidence,
			negativeControls: {},
		});
		const falseControl = evaluateServedMcpContainmentEvidence({
			...evidence,
			negativeControls: {
				...evidence.negativeControls,
				offDomainPeerDenied: false,
			},
		});

		expect(absent.productionEnable).toBe(false);
		expect(
			absent.gates.find((gate) => gate.name === "servedMcp.negative.offDomainPeerDenied")?.detail,
		).toContain("missing");
		expect(falseControl.productionEnable).toBe(false);
		expect(
			falseControl.gates.find((gate) => gate.name === "servedMcp.negative.offDomainPeerDenied")
				?.detail,
		).toContain("false");
	});

	it("does not count negative-control transport failures as proven denials", async () => {
		const harness = await startHarness(cleanup);

		for (const target of [
			{
				context: "probe-forged",
				property: "handle_forgery_denied",
				negativeControl: "forgedAuthorityDenied",
			},
			{
				context: "probe-wrong",
				property: "wrong_connection_denied",
				negativeControl: "wrongConnectionDenied",
			},
			{
				context: "probe-off-domain",
				property: "off_domain_peer_denied",
				negativeControl: "offDomainPeerDenied",
			},
		] as const) {
			const report = await runServedMcpContainmentProbe({
				allowRun: true,
				endpoint: harness.endpoint("private"),
				offDomainPeerEndpoint: harness.endpoint("off-domain"),
				forgedAuthorityEndpoint: harness.endpoint("forged"),
				wrongConnectionEndpoint: harness.endpoint("wrong"),
				unauthenticatedEndpoint: { url: harness.url },
				origin: containedPeerOrigin(),
				fetchImpl: async (input, init) => {
					const headers = new Headers(init?.headers);
					if (headers.get("x-tc-probe-context") === target.context) {
						throw new Error(`simulated transport failure for ${target.context}`);
					}
					return fetch(input, init);
				},
			});

			expect(report.status).toBe("fail");
			expect(report.properties[target.property]).toBe(false);
			expect(report.negativeControls[target.negativeControl]).toBe(false);
			expect(report.checks.find((check) => check.name === target.property)).toMatchObject({
				status: "fail",
				detail: expect.stringContaining("transportError="),
			});
			expect(evaluateServedMcpContainmentEvidence(report).productionEnable).toBe(false);
		}
	});
});

type HarnessOptions = {
	forgedResolvesAsPrivate?: boolean;
};

async function startHarness(
	cleanup: Array<() => void | Promise<void>>,
	options: HarnessOptions = {},
) {
	const registry = createTelclaudeMcpAuthorityRegistry();
	const privateConnection = connection("ops", "endpoint-private", "netns-private");
	const socialConnection = connection("social", "endpoint-social", "netns-social");
	const privateGrant = registry.register({
		connection: privateConnection,
		authority: authority(),
		nowMs: 100_000,
	});
	const ledger = createTelclaudeMcpSideEffectLedger({
		nowMs: () => 120_000,
		makeRef: makeRef(),
		verifyApproval: async () => ({
			ok: false,
			code: "approval_required",
			reason: "Probe approval token is not valid",
		}),
	});
	const relayClients: TelclaudeLiveMcpRelayClients = {
		providerRead: async () => ({ balances: [] }),
		providerPrepareWrite: async () => ({ actionRef: "prepared-by-relay" }),
		memorySearch: async () => ({ entries: [] }),
		memoryWrite: async () => ({ accepted: 1 }),
		attachmentGet: async () => ({ bytes: 0 }),
		outboundPrepare: async () => {
			throw new Error("outbound conversation unavailable or unauthorized");
		},
		auditNote: async () => ({ stored: true }),
	};
	const server = createTelclaudeLiveMcpRelayHttpServer({
		registry,
		ledger,
		relayClients,
		bindHost: "telclaude",
		networkName: "telclaude-hermes-relay",
		nowMs: () => 120_000,
	});
	const privateContext = {
		authorityHandle: privateGrant.handle,
		connection: privateConnection,
		observedPeerAddress: "127.0.0.1",
	};
	const nodeServer = createTelclaudeLiveMcpNodeHttpServer(server, {
		resolveConnection: (request) => {
			const context = request.headers["x-tc-probe-context"];
			if (context === "probe-private") return privateContext;
			if (context === "probe-forged") {
				return options.forgedResolvesAsPrivate
					? privateContext
					: {
							authorityHandle: "tc_mcp_forged",
							connection: privateConnection,
						};
			}
			if (context === "probe-wrong") {
				return {
					authorityHandle: privateGrant.handle,
					connection: socialConnection,
				};
			}
			if (context === "probe-off-domain") return null;
			return null;
		},
	});
	const { url, close } = await listen(nodeServer);
	cleanup.push(close);
	return {
		url,
		privateHandle: privateGrant.handle,
		endpoint: (context: "private" | "forged" | "wrong" | "off-domain") => ({
			url,
			headers: { "x-tc-probe-context": `probe-${context}` },
		}),
	};
}

async function startBearerHarness(cleanup: Array<() => void | Promise<void>>) {
	const registry = createTelclaudeMcpAuthorityRegistry();
	const resolver = createTelclaudeLiveMcpConnectionResolver({
		registry,
		nowMs: () => 120_000,
		allowedPeerAddresses: ["127.0.0.1"],
	});
	const privateConnection = connection("ops", "endpoint-private", "netns-private");
	const socialConnection = connection("social", "endpoint-social", "netns-social");
	const tokenBundle = createTelclaudeLiveMcpProbeTokenBundle({
		registry,
		resolver,
		privateConnection,
		wrongConnection: socialConnection,
		privateAuthority: authority(),
		nowMs: 120_000,
		ttlMs: 60_000,
		peerAddress: "127.0.0.1",
	});
	const ledger = createTelclaudeMcpSideEffectLedger({
		nowMs: () => 120_000,
		makeRef: makeRef(),
		verifyApproval: async () => ({
			ok: false,
			code: "approval_required",
			reason: "Probe approval token is not valid",
		}),
	});
	const relayClients: TelclaudeLiveMcpRelayClients = {
		providerRead: async () => ({ balances: [] }),
		providerPrepareWrite: async () => ({ actionRef: "prepared-by-relay" }),
		memorySearch: async () => ({ entries: [] }),
		memoryWrite: async () => ({ accepted: 1 }),
		attachmentGet: async () => ({ bytes: 0 }),
		outboundPrepare: async () => {
			throw new Error("outbound conversation unavailable or unauthorized");
		},
		auditNote: async () => ({ stored: true }),
	};
	const server = createTelclaudeLiveMcpRelayHttpServer({
		registry,
		ledger,
		relayClients,
		bindHost: "telclaude",
		networkName: "telclaude-hermes-relay",
		nowMs: () => 120_000,
	});
	const nodeServer = createTelclaudeLiveMcpNodeHttpServer(server, {
		resolveConnection: (request) => resolver.resolveConnection(request),
	});
	const { url, close } = await listen(nodeServer);
	cleanup.push(close);
	const tokens = {
		private: tokenBundle.allowed.token,
		"off-domain": tokenBundle.offDomainPeer.token,
		forged: tokenBundle.forged.token,
		wrong: tokenBundle.wrongConnection.token,
	};
	return {
		url,
		tokens: Object.values(tokens),
		endpoint: (context: "private" | "forged" | "wrong" | "off-domain") => ({
			url,
			headers: { Authorization: `Bearer ${tokens[context]}` },
		}),
	};
}

function containedPeerOrigin() {
	return {
		containerName: "tc-hermes-contained",
		expectedPeerAddress: "127.0.0.1",
	};
}

function connection(
	profileId: string,
	endpointId: string,
	networkNamespace: string,
): TelclaudeMcpAuthorityConnection {
	return {
		sessionKey: `telegram:${profileId}`,
		profileId,
		endpointId,
		networkNamespace,
	};
}

function authority(overrides: Partial<TelclaudeMcpAuthority> = {}): TelclaudeMcpAuthority {
	return {
		actorId: "operator",
		profileId: "ops",
		domain: "private",
		memorySource: "telegram:ops",
		writableNamespace: "private:ops",
		providerScopes: ["bank"],
		outboundChannels: ["whatsapp"],
		endpointId: "endpoint-private",
		networkNamespace: "netns-private",
		...overrides,
	};
}

function makeRef(): () => string {
	let refCounter = 0;
	return () => `effect-served-mcp-${++refCounter}`;
}

async function listen(server: http.Server): Promise<{ url: string; close(): Promise<void> }> {
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const address = server.address();
	if (!address || typeof address === "string") {
		throw new Error("HTTP server did not expose an address");
	}
	return {
		url: `http://127.0.0.1:${address.port}/mcp`,
		close: () => new Promise<void>((resolve) => server.close(() => resolve())),
	};
}
