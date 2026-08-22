import { once } from "node:events";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";

import { startCapabilityServer } from "../../src/relay/capabilities.js";
import {
	BROKER_PROVIDER_READ_PATH,
	BROKER_SERVE_STRIPPED_READ_PATH,
	authenticateTailscaleBrokerPeer,
	buildBrokerProviderReadBody,
	isBrokerWriteAction,
} from "../../src/relay/tailscale-broker.js";

describe("Tailscale broker", () => {
	let server: http.Server | null = null;

	afterEach(async () => {
		if (!server) return;
		await new Promise<void>((resolve, reject) => {
			server?.close((error) => (error ? reject(error) : resolve()));
		});
		server = null;
	});

	it("stamps session_only and the operator principal, ignoring spoofed identity", () => {
		const built = buildBrokerProviderReadBody(
			{
				providerId: "clalit",
				service: "clalit",
				action: "prescriptions",
				actorUserId: "grok",
				userId: "attacker",
				authPolicy: "interactive_login",
				subjectUserId: "parent-clalit",
			},
			"admin",
		);
		expect(built).toEqual({
			ok: true,
			providerId: "clalit",
			body: JSON.stringify({
				service: "clalit",
				action: "prescriptions",
				params: {},
				subjectUserId: "parent-clalit",
				authPolicy: "session_only",
			}),
		});
		expect(isBrokerWriteAction("clalit", "prescription_renewal")).toBe(true);
		expect(isBrokerWriteAction("clalit", "appointments.book")).toBe(true);
		expect(isBrokerWriteAction("clalit", "form.submit")).toBe(true);
		expect(isBrokerWriteAction("google", "search")).toBe(true);
		expect(isBrokerWriteAction("clalit", "prescriptions")).toBe(false);
	});

	it("lets a WhoIs peer read through the relay and denies docker/compose/vault", async () => {
		const calls: unknown[] = [];
		server = startCapabilityServer({
			port: 0,
			host: "127.0.0.1",
			broker: {
				whois: async () => ({ loginName: "aviv@example" }),
				operatorUserId: "admin",
				providerProxy: async (request) => {
					calls.push(request);
					return { status: "ok", data: { prescriptions: [] } };
				},
			},
		});
		await once(server, "listening");
		const { port } = server.address() as AddressInfo;
		const baseUrl = `http://127.0.0.1:${port}`;

		const read = await fetch(`${baseUrl}${BROKER_PROVIDER_READ_PATH}`, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				providerId: "clalit",
				service: "clalit",
				action: "prescriptions",
				actorUserId: "spoofed",
				authPolicy: "interactive_login",
			}),
		});
		expect(read.status).toBe(200);
		expect(await read.json()).toEqual({ status: "ok", data: { prescriptions: [] } });
		expect(calls).toEqual([
			{
				providerId: "clalit",
				path: "/v1/fetch",
				method: "POST",
				body: JSON.stringify({
					service: "clalit",
					action: "prescriptions",
					params: {},
					subjectUserId: "admin",
					authPolicy: "session_only",
				}),
				userId: "admin",
			},
		]);

		const write = await fetch(`${baseUrl}${BROKER_PROVIDER_READ_PATH}`, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				providerId: "clalit",
				service: "clalit",
				action: "appointments.book",
			}),
		});
		expect(write.status).toBe(403);

		for (const path of ["/v1/broker/docker", "/v1/broker/compose", "/v1/broker/vault"]) {
			const denied = await fetch(`${baseUrl}${path}`, {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ command: "compose down -v" }),
			});
			expect(denied.status).toBe(403);
		}
	});

	it("requires the node token when one is configured", async () => {
		server = startCapabilityServer({
			port: 0,
			host: "127.0.0.1",
			broker: {
				whois: async () => ({ loginName: "aviv@example" }),
				nodeToken: "node-bound-token",
				providerProxy: async () => ({ status: "ok", data: {} }),
			},
		});
		await once(server, "listening");
		const { port } = server.address() as AddressInfo;
		const baseUrl = `http://127.0.0.1:${port}`;

		const missing = await fetch(`${baseUrl}${BROKER_PROVIDER_READ_PATH}`, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				providerId: "clalit",
				service: "clalit",
				action: "prescriptions",
			}),
		});
		expect(missing.status).toBe(401);

		const ok = await fetch(`${baseUrl}${BROKER_PROVIDER_READ_PATH}`, {
			method: "POST",
			headers: {
				"content-type": "application/json",
				authorization: "Bearer node-bound-token",
			},
			body: JSON.stringify({
				providerId: "clalit",
				service: "clalit",
				action: "prescriptions",
			}),
		});
		expect(ok.status).toBe(200);
	});

	it("rejects a matching node token when WhoIs does not prove a Tailscale peer", async () => {
		server = startCapabilityServer({
			port: 0,
			host: "127.0.0.1",
			broker: {
				whois: async () => null,
				nodeToken: "node-bound-token",
				providerProxy: async () => ({ status: "ok", data: {} }),
			},
		});
		await once(server, "listening");
		const { port } = server.address() as AddressInfo;

		const response = await fetch(`http://127.0.0.1:${port}${BROKER_PROVIDER_READ_PATH}`, {
			method: "POST",
			headers: {
				"content-type": "application/json",
				authorization: "Bearer node-bound-token",
			},
			body: JSON.stringify({
				providerId: "clalit",
				service: "clalit",
				action: "prescriptions",
			}),
		});
		expect(response.status).toBe(401);
	});

	it("accepts a Serve client when WhoIs of the TCP peer fails but X-Forwarded-For WhoIs succeeds", async () => {
		const clientAddr = "100.64.1.10";
		server = startCapabilityServer({
			port: 0,
			host: "127.0.0.1",
			broker: {
				whois: async (addr) => (addr === clientAddr ? { loginName: "aviv@example" } : null),
				trustedProxies: ["127.0.0.1"],
				operatorUserId: "admin",
				providerProxy: async () => ({ status: "ok", data: { balance: [] } }),
			},
		});
		await once(server, "listening");
		const { port } = server.address() as AddressInfo;

		const response = await fetch(`http://127.0.0.1:${port}${BROKER_PROVIDER_READ_PATH}`, {
			method: "POST",
			headers: {
				"content-type": "application/json",
				"x-forwarded-for": clientAddr,
			},
			body: JSON.stringify({
				providerId: "poalim",
				service: "poalim",
				action: "balance",
			}),
		});
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ status: "ok", data: { balance: [] } });
	});

	it("rejects a Serve login header that does not match WhoIs", async () => {
		const clientAddr = "100.64.1.10";
		server = startCapabilityServer({
			port: 0,
			host: "127.0.0.1",
			broker: {
				whois: async (addr) => (addr === clientAddr ? { loginName: "aviv@example" } : null),
				trustedProxies: ["127.0.0.1"],
				providerProxy: async () => ({ status: "ok", data: {} }),
			},
		});
		await once(server, "listening");
		const { port } = server.address() as AddressInfo;

		const response = await fetch(`http://127.0.0.1:${port}${BROKER_PROVIDER_READ_PATH}`, {
			method: "POST",
			headers: {
				"content-type": "application/json",
				"x-forwarded-for": clientAddr,
				"tailscale-user-login": "other@example",
			},
			body: JSON.stringify({
				providerId: "poalim",
				service: "poalim",
				action: "balance",
			}),
		});
		expect(response.status).toBe(401);
	});

	it("does not honor X-Forwarded-For from the contained Hermes address", async () => {
		const auth = await authenticateTailscaleBrokerPeer(
			{
				socket: { remoteAddress: "172.30.92.11" },
				headers: { "x-forwarded-for": "100.64.1.10" },
			} as http.IncomingMessage,
			{
				whois: async (addr) => (addr === "100.64.1.10" ? { loginName: "aviv@example" } : null),
				trustedProxies: ["127.0.0.1"],
			},
		);
		expect(auth).toEqual({ ok: false, status: 401, error: "Unauthorized." });
	});

	it("treats Serve-stripped /provider/read as the broker read path", async () => {
		server = startCapabilityServer({
			port: 0,
			host: "127.0.0.1",
			broker: {
				whois: async () => ({ loginName: "aviv@example" }),
				operatorUserId: "admin",
				providerProxy: async () => ({ status: "ok", data: { home: true } }),
			},
		});
		await once(server, "listening");
		const { port } = server.address() as AddressInfo;

		const response = await fetch(`http://127.0.0.1:${port}${BROKER_SERVE_STRIPPED_READ_PATH}`, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				providerId: "clalit",
				service: "clalit",
				action: "home",
			}),
		});
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ status: "ok", data: { home: true } });
	});
});
