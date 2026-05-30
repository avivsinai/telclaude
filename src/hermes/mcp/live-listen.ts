import type http from "node:http";
import net from "node:net";
import type { TelclaudeLiveMcpRelayHttpServer } from "./live-server.js";

export type TelclaudeLiveMcpListenEndpoint = {
	readonly url: string;
	readonly path: string;
	readonly host: string;
	readonly port: number;
	readonly actualAddress: string;
	readonly networkName: string;
	readonly placement: TelclaudeLiveMcpRelayHttpServer["placement"];
	close(): Promise<void>;
};

export type TelclaudeLiveMcpListenOptions = {
	readonly host?: string;
	readonly port?: number;
	readonly path?: string;
};

export async function listenTelclaudeLiveMcpRelayHttpServer(
	liveServer: TelclaudeLiveMcpRelayHttpServer,
	nodeServer: http.Server,
	options: TelclaudeLiveMcpListenOptions = {},
): Promise<TelclaudeLiveMcpListenEndpoint> {
	const path = options.path ?? "/mcp";
	const host = requiredTrimmed(options.host ?? liveServer.placement.bindHost, "host");
	const port = normalizePort(options.port ?? 0);
	assertPlacementMatchesBindHost(liveServer.placement, host);
	assertRelayInternalBindHost(host);

	await listen(nodeServer, port, host);
	try {
		const address = concreteAddress(nodeServer);
		assertRelayInternalBoundAddress(host, address.address);
		return {
			url: `http://${urlHost(host)}:${address.port}${path}`,
			path,
			host,
			port: address.port,
			actualAddress: address.address,
			networkName: liveServer.placement.networkName,
			placement: liveServer.placement,
			close: () => close(nodeServer),
		};
	} catch (error) {
		await close(nodeServer);
		throw error;
	}
}

export function assertPlacementMatchesBindHost(
	placement: TelclaudeLiveMcpRelayHttpServer["placement"],
	host: string,
): void {
	if (
		placement.side !== "relay" ||
		placement.runsInHermesContainer ||
		placement.networkExposure !== "relay_internal_only"
	) {
		throw new Error("live MCP server placement must be relay-internal");
	}
	if (placement.bindHost !== host) {
		throw new Error(
			`live MCP bind host ${host} does not match placement bindHost ${placement.bindHost}`,
		);
	}
}

export function assertRelayInternalBindHost(host: string): void {
	const normalized = normalizeHost(host);
	if (normalized === "0.0.0.0" || normalized === "::" || normalized === "[::]") {
		throw new Error("live MCP server must not bind an unspecified interface");
	}
	if (normalized === "localhost") {
		throw new Error("live MCP server bind host must be explicit, not localhost");
	}
	const ipVersion = net.isIP(stripIpv6Brackets(normalized));
	if (ipVersion === 4 || ipVersion === 6) {
		if (!isPrivateOrLoopbackAddress(stripIpv6Brackets(normalized), ipVersion)) {
			throw new Error("live MCP server bind host must be loopback or private/internal");
		}
		return;
	}
	if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(normalized)) {
		throw new Error("live MCP server hostname must be a single-label internal name");
	}
}

export function assertRelayInternalBoundAddress(
	requestedHost: string,
	actualAddress: string,
): void {
	const normalizedActual = normalizeHost(actualAddress);
	const actualIpVersion = net.isIP(stripIpv6Brackets(normalizedActual));
	if (actualIpVersion !== 4 && actualIpVersion !== 6) {
		throw new Error("live MCP server actual bind address must be an IP address");
	}
	if (!isPrivateOrLoopbackAddress(stripIpv6Brackets(normalizedActual), actualIpVersion)) {
		throw new Error("live MCP server actual bind address must be loopback or private/internal");
	}
	const normalizedRequested = normalizeHost(requestedHost);
	const requestedIpVersion = net.isIP(stripIpv6Brackets(normalizedRequested));
	if (
		requestedIpVersion !== 0 &&
		normalizeIp(stripIpv6Brackets(normalizedRequested)) !==
			normalizeIp(stripIpv6Brackets(normalizedActual))
	) {
		throw new Error(
			`live MCP actual bind address ${actualAddress} does not match requested host ${requestedHost}`,
		);
	}
}

function normalizePort(port: number): number {
	if (!Number.isInteger(port) || port < 0 || port > 65535) {
		throw new Error(`Invalid live MCP listen port: ${port}`);
	}
	return port;
}

function requiredTrimmed(value: string, field: string): string {
	const trimmed = value.trim();
	if (!trimmed) throw new Error(`live MCP listen ${field} is required`);
	return trimmed;
}

function normalizeHost(host: string): string {
	const trimmed = host.trim().toLowerCase();
	if (trimmed.startsWith("::ffff:")) return trimmed.slice("::ffff:".length);
	if (trimmed === "::1" || trimmed === "[::1]") return "127.0.0.1";
	return trimmed;
}

function stripIpv6Brackets(host: string): string {
	return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
}

function isPrivateOrLoopbackAddress(address: string, ipVersion: 4 | 6): boolean {
	if (ipVersion === 6) {
		const normalized = address.toLowerCase();
		return (
			normalized === "::1" ||
			normalized.startsWith("fc") ||
			normalized.startsWith("fd") ||
			normalized.startsWith("fe80:")
		);
	}
	const parts = address.split(".").map((part) => Number.parseInt(part, 10));
	if (
		parts.length !== 4 ||
		parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)
	) {
		return false;
	}
	const [a, b] = parts;
	return (
		a === 10 ||
		a === 127 ||
		(a === 172 && b >= 16 && b <= 31) ||
		(a === 192 && b === 168) ||
		(a === 100 && b >= 64 && b <= 127)
	);
}

function normalizeIp(address: string): string {
	if (address.startsWith("::ffff:")) return address.slice("::ffff:".length);
	if (address === "::1") return "127.0.0.1";
	return address.toLowerCase();
}

function urlHost(host: string): string {
	const normalized = stripIpv6Brackets(host);
	return net.isIP(normalized) === 6 ? `[${normalized}]` : host;
}

async function listen(server: http.Server, port: number, host: string): Promise<void> {
	await new Promise<void>((resolve, reject) => {
		const onError = (error: Error) => {
			server.off("listening", onListening);
			reject(error);
		};
		const onListening = () => {
			server.off("error", onError);
			resolve();
		};
		server.once("error", onError);
		server.once("listening", onListening);
		server.listen(port, host);
	});
}

function concreteAddress(server: http.Server): { address: string; port: number } {
	const address = server.address();
	if (!address || typeof address === "string") {
		throw new Error("live MCP server did not expose a concrete TCP address");
	}
	return { address: address.address, port: address.port };
}

async function close(server: http.Server): Promise<void> {
	if (!server.listening) return;
	await new Promise<void>((resolve, reject) => {
		server.close((error) => (error ? reject(error) : resolve()));
	});
}
