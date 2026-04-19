import net from "node:net";

import { loadConfig } from "../config/config.js";
import {
	cachedDNSLookup,
	checkPrivateNetworkAccess,
	isNonOverridableBlock,
	isPrivateIP,
} from "../sandbox/network-proxy.js";

function isLoopbackHost(hostname: string): boolean {
	return hostname === "localhost" || hostname === "::1" || hostname.startsWith("127.");
}

function isInternalProviderHostname(hostname: string): boolean {
	return isLoopbackHost(hostname) || hostname.endsWith(".local") || !hostname.includes(".");
}

export async function validateProviderBaseUrlInput(baseUrl: string): Promise<URL> {
	let url: URL;
	try {
		url = new URL(baseUrl);
	} catch {
		throw new Error(`Invalid provider URL: ${baseUrl}`);
	}

	if (url.protocol !== "http:" && url.protocol !== "https:") {
		throw new Error(`Unsupported provider URL protocol: ${url.protocol}`);
	}

	const hostname = url.hostname.toLowerCase();
	const internalHost = isInternalProviderHostname(hostname);
	if (net.isIP(hostname) !== 0) {
		if (isLoopbackHost(hostname)) {
			return url;
		}
		if (isNonOverridableBlock(hostname) || isPrivateIP(hostname)) {
			throw new Error(
				"Provider URL must not use a raw private, metadata, or CGNAT IP. Use a trusted hostname instead.",
			);
		}
		throw new Error("Provider URL must use a hostname instead of a raw IP address.");
	}

	if (!internalHost && url.protocol !== "https:") {
		throw new Error(
			"Provider URL must use https unless it points at loopback, .local, or a container hostname.",
		);
	}

	const resolved = await cachedDNSLookup(hostname);
	if (resolved && resolved.length > 0 && !internalHost) {
		const privateTargets = resolved.filter((ip) => isNonOverridableBlock(ip) || isPrivateIP(ip));
		if (privateTargets.length > 0) {
			throw new Error(
				`Provider hostname resolves to blocked private IPs: ${privateTargets.join(", ")}`,
			);
		}
	}

	return url;
}

export async function validateProviderBaseUrl(
	baseUrl: string,
): Promise<{ url: URL; port: number }> {
	const url = await validateProviderBaseUrlInput(baseUrl);

	const port = url.port ? Number.parseInt(url.port, 10) : url.protocol === "https:" ? 443 : 80;

	const cfg = loadConfig();
	const endpoints = cfg.security?.network?.privateEndpoints ?? [];
	if (!endpoints.length) {
		throw new Error(
			"No private endpoints configured. Configure a provider via `telclaude providers add <id>`. " +
				"For non-provider private services, use `telclaude dev network add` as an escape hatch.",
		);
	}

	const privateCheck = await checkPrivateNetworkAccess(url.hostname, port, endpoints);
	if (!privateCheck.allowed || !privateCheck.matchedEndpoint) {
		throw new Error(
			privateCheck.reason || "Provider URL must resolve to an allowlisted private endpoint.",
		);
	}

	const resolved = await cachedDNSLookup(url.hostname);
	const ips = resolved && resolved.length > 0 ? resolved : [url.hostname];
	const nonPrivate = ips.filter((ip) => !isPrivateIP(ip));
	if (nonPrivate.length > 0) {
		throw new Error(
			`Provider URL must resolve to private IPs only (non-private: ${nonPrivate.join(", ")})`,
		);
	}

	return { url, port };
}
