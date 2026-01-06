import { loadConfig } from "../config/config.js";
import {
	cachedDNSLookup,
	checkPrivateNetworkAccess,
	isPrivateIP,
} from "../sandbox/network-proxy.js";

export async function validateProviderBaseUrl(
	baseUrl: string,
): Promise<{ url: URL; port: number }> {
	let url: URL;
	try {
		url = new URL(baseUrl);
	} catch {
		throw new Error(`Invalid provider URL: ${baseUrl}`);
	}

	if (url.protocol !== "http:" && url.protocol !== "https:") {
		throw new Error(`Unsupported provider URL protocol: ${url.protocol}`);
	}

	const port = url.port ? Number.parseInt(url.port, 10) : url.protocol === "https:" ? 443 : 80;

	const cfg = loadConfig();
	const endpoints = cfg.security?.network?.privateEndpoints ?? [];
	if (!endpoints.length) {
		throw new Error(
			"No private endpoints configured. Add a provider endpoint via `telclaude network add`.",
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
