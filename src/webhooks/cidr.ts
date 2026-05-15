import { isIP } from "node:net";
import { IPv4, IPv4CidrRange, IPv6, IPv6CidrRange } from "ip-num";

function normalizeIp(ip: string): string {
	const trimmed = ip.trim();
	if (trimmed.startsWith("::ffff:")) {
		const mapped = trimmed.slice("::ffff:".length);
		if (isIP(mapped) === 4) return mapped;
	}
	return trimmed;
}

export function validateAllowedCidrs(cidrs: string[]): string[] {
	const seen = new Set<string>();
	const normalized: string[] = [];
	for (const raw of cidrs) {
		const cidr = raw.trim();
		if (!cidr) continue;
		try {
			if (cidr.includes(":")) {
				IPv6CidrRange.fromCidr(cidr);
			} else {
				IPv4CidrRange.fromCidr(cidr);
			}
		} catch (err) {
			throw new Error(
				`invalid CIDR '${cidr}': ${err instanceof Error ? err.message : String(err)}`,
			);
		}
		if (!seen.has(cidr)) {
			seen.add(cidr);
			normalized.push(cidr);
		}
	}
	return normalized;
}

export function ipAllowedByCidrs(sourceIp: string | undefined, allowedCidrs: string[]): boolean {
	if (allowedCidrs.length === 0) return true;
	if (!sourceIp) return false;

	const ip = normalizeIp(sourceIp);
	const version = isIP(ip);
	if (version === 4) {
		const addr = IPv4.fromString(ip);
		for (const cidr of allowedCidrs) {
			if (!cidr.includes(":") && IPv4CidrRange.fromCidr(cidr).contains(addr)) {
				return true;
			}
		}
		return false;
	}

	if (version === 6) {
		const addr = IPv6.fromString(ip);
		for (const cidr of allowedCidrs) {
			if (cidr.includes(":") && IPv6CidrRange.fromCidr(cidr).contains(addr)) {
				return true;
			}
		}
		return false;
	}

	return false;
}
