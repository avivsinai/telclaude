import type { PermissionTier, SecurityConfig } from "../config/config.js";
import { chatIdToString } from "../utils.js";

/**
 * Capabilities for each permission tier.
 */
export const TIER_CAPABILITIES: Record<
	PermissionTier,
	{
		claudeFlags: string[];
		description: string;
	}
> = {
	READ_ONLY: {
		claudeFlags: ["--allowedTools", "Read,Glob,Grep,WebFetch,WebSearch"],
		description: "Can only read files and search. No write operations allowed.",
	},
	WRITE_SAFE: {
		claudeFlags: [
			"--allowedTools",
			"Read,Glob,Grep,Write,Edit,WebFetch,WebSearch",
			"--disallowedCommands",
			"rm,rmdir,mv,chmod,chown,kill,pkill",
		],
		description: "Can read and write files, but cannot delete or modify permissions.",
	},
	FULL_ACCESS: {
		claudeFlags: ["--dangerously-skip-permissions"],
		description: "Full system access with no restrictions.",
	},
};

/**
 * Get the permission tier for a user.
 */
export function getUserPermissionTier(
	userId: string | number,
	securityConfig?: SecurityConfig,
): PermissionTier {
	const normalizedId = typeof userId === "number" ? String(userId) : userId;
	const withPrefix = chatIdToString(userId);

	// Check user-specific permissions
	const userPerms = securityConfig?.permissions?.users;
	if (userPerms) {
		// Try both with and without prefix
		if (userPerms[normalizedId]) {
			return userPerms[normalizedId].tier;
		}
		if (userPerms[withPrefix]) {
			return userPerms[withPrefix].tier;
		}
	}

	// Return default tier
	return securityConfig?.permissions?.defaultTier ?? "READ_ONLY";
}

/**
 * Get Claude CLI flags for a permission tier.
 */
export function getClaudeFlagsForTier(tier: PermissionTier): string[] {
	return TIER_CAPABILITIES[tier].claudeFlags;
}

/**
 * Check if a user has at least the specified permission tier.
 */
export function hasMinimumTier(userTier: PermissionTier, requiredTier: PermissionTier): boolean {
	const tierOrder: PermissionTier[] = ["READ_ONLY", "WRITE_SAFE", "FULL_ACCESS"];
	return tierOrder.indexOf(userTier) >= tierOrder.indexOf(requiredTier);
}

/**
 * Format tier for display.
 */
export function formatTier(tier: PermissionTier): string {
	switch (tier) {
		case "READ_ONLY":
			return "Read Only";
		case "WRITE_SAFE":
			return "Write Safe";
		case "FULL_ACCESS":
			return "Full Access";
	}
}
