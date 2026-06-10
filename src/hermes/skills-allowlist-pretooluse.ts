import type { PermissionTier } from "../config/config.js";
import { buildSkillLoadPlan, resolveSkillPersonaContext } from "../skills/persona.js";

export type SkillAllowlistPreToolUseProbeResult = {
	readonly hookRegistered: boolean;
	readonly decision: "allow" | "deny";
	readonly reason?: string;
};

function extractDenyReason(skillName: string, reason: string): SkillAllowlistPreToolUseProbeResult {
	return {
		hookRegistered: true,
		decision: "deny",
		reason: `Skill "${skillName}" ${reason}`,
	};
}

export async function probeSkillAllowlistPreToolUse(options: {
	readonly cwd: string;
	readonly tier: PermissionTier;
	readonly skillName: string;
	readonly allowedSkills?: readonly string[];
	readonly omitAllowedSkills?: boolean;
	readonly allowedAgentSkills?: readonly string[];
	readonly enableSkills?: boolean;
}): Promise<SkillAllowlistPreToolUseProbeResult> {
	if (options.enableSkills === false) {
		return {
			hookRegistered: false,
			decision: "deny",
			reason: "skills are disabled for this runtime profile",
		};
	}

	const context = resolveSkillPersonaContext({
		tier: options.tier,
		userId: "hermes:skills-allowlist-probe",
		telemetrySource: options.tier === "SOCIAL" ? "social" : "telegram",
		telemetryServiceId: options.tier === "SOCIAL" ? "hermes-probe" : undefined,
		allowedAgentSkills: options.allowedAgentSkills ?? [],
	});
	const loadPlan = buildSkillLoadPlan(context, { cwd: options.cwd });
	if (!loadPlan.names.includes(options.skillName)) {
		return extractDenyReason(options.skillName, "is not loadable in this persona context.");
	}

	let effectiveAllowedSkills: readonly string[] | null = options.omitAllowedSkills
		? null
		: (options.allowedSkills ?? []);
	if (
		options.tier === "SOCIAL" &&
		options.omitAllowedSkills &&
		(options.allowedAgentSkills?.length ?? 0) === 0
	) {
		effectiveAllowedSkills = [];
	}
	if (options.tier === "SOCIAL" && (options.allowedAgentSkills?.length ?? 0) > 0) {
		effectiveAllowedSkills = [
			...(effectiveAllowedSkills ?? []),
			...(options.allowedAgentSkills ?? []),
		];
	}

	if (effectiveAllowedSkills !== null && !new Set(effectiveAllowedSkills).has(options.skillName)) {
		return extractDenyReason(
			options.skillName,
			"is not in the allowedSkills list for this service.",
		);
	}

	return { hookRegistered: true, decision: "allow" };
}
