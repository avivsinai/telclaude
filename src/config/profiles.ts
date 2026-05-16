import type { OperatorProfileConfig, TelclaudeConfig } from "./config.js";
import { getChatActiveProfileId } from "./sessions.js";

export const IMPLICIT_DEFAULT_PROFILE_ID = "default";

export type EffectiveOperatorProfile = {
	id: string;
	label: string;
	description?: string;
	soulPath?: string;
	allowedSkills?: string[];
	defaultModel?: OperatorProfileConfig["defaultModel"];
	implicit: boolean;
};

export type ResolvedChatProfile = {
	profile: EffectiveOperatorProfile;
	requestedProfileId?: string;
	missingProfileId?: string;
	warnings: string[];
};

export function implicitDefaultProfile(): EffectiveOperatorProfile {
	return {
		id: IMPLICIT_DEFAULT_PROFILE_ID,
		label: "Default",
		implicit: true,
	};
}

export function listOperatorProfiles(cfg: TelclaudeConfig): EffectiveOperatorProfile[] {
	return [
		implicitDefaultProfile(),
		...(cfg.profiles ?? []).map((profile) => ({
			...profile,
			allowedSkills: profile.allowedSkills ? [...profile.allowedSkills] : undefined,
			implicit: false,
		})),
	];
}

export function getOperatorProfile(
	profileId: string,
	cfg: TelclaudeConfig,
): EffectiveOperatorProfile | null {
	if (profileId === IMPLICIT_DEFAULT_PROFILE_ID) {
		return implicitDefaultProfile();
	}
	const configured = (cfg.profiles ?? []).find((profile) => profile.id === profileId);
	if (!configured) return null;
	return {
		...configured,
		allowedSkills: configured.allowedSkills ? [...configured.allowedSkills] : undefined,
		implicit: false,
	};
}

export function resolveChatProfile(chatId: number, cfg: TelclaudeConfig): ResolvedChatProfile {
	const requestedProfileId = getChatActiveProfileId(chatId) ?? undefined;
	if (!requestedProfileId) {
		return { profile: implicitDefaultProfile(), warnings: [] };
	}

	const profile = getOperatorProfile(requestedProfileId, cfg);
	if (profile) {
		return { profile, requestedProfileId, warnings: [] };
	}

	return {
		profile: implicitDefaultProfile(),
		requestedProfileId,
		missingProfileId: requestedProfileId,
		warnings: [`configured profile missing: ${requestedProfileId}`],
	};
}

export function formatAllowedSkillsCount(profile: EffectiveOperatorProfile): string {
	if (profile.allowedSkills === undefined) return "all private skills";
	if (profile.allowedSkills.length === 0) return "no skills";
	return `${profile.allowedSkills.length} skill${profile.allowedSkills.length === 1 ? "" : "s"}`;
}

export function formatProfileSummary(resolved: ResolvedChatProfile): string {
	const { profile } = resolved;
	const parts = [`${profile.label} (${profile.id})`, formatAllowedSkillsCount(profile)];
	if (profile.defaultModel) {
		parts.push(`model ${profile.defaultModel.providerId}:${profile.defaultModel.modelId}`);
	}
	if (profile.description) {
		parts.push(profile.description);
	}
	if (resolved.missingProfileId) {
		parts.push(`warning ${resolved.missingProfileId} not configured`);
	}
	return parts.join(" · ");
}
