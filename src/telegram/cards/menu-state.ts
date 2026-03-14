import { listActiveSkills, listDraftSkills } from "../../commands/skills-promote.js";
import { loadConfig, type TelclaudeConfig } from "../../config/config.js";
import { isAdmin } from "../../security/linking.js";
import { loadPendingQueueEntries } from "./renderers/pending-queue.js";
import type { SkillsMenuCardState, SocialMenuCardState } from "./types.js";
import { CardKind } from "./types.js";

export type SocialServiceConfig = NonNullable<TelclaudeConfig["socialServices"]>[number];

export function getEnabledSocialServices(
	cfg: TelclaudeConfig = loadConfig(),
): SocialServiceConfig[] {
	return cfg.socialServices?.filter((service) => service.enabled) ?? [];
}

export function buildSkillsMenuState(chatId: number, sessionKey?: string): SkillsMenuCardState {
	return {
		kind: CardKind.SkillsMenu,
		title: "Skills",
		activeSkills: listActiveSkills().map((name) => ({ id: name, label: name })),
		draftCount: listDraftSkills().length,
		adminControlsEnabled: isAdmin(chatId),
		sessionKey,
		lastRefreshedAt: Date.now(),
	};
}

export function buildSocialMenuState(
	chatId: number,
	cfg: TelclaudeConfig = loadConfig(),
): SocialMenuCardState {
	const adminControlsEnabled = isAdmin(chatId);
	return {
		kind: CardKind.SocialMenu,
		title: "Social",
		services: getEnabledSocialServices(cfg).map((service) => ({
			id: service.id,
			label: service.id,
		})),
		queueCount: adminControlsEnabled ? loadPendingQueueEntries(String(chatId)).length : undefined,
		adminControlsEnabled,
		lastRefreshedAt: Date.now(),
	};
}
