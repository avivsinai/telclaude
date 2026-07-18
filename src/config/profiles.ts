import { householdMemorySource } from "../memory/source.js";
import { normalizeWhatsAppAddressRef, whatsAppDirectConversationKey } from "../whatsapp/address.js";
import type { OperatorProfileConfig, TelclaudeConfig } from "./config.js";
import { getChatActiveProfileId } from "./sessions.js";

export const IMPLICIT_DEFAULT_PROFILE_ID = "default";

export type EffectiveOperatorProfile = {
	id: string;
	label: string;
	description?: string;
	soulPath?: string;
	allowedSkills?: string[];
	providerScopes?: string[];
	capabilityScopes?: OperatorProfileConfig["capabilityScopes"];
	outboundChannels?: string[];
	defaultModel?: OperatorProfileConfig["defaultModel"];
	whatsappHouseholdBindings?: OperatorProfileConfig["whatsappHouseholdBindings"];
	implicit: boolean;
};

export type ResolvedWhatsAppHouseholdBinding = {
	readonly bindingId: string;
	readonly addresseeGender: "f" | "m";
	readonly actorId: string;
	readonly subjectUserId: string;
	readonly memorySource: ReturnType<typeof householdMemorySource>;
	readonly writableNamespace: ReturnType<typeof householdMemorySource>;
	readonly domain: "household";
	readonly address: string;
	readonly replyAddress: string;
	readonly expectedConversationKey: string;
	readonly displayName: string;
	readonly providerConsent?: NonNullable<
		OperatorProfileConfig["whatsappHouseholdBindings"]
	>[number]["providerConsent"];
	readonly reminderConsent?: NonNullable<
		OperatorProfileConfig["whatsappHouseholdBindings"]
	>[number]["reminderConsent"];
	readonly remindersEnabled?: boolean;
	readonly mediaEnabled?: boolean;
	readonly emergencyEnabled?: boolean;
	readonly profile: EffectiveOperatorProfile;
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
			providerScopes: profile.providerScopes ? [...profile.providerScopes] : undefined,
			capabilityScopes: profile.capabilityScopes ? [...profile.capabilityScopes] : undefined,
			outboundChannels: profile.outboundChannels ? [...profile.outboundChannels] : undefined,
			whatsappHouseholdBindings: profile.whatsappHouseholdBindings?.map((binding) => ({
				...binding,
			})),
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
		providerScopes: configured.providerScopes ? [...configured.providerScopes] : undefined,
		capabilityScopes: configured.capabilityScopes ? [...configured.capabilityScopes] : undefined,
		outboundChannels: configured.outboundChannels ? [...configured.outboundChannels] : undefined,
		whatsappHouseholdBindings: configured.whatsappHouseholdBindings?.map((binding) => ({
			...binding,
		})),
		implicit: false,
	};
}

export function resolveWhatsAppHouseholdBinding(
	addressRef: string,
	cfg: TelclaudeConfig,
): ResolvedWhatsAppHouseholdBinding | null {
	const normalized = normalizeWhatsAppAddressRef(addressRef);
	if (!normalized) return null;
	for (const profile of listOperatorProfiles(cfg)) {
		if (profile.implicit) continue;
		const binding = profile.whatsappHouseholdBindings?.find(
			(candidate) => candidate.address === normalized,
		);
		if (!binding) continue;
		assertNarrowHouseholdProfile(profile);
		const replyAddress = normalizeWhatsAppAddressRef(binding.replyAddress);
		const expectedConversationKey = replyAddress
			? whatsAppDirectConversationKey(replyAddress)
			: null;
		if (
			!replyAddress ||
			replyAddress !== normalized ||
			!expectedConversationKey ||
			binding.subjectUserId !== `household:${binding.bindingId}`
		) {
			throw new Error(`invalid household WhatsApp binding: ${binding.bindingId}`);
		}
		const memorySource = householdMemorySource(binding.bindingId);
		return {
			bindingId: binding.bindingId,
			addresseeGender: binding.addresseeGender,
			actorId: `household:whatsapp:${binding.bindingId}`,
			subjectUserId: binding.subjectUserId,
			memorySource,
			writableNamespace: memorySource,
			domain: "household",
			address: normalized,
			replyAddress,
			expectedConversationKey,
			displayName: binding.displayName,
			...(binding.providerConsent ? { providerConsent: { ...binding.providerConsent } } : {}),
			...(binding.reminderConsent ? { reminderConsent: { ...binding.reminderConsent } } : {}),
			...(binding.remindersEnabled === undefined
				? {}
				: { remindersEnabled: binding.remindersEnabled }),
			...(binding.mediaEnabled === undefined ? {} : { mediaEnabled: binding.mediaEnabled }),
			...(binding.emergencyEnabled === undefined
				? {}
				: { emergencyEnabled: binding.emergencyEnabled }),
			profile,
		};
	}
	return null;
}

export type HouseholdEmergencyActivation =
	| { readonly enabled: false; readonly reason: "global_disabled" | "binding_disabled" }
	| { readonly enabled: true; readonly eligibleBindingIds: ReadonlySet<string> };

export function resolveHouseholdEmergencyActivation(
	config: Pick<TelclaudeConfig, "householdEmergency" | "profiles">,
): HouseholdEmergencyActivation {
	if (!config.householdEmergency?.enabled) return { enabled: false, reason: "global_disabled" };
	const eligibleBindingIds = new Set(
		(config.profiles ?? []).flatMap((profile) =>
			(profile.whatsappHouseholdBindings ?? [])
				.filter((binding) => binding.emergencyEnabled === true)
				.map((binding) => binding.bindingId),
		),
	);
	return eligibleBindingIds.size === 0
		? { enabled: false, reason: "binding_disabled" }
		: { enabled: true, eligibleBindingIds };
}

export type HouseholdMediaActivation =
	| {
			readonly enabled: false;
			readonly reason: "global_disabled" | "binding_disabled" | "key_unavailable";
	  }
	| {
			readonly enabled: true;
			readonly encryptionKey: string;
			readonly eligibleBindingIds: ReadonlySet<string>;
	  };

export function resolveHouseholdMediaActivation(
	config: Pick<TelclaudeConfig, "householdMedia" | "profiles">,
	encryptionKey: string | undefined,
): HouseholdMediaActivation {
	if (!config.householdMedia?.enabled) return { enabled: false, reason: "global_disabled" };
	const eligibleBindingIds = new Set(
		(config.profiles ?? []).flatMap((profile) =>
			(profile.whatsappHouseholdBindings ?? [])
				.filter((binding) => binding.mediaEnabled === true)
				.map((binding) => binding.bindingId),
		),
	);
	if (eligibleBindingIds.size === 0) return { enabled: false, reason: "binding_disabled" };
	if (!encryptionKey || Array.from(encryptionKey).length < 32) {
		return { enabled: false, reason: "key_unavailable" };
	}
	return { enabled: true, encryptionKey, eligibleBindingIds };
}

export function resolveWhatsAppHouseholdBindingById(
	bindingId: string,
	cfg: TelclaudeConfig,
): ResolvedWhatsAppHouseholdBinding | null {
	const normalized = bindingId.trim();
	if (!normalized) return null;
	for (const profile of listOperatorProfiles(cfg)) {
		if (profile.implicit) continue;
		const binding = profile.whatsappHouseholdBindings?.find(
			(candidate) => candidate.bindingId === normalized,
		);
		if (!binding) continue;
		return resolveWhatsAppHouseholdBinding(binding.address, cfg);
	}
	return null;
}

export function assertNarrowHouseholdProfile(profile: EffectiveOperatorProfile): void {
	if (
		!sameStringSet(profile.allowedSkills, []) ||
		!sameStringSet(profile.providerScopes, ["clalit"]) ||
		!sameStringSet(profile.capabilityScopes, ["schedule.read", "schedule.write"]) ||
		!sameStringSet(profile.outboundChannels, ["whatsapp"])
	) {
		throw new Error(`household profile is not narrowly scoped: ${profile.id}`);
	}
}

function sameStringSet(
	actual: readonly string[] | undefined,
	expected: readonly string[],
): boolean {
	return (
		actual !== undefined &&
		actual.length === expected.length &&
		new Set(actual).size === actual.length &&
		expected.every((value) => actual.includes(value))
	);
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
