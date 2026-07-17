import type { MemorySource } from "./types.js";

export const DEFAULT_TELEGRAM_PROFILE_ID = "default";
export const TELEGRAM_MEMORY_SOURCE_PREFIX = "telegram:";
export const HOUSEHOLD_MEMORY_SOURCE_PREFIX = "household:";

const PROFILE_ID_PATTERN = /^[a-z0-9-]{1,32}$/;
const HOUSEHOLD_BINDING_ID_PATTERN = /^(?=.{1,64}$)(?=.*[a-z])[a-z0-9]+(?:-[a-z0-9]+)*$/;

export type MemorySourceFamily = "telegram" | "household" | "social";

export function isValidMemoryProfileId(profileId: string): boolean {
	return profileId === DEFAULT_TELEGRAM_PROFILE_ID || PROFILE_ID_PATTERN.test(profileId);
}

export function telegramMemorySource(profileId = DEFAULT_TELEGRAM_PROFILE_ID): MemorySource {
	if (!isValidMemoryProfileId(profileId)) {
		throw new Error(`invalid telegram memory profile id: ${profileId}`);
	}
	return `${TELEGRAM_MEMORY_SOURCE_PREFIX}${profileId}` as MemorySource;
}

export function isTelegramMemorySource(source: MemorySource | string): boolean {
	return (
		source === "telegram" ||
		(source.startsWith(TELEGRAM_MEMORY_SOURCE_PREFIX) &&
			isValidMemoryProfileId(source.slice(TELEGRAM_MEMORY_SOURCE_PREFIX.length)))
	);
}

export function isSocialMemorySource(source: MemorySource | string): boolean {
	return source === "social";
}

export function isValidHouseholdBindingId(bindingId: string): boolean {
	return HOUSEHOLD_BINDING_ID_PATTERN.test(bindingId);
}

export function householdMemorySource(bindingId: string): MemorySource {
	if (!isValidHouseholdBindingId(bindingId)) {
		throw new Error(`invalid opaque household binding id: ${bindingId}`);
	}
	return `${HOUSEHOLD_MEMORY_SOURCE_PREFIX}${bindingId}` as MemorySource;
}

export function isHouseholdMemorySource(source: MemorySource | string): boolean {
	return (
		source.startsWith(HOUSEHOLD_MEMORY_SOURCE_PREFIX) &&
		isValidHouseholdBindingId(source.slice(HOUSEHOLD_MEMORY_SOURCE_PREFIX.length))
	);
}

export function validateMemorySource(source: MemorySource | string): string | null {
	if (isSocialMemorySource(source)) return null;
	if (isHouseholdMemorySource(source)) return null;
	if (source.startsWith(HOUSEHOLD_MEMORY_SOURCE_PREFIX)) {
		return "Invalid opaque household binding memory source.";
	}
	if (source === "telegram") {
		return "Bare telegram memory source is legacy-only; use telegram:<profile-id>.";
	}
	if (!source.startsWith(TELEGRAM_MEMORY_SOURCE_PREFIX)) {
		return "Invalid memory source format.";
	}
	const profileId = source.slice(TELEGRAM_MEMORY_SOURCE_PREFIX.length);
	if (!isValidMemoryProfileId(profileId)) {
		return "Invalid telegram memory profile id.";
	}
	return null;
}

export function memorySourceFamily(source: MemorySource | string): MemorySourceFamily | null {
	if (isTelegramMemorySource(source)) return "telegram";
	if (isHouseholdMemorySource(source)) return "household";
	if (isSocialMemorySource(source)) return "social";
	return null;
}
