import { loadConfig, type TelclaudeConfig } from "../config/config.js";

export type SocialServiceConfig = NonNullable<TelclaudeConfig["socialServices"]>[number];

export function getEnabledSocialServices(
	cfg: TelclaudeConfig = loadConfig(),
): SocialServiceConfig[] {
	return cfg.socialServices?.filter((service) => service.enabled) ?? [];
}

export function isAutomaticHeartbeatEnabled(service: SocialServiceConfig): boolean {
	return service.heartbeatEnabled ?? true;
}

export function getAutomaticHeartbeatSocialServices(
	cfg: TelclaudeConfig = loadConfig(),
): SocialServiceConfig[] {
	return getEnabledSocialServices(cfg).filter(isAutomaticHeartbeatEnabled);
}
