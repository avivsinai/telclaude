/**
 * Shared masking utility for CLI display.
 *
 * Consolidates duplicate mask/maskApiKey/maskToken functions from
 * setup-openai, setup-git, setup-google, setup-github-app, and oauth commands.
 */

export type MaskOptions = {
	/** Min length before masking applies (default: 8) */
	threshold?: number;
	/** Number of visible prefix chars (default: 4) */
	prefix?: number;
	/** Number of visible suffix chars (default: 4) */
	suffix?: number;
};

/**
 * Mask a sensitive value for display, showing only a prefix and suffix.
 *
 * Examples (with defaults):
 *   mask("sk-proj-abc123xyz789") => "sk-p...z789"
 *   mask("short") => "****"
 */
export function mask(value: string, opts?: MaskOptions): string {
	const threshold = opts?.threshold ?? 8;
	const prefix = opts?.prefix ?? 4;
	const suffix = opts?.suffix ?? 4;

	if (value.length <= threshold) {
		return `****${"*".repeat(Math.max(0, threshold - 4))}`;
	}

	return `${value.slice(0, prefix)}...${value.slice(-suffix)}`;
}
