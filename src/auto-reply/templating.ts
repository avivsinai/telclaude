import type { MsgContext } from "../types/message.js";

// Re-export for convenience
export type { MsgContext } from "../types/message.js";

export type TemplateContext = MsgContext & {
	BodyStripped?: string;
	SessionId?: string;
	IsNewSession?: string;
};

// Simple {{Placeholder}} interpolation using inbound message context.
export function applyTemplate(str: string, ctx: TemplateContext) {
	return str.replace(/{{\s*(\w+)\s*}}/g, (_, key) => {
		const value = (ctx as Record<string, unknown>)[key];
		return value == null ? "" : String(value);
	});
}
