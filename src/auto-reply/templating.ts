export type MsgContext = {
	Body?: string;
	From?: string;
	To?: string;
	MessageId?: string;
	MediaPath?: string;
	MediaUrl?: string;
	MediaType?: string;
	Transcript?: string;
	Username?: string;
};

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
