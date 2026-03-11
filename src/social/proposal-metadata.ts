export type SocialQuoteProposalMetadata = {
	action: "quote";
	targetPostId: string;
	targetAuthor?: string;
	targetExcerpt?: string;
};

export function parseSocialQuoteProposalMetadata(
	metadata: unknown,
): SocialQuoteProposalMetadata | null {
	if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) {
		return null;
	}

	const candidate = metadata as Record<string, unknown>;
	if (candidate.action !== "quote" || typeof candidate.targetPostId !== "string") {
		return null;
	}

	const targetPostId = candidate.targetPostId.trim();
	if (!targetPostId) {
		return null;
	}

	return {
		action: "quote",
		targetPostId,
		targetAuthor:
			typeof candidate.targetAuthor === "string" && candidate.targetAuthor.trim()
				? candidate.targetAuthor.trim()
				: undefined,
		targetExcerpt:
			typeof candidate.targetExcerpt === "string" && candidate.targetExcerpt.trim()
				? candidate.targetExcerpt.trim()
				: undefined,
	};
}
