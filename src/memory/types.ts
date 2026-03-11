export type TrustLevel = "trusted" | "quarantined" | "untrusted";
export type MemoryCategory = "profile" | "interests" | "threads" | "posts" | "meta";
export type MemorySource = "telegram" | "social" | (string & {});

export type MemoryProvenance = {
	source: MemorySource;
	trust: TrustLevel;
	createdAt: number;
	promotedAt?: number;
	promotedBy?: string;
	postedAt?: number;
	chatId?: string;
};

export type MemoryEntry = {
	id: string;
	category: MemoryCategory;
	content: string;
	metadata?: Record<string, unknown>;
	_provenance: MemoryProvenance;
};
