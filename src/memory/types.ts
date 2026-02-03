export type TrustLevel = "trusted" | "quarantined" | "untrusted";
export type MemoryCategory = "profile" | "interests" | "threads" | "posts" | "meta";
export type MemorySource = "telegram" | "moltbook";

export type MemoryProvenance = {
	source: MemorySource;
	trust: TrustLevel;
	createdAt: number;
	promotedAt?: number;
	promotedBy?: string;
	postedAt?: number;
};

export type MemoryEntry = {
	id: string;
	category: MemoryCategory;
	content: string;
	_provenance: MemoryProvenance;
};
