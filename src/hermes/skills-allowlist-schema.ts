import { z } from "zod";

// Evidence schema for the skills-allowlist parity probe. The probe exercises the
// wrapper's skill-invocation path in the contained runtime and records whether the
// allowlist is enforced fail-closed: an allowlisted skill loads, a non-allowlisted
// one is denied, and a SOCIAL service with enableSkills but no (or empty)
// allowedSkills denies ALL skills (architecture invariant #9). This file is the
// schema + required-check catalog; skills-allowlist-probe.ts holds the evaluator.

export const SKILLS_ALLOWLIST_SCHEMA_VERSION = "telclaude.hermes.skills-allowlist.v1";

export const SKILLS_ALLOWLIST_REQUIRED_PROPERTY_NAMES = [
	// An explicitly allowlisted skill is invocable.
	"positive_allowlisted_skill_allowed",
	// A skill NOT on the allowlist is denied at runtime (fail-closed), not silently run.
	"nonallowlisted_skill_denied",
	// SOCIAL + enableSkills:true + allowedSkills OMITTED -> every Skill call denied.
	"social_omitted_allowlist_denies_all",
	// SOCIAL + enableSkills:true + allowedSkills:[] -> every Skill call denied.
	"social_empty_allowlist_denies_all",
	// The evidence artifact bytes carry no unredacted secret-shaped material.
	"artifact_redacted",
] as const;

export type SkillsAllowlistPropertyName = (typeof SKILLS_ALLOWLIST_REQUIRED_PROPERTY_NAMES)[number];

const NonEmptyString = z.string().trim().min(1);
const SkillsAllowlistPropertyNameSchema = z.enum(SKILLS_ALLOWLIST_REQUIRED_PROPERTY_NAMES);

const SkillsAllowlistPropertiesSchema = z
	.object({
		positive_allowlisted_skill_allowed: z.boolean().optional(),
		nonallowlisted_skill_denied: z.boolean().optional(),
		social_omitted_allowlist_denies_all: z.boolean().optional(),
		social_empty_allowlist_denies_all: z.boolean().optional(),
		artifact_redacted: z.boolean().optional(),
	})
	.strict();

const SkillsAllowlistCheckSchema = z
	.object({
		name: SkillsAllowlistPropertyNameSchema,
		status: z.enum(["pass", "fail"]),
		detail: NonEmptyString,
		// Which enforcement layer observed the denial, when applicable
		// (PreToolUse hook is primary; canUseTool is the fallback).
		enforcementLayer: z.enum(["pretooluse_hook", "can_use_tool", "both"]).optional(),
	})
	.strict();

// Runtime-grounded origin: skill-allowlist enforcement is the SDK PreToolUse
// hook in the contained runtime, NOT a network endpoint, so origin is proven by
// the docker internal-network topology + container identity (mirroring the
// api-server-containment runtime probe), not a server-peer-echo header. (Network
// surfaces like served-MCP/memory keep server-peer-echo.)
const SkillsAllowlistOriginSchema = z
	.object({
		kind: z.enum(["contained-runtime", "unknown"]),
		containerName: NonEmptyString.optional(),
		topologyInternal: z.boolean().optional(),
		relayContainerPresent: z.boolean().optional(),
		authoritativeBoundary: z.literal("docker_internal_network").optional(),
		detail: NonEmptyString,
	})
	.strict();

export const SkillsAllowlistEvidenceSchema = z
	.object({
		schemaVersion: z.literal(SKILLS_ALLOWLIST_SCHEMA_VERSION),
		probeId: z.literal("skills.allowlist"),
		status: z.enum(["pass", "fail", "pending"]),
		ran: z.boolean(),
		generatedAt: NonEmptyString,
		summary: NonEmptyString,
		origin: SkillsAllowlistOriginSchema,
		properties: SkillsAllowlistPropertiesSchema,
		checks: z.array(SkillsAllowlistCheckSchema),
	})
	.strict();

export type SkillsAllowlistEvidence = z.infer<typeof SkillsAllowlistEvidenceSchema>;
export type SkillsAllowlistCheck = SkillsAllowlistEvidence["checks"][number];
