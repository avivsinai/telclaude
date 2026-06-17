import { z } from "zod";
import { SkillsAllowlistAttestationSchema } from "./skills-allowlist-attestation.js";

// Evidence schema for the skills-allowlist parity probe. The probe exercises the
// contained Hermes profile, not a host-side SDK simulation: the runtime allowlist
// manifest must be present, an allowlisted skill must be installed in the
// read-only curated external directory, a known non-allowlisted skill must be
// absent, and the curated runtime skill tree must match the manifest exactly.
// This file is the schema + required-check catalog;
// skills-allowlist-probe.ts holds the evaluator.

export const SKILLS_ALLOWLIST_SCHEMA_VERSION = "telclaude.hermes.skills-allowlist.v1";

export const SKILLS_ALLOWLIST_REQUIRED_PROPERTY_NAMES = [
	// The runtime profile carries the copied allowlist manifest.
	"allowlist_manifest_present",
	// An explicitly allowlisted skill is present in the curated external skill dir.
	"allowlisted_skill_present",
	// A known non-allowlisted skill is absent from the runtime profile.
	"nonallowlisted_skill_absent",
	// The curated runtime skills with SKILL.md match the manifest exactly.
	"runtime_skills_match_allowlist",
	// Upstream Hermes self-improvement skill creation is disabled at the source.
	"skill_creation_nudge_disabled",
	// The production runtime tool policy registers the PreToolUse skill gate.
	"pretooluse_hook_registered",
	// Positive/negative controls prove hook behavior, not only profile files.
	"allowlisted_skill_invocation_allowed",
	"nonallowlisted_skill_invocation_denied",
	"social_missing_allowlist_denied",
	"social_empty_allowlist_denied",
	// The evidence artifact bytes carry no unredacted secret-shaped material.
	"artifact_redacted",
] as const;

export type SkillsAllowlistPropertyName = (typeof SKILLS_ALLOWLIST_REQUIRED_PROPERTY_NAMES)[number];

// Relay-owned catalog section. When the relay serves an external skill catalog
// into the contained runtime (skills.external_dirs), the probe must also prove —
// from inside the container, via docker exec — that the mounted catalog matches
// the relay manifest and carries no scripts/symlinks/executables. The section is
// optional in the schema only because catalog-free deployments have nothing to
// prove: the evaluator independently resolves the relay catalog state and fails
// closed (`skills.catalog.required`) when a served catalog has no matching,
// manifest-digest-bound evidence.
export const SKILLS_CATALOG_REQUIRED_CHECK_NAMES = [
	// Container-visible catalog entries match the relay manifest (names + content hashes).
	"catalog_manifest_match",
	// No catalog entry contains a scripts/ directory.
	"catalog_no_scripts",
	// No catalog entry contains a symlink.
	"catalog_no_symlinks",
	// No catalog entry contains an executable-bit file.
	"catalog_no_executables",
] as const;

export type SkillsCatalogCheckName = (typeof SKILLS_CATALOG_REQUIRED_CHECK_NAMES)[number];

const NonEmptyString = z.string().trim().min(1);
const SkillsAllowlistPropertyNameSchema = z.enum(SKILLS_ALLOWLIST_REQUIRED_PROPERTY_NAMES);

const SkillsAllowlistPropertiesSchema = z
	.object({
		allowlist_manifest_present: z.boolean().optional(),
		allowlisted_skill_present: z.boolean().optional(),
		nonallowlisted_skill_absent: z.boolean().optional(),
		runtime_skills_match_allowlist: z.boolean().optional(),
		skill_creation_nudge_disabled: z.boolean().optional(),
		pretooluse_hook_registered: z.boolean().optional(),
		allowlisted_skill_invocation_allowed: z.boolean().optional(),
		nonallowlisted_skill_invocation_denied: z.boolean().optional(),
		social_missing_allowlist_denied: z.boolean().optional(),
		social_empty_allowlist_denied: z.boolean().optional(),
		artifact_redacted: z.boolean().optional(),
	})
	.strict();

const SkillsAllowlistCheckSchema = z
	.object({
		name: SkillsAllowlistPropertyNameSchema,
		status: z.enum(["pass", "fail"]),
		detail: NonEmptyString,
		// Every runtime/profile check must be observed through docker exec inside the
		// contained Hermes runtime. The redaction check is evaluator-owned and may omit it.
		observationLayer: z.literal("docker_exec").optional(),
		// Enforcement checks must prove the primary PreToolUse gate, not a fallback.
		enforcementLayer: z.literal("pretooluse").optional(),
	})
	.strict();

// Runtime-grounded origin: skill-allowlist evidence is produced from the
// contained Hermes runtime and origin is proven by docker internal-network
// topology + container identity (mirroring the api-server-containment runtime
// probe), not a server-peer-echo header. (Network surfaces like
// served-MCP/memory keep server-peer-echo.)
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

const SkillsCatalogCheckSchema = z
	.object({
		name: z.enum(SKILLS_CATALOG_REQUIRED_CHECK_NAMES),
		status: z.enum(["pass", "fail"]),
		detail: NonEmptyString,
		// Catalog checks observe the container-visible mount, so docker exec is mandatory.
		observationLayer: z.literal("docker_exec"),
	})
	.strict();

export const SkillsCatalogSectionSchema = z
	.object({
		mountPath: NonEmptyString,
		manifestSkillCount: z.number().int().nonnegative(),
		// Canonical digest of the relay manifest the probe compared against
		// (catalogManifestDigestSha256). The evaluator recomputes this from the live
		// relay catalog, so evidence probed against a stale or substituted manifest
		// fails the skills.catalog.required gate.
		manifestSha256: z.string().regex(/^[a-f0-9]{64}$/),
		checks: z.array(SkillsCatalogCheckSchema),
	})
	.strict();

export type SkillsCatalogSection = z.infer<typeof SkillsCatalogSectionSchema>;

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
		// Relay-owned catalog proof; absent only when no catalog is configured.
		// The evaluator resolves the relay catalog state itself and fails closed
		// when a served catalog has no catalog section here.
		catalog: SkillsCatalogSectionSchema.optional(),
		// Relay-owned social catalog proof. The social runtime is a separate trust
		// domain and mount, so its catalog is attested separately from the private
		// contained catalog.
		socialCatalog: SkillsCatalogSectionSchema.optional(),
		// Signed runner attestation binding this evidence body to the operator relay
		// key. Optional in the schema (pending/non-live evidence has none); the
		// evaluator REQUIRES a valid one before productionEnable under a live cutover.
		runnerAttestation: SkillsAllowlistAttestationSchema.optional(),
	})
	.strict();

export type SkillsAllowlistEvidence = z.infer<typeof SkillsAllowlistEvidenceSchema>;
export type SkillsAllowlistCheck = SkillsAllowlistEvidence["checks"][number];
