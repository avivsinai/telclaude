import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { listCuratorItems } from "../../src/curator/store.js";
import type {
	TelclaudeMcpAuthorityStamp,
	TelclaudeMcpSkillRequestRequest,
} from "../../src/hermes/mcp/bridge.js";
import {
	createTelclaudeLiveMcpRelayClients,
	type TelclaudeLiveMcpAuditEntry,
} from "../../src/hermes/mcp/live-relay-clients.js";
import { createTelclaudeMcpSideEffectLedger } from "../../src/hermes/mcp/side-effect-ledger.js";
import { resetDatabase } from "../../src/storage/db.js";

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

type SkillRequestResult = {
	curatorItemId: string;
	shortId: string;
	status: string;
	note: string;
};

describe("Telclaude live MCP skill-request capability client", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tc-live-mcp-skill-request-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		resetDatabase();
	});

	afterEach(() => {
		vi.useRealTimers();
		resetDatabase();
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) {
			delete process.env.TELCLAUDE_DATA_DIR;
		} else {
			process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
		}
	});

	it("files an operator-review Curator item and never installs anything", async () => {
		const auditEntries: TelclaudeLiveMcpAuditEntry[] = [];
		const clients = makeClients({ auditEntries });

		const result = (await clients.skillRequest(
			skillRequest({ sourceHint: "upstream hermes skills/weather" }),
		)) as SkillRequestResult;

		expect(result.status).toBe("filed");
		expect(result.curatorItemId).toMatch(/^curator-/);
		expect(result.shortId).toMatch(/^[0-9a-f]{8}$/);
		// The tool result must tell the model the operator decides via /curator.
		expect(result.note).toContain("/curator");
		expect(result.note).toContain("nothing is installed");

		const items = listCuratorItems({ status: "open", kind: "skill_review" });
		expect(items).toHaveLength(1);
		const item = items[0];
		expect(item.id).toBe(result.curatorItemId);
		expect(item.shortId).toBe(result.shortId);
		expect(item).toMatchObject({
			kind: "skill_review",
			status: "open",
			severity: "info",
			source: "hermes-live-mcp",
			entityRef: "skill-catalog:weather",
			producerKind: "system",
			producerId: "operator",
		});
		expect(item.rationale).toContain("operator keeps asking for forecasts");
		expect(item.proposedAction).toEqual({
			catalogInstall: {
				skillName: "weather",
				sourceHint: "upstream hermes skills/weather",
				requestedBy: "operator",
			},
		});
		// The model cannot name an install source: install-from-curator requires
		// sourceDir/upstreamRel, which the operator adds after review.
		expect(item.proposedAction.catalogInstall).not.toHaveProperty("sourceDir");
		expect(item.proposedAction.catalogInstall).not.toHaveProperty("upstreamRel");
		expect(item.evidence).toMatchObject({
			rationale: expect.stringContaining("operator keeps asking for forecasts"),
			domain: "private",
			profileId: "ops",
		});

		expect(auditEntries).toEqual([
			expect.objectContaining({
				actorId: "operator",
				domain: "private",
				kind: "skill.request",
				payload: expect.objectContaining({
					curatorItemId: result.curatorItemId,
					shortId: result.shortId,
					skillName: "weather",
				}),
			}),
		]);
	});

	it("dedupes repeated requests for the same skill into one open item", async () => {
		const clients = makeClients();

		const first = (await clients.skillRequest(skillRequest())) as SkillRequestResult;
		const second = (await clients.skillRequest(
			skillRequest({ rationale: "still no forecasts; asked again today" }),
		)) as SkillRequestResult;

		expect(second.curatorItemId).toBe(first.curatorItemId);
		const items = listCuratorItems({ status: "all", kind: "skill_review" });
		expect(items).toHaveLength(1);
		expect(items[0].rationale).toContain("asked again today");

		// A different skill files a separate item.
		const other = (await clients.skillRequest(
			skillRequest({ skillName: "gifgrep" }),
		)) as SkillRequestResult;
		expect(other.curatorItemId).not.toBe(first.curatorItemId);
		expect(listCuratorItems({ status: "all", kind: "skill_review" })).toHaveLength(2);
	});

	it("enforces the 5/hour skill-request rate limit per actor", async () => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date("2026-07-19T00:30:00.000Z"));
		const clients = makeClients();

		for (let index = 0; index < 5; index += 1) {
			await expect(
				clients.skillRequest(skillRequest({ skillName: `skill-${index}` })),
			).resolves.toBeTruthy();
		}
		await expect(clients.skillRequest(skillRequest({ skillName: "skill-over" }))).rejects.toThrow(
			/Hourly limit reached \(5\/hour\)/,
		);
		expect(listCuratorItems({ status: "all", kind: "skill_review" })).toHaveLength(5);

		// A different actor has its own bucket.
		await expect(
			clients.skillRequest(skillRequest({ skillName: "skill-over", actorId: "other-operator" })),
		).resolves.toBeTruthy();
	});
});

function makeClients(options: { auditEntries?: TelclaudeLiveMcpAuditEntry[] } = {}) {
	return createTelclaudeLiveMcpRelayClients({
		ledger: createTelclaudeMcpSideEffectLedger({
			verifyApproval: async () => ({
				ok: false,
				code: "approval_required",
				reason: "test verifier not used by skill requests",
			}),
		}),
		...(options.auditEntries
			? {
					auditNote: (entry: TelclaudeLiveMcpAuditEntry) => {
						options.auditEntries?.push(entry);
					},
				}
			: {}),
	});
}

function privateStamp(): TelclaudeMcpAuthorityStamp {
	return {
		actorId: "operator",
		profileId: "ops",
		domain: "private",
		memorySource: "telegram:ops",
		writableNamespace: "private:ops",
		endpointId: "endpoint-private",
		networkNamespace: "netns-private",
	};
}

function skillRequest(
	overrides: Partial<TelclaudeMcpSkillRequestRequest> = {},
): TelclaudeMcpSkillRequestRequest {
	return {
		...privateStamp(),
		skillName: "weather",
		rationale: "operator keeps asking for forecasts and the runtime has no weather skill",
		...overrides,
	};
}
