import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type {
	TelclaudeMcpAuthorityStamp,
	TelclaudeMcpBrowserActPrepareRequest,
	TelclaudeMcpBrowserActRequest,
} from "../../src/hermes/mcp/bridge.js";
import {
	createTelclaudeLiveMcpRelayClients,
	type TelclaudeLiveMcpAuditEntry,
} from "../../src/hermes/mcp/live-relay-clients.js";
import { createTelclaudeMcpSideEffectLedger } from "../../src/hermes/mcp/side-effect-ledger.js";
import type { BrowserActCommitSignal } from "../../src/relay/browser-act-evidence.js";
import type {
	BrowserActExecutorSurface,
	BrowserActSurfaceRequest,
} from "../../src/relay/browser-act-relay-surface.js";
import type { PreparedBrowserWrite } from "../../src/relay/browser-write-confirm.js";
import { resetDatabase } from "../../src/storage/db.js";

// A canonical fake binding hash (sha256 shape) the ledger accepts.
const FAKE_BINDING_HASH = `sha256:${"a".repeat(64)}`;
const COMMIT_SIGNAL: BrowserActCommitSignal = {
	forceConfirm: true,
	reasons: ["action.verb.click", "playwright.form_submit_observed"],
	observed: { navigation: false, formSubmit: true, mutatingRequest: false },
};

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;
const ORIGINAL_CONFIG = process.env.TELCLAUDE_CONFIG;

describe("Telclaude live MCP browser-act clients", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tc-live-mcp-act-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		process.env.TELCLAUDE_CONFIG = path.join(tempDir, "telclaude.json");
		resetDatabase();
	});

	afterEach(() => {
		resetDatabase();
		fs.rmSync(tempDir, { recursive: true, force: true });
		restoreEnv("TELCLAUDE_DATA_DIR", ORIGINAL_DATA_DIR);
		restoreEnv("TELCLAUDE_CONFIG", ORIGINAL_CONFIG);
	});

	it("runs a non-committing act inline and returns only the safe page view", async () => {
		const surface = recordingSurface();
		const auditEntries: TelclaudeLiveMcpAuditEntry[] = [];
		const clients = makeClients({ surface, auditEntries });

		const result = (await clients.browseAct(
			actRequest({ verb: "fill", target: "#qty", submittedValues: "2" }),
		)) as Record<string, unknown>;

		// Safe view only: no screenshot ref, no DOM digest, no raw target/values.
		expect(result).toEqual({
			committing: false,
			urlOrigin: "https://shop.example.com",
			pageRevision: "hmac-sha256:fake-revision",
			commitSignal: { forceConfirm: false, reasons: [] },
		});
		expect(JSON.stringify(result)).not.toContain("screenshot");
		expect(JSON.stringify(result)).not.toContain("#qty");

		// The surface was driven with the relay-stamped authority + a server-derived
		// sessionRef (the endpoint id) — the runtime named none of it.
		expect(surface.actCalls).toEqual([
			expect.objectContaining({
				actor: "operator",
				profileId: "ops",
				mcpDomain: "private",
				sessionRef: "endpoint-private",
				url: "https://shop.example.com/cart",
				verb: "fill",
				target: "#qty",
				submittedValues: "2",
			}),
		]);
		expect(auditEntries).toEqual([
			expect.objectContaining({
				actorId: "operator",
				kind: "web.browse_act",
				payload: expect.objectContaining({ verb: "fill", committing: false }),
			}),
		]);
	});

	it("fails closed when no browser-act surface is configured", async () => {
		const clients = makeClients({});
		await expect(clients.browseAct(actRequest())).rejects.toMatchObject({
			code: "mcp_tool_not_configured",
		});
		await expect(clients.browseActPrepare(prepareRequest())).rejects.toMatchObject({
			code: "mcp_tool_not_configured",
		});
	});

	it("refuses a secret-shaped act URL before reaching the surface", async () => {
		const surface = recordingSurface();
		const clients = makeClients({ surface });
		// Canonical AWS docs example key — never a live credential. gitleaks:allow
		const fakeKey = ["AKIA", "IOSFODNN7EXAMPLE"].join("");
		await expect(
			clients.browseAct(actRequest({ url: `https://shop.example.com/?token=${fakeKey}` })),
		).rejects.toMatchObject({ code: "mcp_outbound_secret_blocked" });
		expect(surface.actCalls).toEqual([]);
	});

	it("preflights the goto DESTINATION (submittedValues), not just the entry url", async () => {
		const surface = recordingSurface();
		const clients = makeClients({ surface });
		// Canonical AWS docs example key — never a live credential. gitleaks:allow
		const fakeKey = ["AKIA", "IOSFODNN7EXAMPLE"].join("");
		// A clean entry url but a secret-shaped goto destination must fail closed
		// BEFORE the surface is reached.
		await expect(
			clients.browseAct(
				actRequest({
					verb: "goto",
					submittedValues: `https://shop.example.com/go?token=${fakeKey}`,
				}),
			),
		).rejects.toMatchObject({ code: "mcp_outbound_secret_blocked" });
		// A non-http(s) goto destination is rejected (typed) before any browser work.
		await expect(
			clients.browseAct(actRequest({ verb: "goto", submittedValues: "file:///etc/passwd" })),
		).rejects.toMatchObject({ code: "browser_act_goto_destination_invalid" });
		// A non-string goto destination is rejected too.
		await expect(
			clients.browseAct(actRequest({ verb: "goto", submittedValues: { not: "a-string" } })),
		).rejects.toMatchObject({ code: "browser_act_goto_destination_invalid" });
		expect(surface.actCalls).toEqual([]);

		// The same preflight runs on the prepare path.
		await expect(
			clients.browseActPrepare(
				prepareRequest({
					verb: "goto",
					target: undefined,
					submittedValues: "file:///etc/passwd",
				}),
			),
		).rejects.toMatchObject({ code: "browser_act_goto_destination_invalid" });
		expect(surface.prepareCalls).toEqual([]);
	});

	it("prepares a committing act into the ledger and returns only actionRef + safe display", async () => {
		const ledger = testLedger();
		const surface = recordingSurface();
		const requestedApprovals: string[] = [];
		const auditEntries: TelclaudeLiveMcpAuditEntry[] = [];
		const clients = makeClients({
			ledger,
			surface,
			auditEntries,
			browserWriteApproverActorId: "operator:browser-approver",
			requestSideEffectApproval: (record) => {
				requestedApprovals.push(record.ref);
			},
		});

		const prepared = (await clients.browseActPrepare(
			prepareRequest({ verb: "click", target: "#pay", submittedValues: { confirm: true } }),
		)) as { actionRef: string; approvalRequestId: string; display: unknown };

		// The returned envelope carries ONLY the opaque actionRef + a redacted display
		// summary — never the raw target, the submitted values, or any approval token.
		expect(prepared.actionRef).toMatch(/^effect-/);
		expect(prepared.display).toEqual({
			verb: "click",
			target: "#pay-origin",
			urlOrigin: "https://shop.example.com",
		});
		expect(JSON.stringify(prepared)).not.toContain("confirm");
		expect(prepared).not.toHaveProperty("bindingHash");
		expect(prepared).not.toHaveProperty("approvalToken");
		expect(prepared).not.toHaveProperty("evidenceNonce");

		// The executor's prepareIntent was keyed by the SAME ref the ledger filed under.
		expect(surface.prepareCalls).toEqual([
			expect.objectContaining({ actionRef: prepared.actionRef, verb: "click", target: "#pay" }),
		]);

		// A real browser-write record is staged in the ledger (prepared, distinct approver).
		const record = ledger.get(prepared.actionRef);
		expect(record).toMatchObject({
			kind: "browser-write",
			status: "prepared",
			ref: prepared.actionRef,
			actorId: "operator",
			approverActorId: "operator:browser-approver",
			profileId: "ops",
			domain: "private",
			sessionRef: "endpoint-private",
			host: "shop.example.com",
			actionVerb: "click",
			actionTarget: "#pay",
			bindingHash: FAKE_BINDING_HASH,
		});
		// The approved submitted values never enter the ledger record (hashes only).
		expect(JSON.stringify(record)).not.toContain("confirm");
		expect(requestedApprovals).toEqual([prepared.actionRef]);
		expect(auditEntries).toEqual([expect.objectContaining({ kind: "web.browse_act_prepare" })]);
	});

	it("denies prepare when the browser-write approver is missing or equals the actor", async () => {
		const surface = recordingSurface();
		const missing = makeClients({ surface });
		await expect(missing.browseActPrepare(prepareRequest())).rejects.toThrow(
			"browserWriteApproverActorId is not configured",
		);

		const selfApprover = makeClients({
			surface,
			browserWriteApproverActorId: "operator",
		});
		await expect(selfApprover.browseActPrepare(prepareRequest())).rejects.toThrow(
			"must differ from actorId",
		);
		// A denied prepare never asks the executor to stage / hold a live page.
		expect(surface.prepareCalls).toEqual([]);
	});
});

function makeClients(options: {
	ledger?: ReturnType<typeof testLedger>;
	surface?: BrowserActExecutorSurface;
	auditEntries?: TelclaudeLiveMcpAuditEntry[];
	browserWriteApproverActorId?: string;
	requestSideEffectApproval?: (record: { ref: string }) => void;
}) {
	return createTelclaudeLiveMcpRelayClients({
		ledger: options.ledger ?? testLedger(),
		makeApprovalRequestId: makeApprovalIds(),
		...(options.surface ? { browserAct: options.surface } : {}),
		...(options.auditEntries
			? {
					auditNote: (entry: TelclaudeLiveMcpAuditEntry) => {
						options.auditEntries?.push(entry);
					},
				}
			: {}),
		...(options.browserWriteApproverActorId
			? { browserWriteApproverActorId: options.browserWriteApproverActorId }
			: {}),
		...(options.requestSideEffectApproval
			? { requestSideEffectApproval: options.requestSideEffectApproval }
			: {}),
	});
}

function testLedger() {
	return createTelclaudeMcpSideEffectLedger({
		verifyApproval: async () => ({
			ok: false,
			code: "approval_required",
			reason: "test verifier not used here",
		}),
	});
}

function makeApprovalIds(): () => string {
	let n = 0;
	return () => `approval-${++n}`;
}

/** A fake act surface that records calls and returns deterministic evidence/binding. */
function recordingSurface(): BrowserActExecutorSurface & {
	readonly actCalls: BrowserActSurfaceRequest[];
	readonly prepareCalls: (BrowserActSurfaceRequest & { readonly actionRef: string })[];
} {
	const actCalls: BrowserActSurfaceRequest[] = [];
	const prepareCalls: (BrowserActSurfaceRequest & { readonly actionRef: string })[] = [];
	return {
		actCalls,
		prepareCalls,
		async act(request) {
			actCalls.push(request);
			return {
				committing: false,
				evidence: fakeEvidence(),
			};
		},
		async prepareIntent(request) {
			prepareCalls.push(request);
			return {
				committing: true,
				record: "browser-write",
				prepared: preparedBrowserWrite(request),
			};
		},
	};
}

function fakeEvidence() {
	return {
		schemaVersion: "telclaude.browser.act-evidence.v1" as const,
		evidenceNonce: "nonce-1",
		urlHash: "hmac-sha256:url",
		urlOrigin: "https://shop.example.com",
		domDigest: "sha256:dom",
		screenshotHash: "sha256:shot",
		screenshotRef: "/relay/media/secret-screenshot.png",
		revision: "hmac-sha256:fake-revision",
		submittedValuesHash: "hmac-sha256:values",
		commitSignal: {
			forceConfirm: false,
			reasons: [],
			observed: { navigation: false, formSubmit: false, mutatingRequest: false },
		},
	};
}

function preparedBrowserWrite(
	request: BrowserActSurfaceRequest & { readonly actionRef: string },
): PreparedBrowserWrite {
	return {
		writeRef: "bwrite-internal-1",
		actor: request.actor,
		approver: "operator:browser-approver",
		profile: request.profileId,
		authorityDomain: "private",
		host: "shop.example.com",
		originScope: ["shop.example.com"],
		evidenceRevision: "hmac-sha256:fake-revision",
		evidenceNonce: "nonce-1",
		bindingHash: FAKE_BINDING_HASH,
		// The display target is the REDACTED summary (origin only), never the raw "#pay".
		display: { verb: "click", target: "#pay-origin", urlOrigin: "https://shop.example.com" },
		commitSignal: COMMIT_SIGNAL,
		createdAtMs: 1_000_000,
		expiresAtMs: 1_300_000,
	};
}

function stamp(): TelclaudeMcpAuthorityStamp {
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

function actRequest(
	overrides: Partial<TelclaudeMcpBrowserActRequest> = {},
): TelclaudeMcpBrowserActRequest {
	return {
		...stamp(),
		url: "https://shop.example.com/cart",
		verb: "fill",
		...overrides,
	};
}

function prepareRequest(
	overrides: Partial<TelclaudeMcpBrowserActPrepareRequest> = {},
): TelclaudeMcpBrowserActPrepareRequest {
	return {
		...stamp(),
		url: "https://shop.example.com/cart",
		verb: "click",
		target: "#pay",
		...overrides,
	};
}

function restoreEnv(key: string, value: string | undefined): void {
	if (value === undefined) {
		delete process.env[key];
	} else {
		process.env[key] = value;
	}
}
