import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type {
	TelclaudeMcpAttachmentGetRequest,
	TelclaudeMcpAuthorityStamp,
	TelclaudeMcpMemorySearchRequest,
	TelclaudeMcpMemoryWriteRequest,
	TelclaudeMcpOutboundPrepareRequest,
	TelclaudeMcpProviderPrepareWriteRequest,
	TelclaudeMcpProviderReadRequest,
} from "../../src/hermes/mcp/bridge.js";
import { createTelclaudeLiveMcpRelayClients } from "../../src/hermes/mcp/live-relay-clients.js";
import { startTelclaudeLiveMcpRuntime } from "../../src/hermes/mcp/live-runtime.js";
import { createTelclaudeMcpSideEffectLedger } from "../../src/hermes/mcp/side-effect-ledger.js";
import type { AttachmentRef } from "../../src/storage/attachment-refs.js";
import { resetDatabase } from "../../src/storage/db.js";

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

describe("Telclaude live MCP relay-client adapters", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tc-live-mcp-clients-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		resetDatabase();
	});

	afterEach(() => {
		resetDatabase();
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) {
			delete process.env.TELCLAUDE_DATA_DIR;
		} else {
			process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
		}
	});

	it("reads and writes memory only through the authority-derived source", async () => {
		const clients = createTelclaudeLiveMcpRelayClients({ ledger: testLedger() });

		await clients.memoryWrite(memoryWrite({ id: "private-1", content: "operator likes tea" }));
		await clients.memoryWrite(
			memoryWrite({
				...socialStamp(),
				id: "social-1",
				category: "posts",
				content: "public draft about launch",
				trust: "untrusted",
			}),
		);

		await expect(
			clients.memorySearch(memorySearch({ filters: { sources: ["social"] } })),
		).rejects.toThrow("memory filters denied: sources");
		await expect(
			clients.memorySearch(memorySearch({ filters: { categories: ["profile;DROP"] } })),
		).rejects.toThrow("invalid memory category filter");
		await expect(clients.memorySearch(memorySearch({ memorySource: "social" }))).rejects.toThrow(
			"live MCP private authority must use telegram profile memory source",
		);

		const privateResult = await clients.memorySearch(memorySearch({ query: "operator" }));
		expect(privateResult).toMatchObject({
			entries: [
				expect.objectContaining({
					id: "private-1",
					_provenance: expect.objectContaining({ source: "telegram:ops" }),
				}),
			],
		});

		const socialResult = await clients.memorySearch(
			memorySearch({
				...socialStamp(),
				query: "public",
				filters: { categories: ["posts"], trust: ["untrusted"] },
			}),
		);
		expect(socialResult).toMatchObject({
			entries: [
				expect.objectContaining({
					id: "social-1",
					_provenance: expect.objectContaining({ source: "social" }),
				}),
			],
		});
	});

	it("routes provider reads through the relay proxy and returns sanitized data only", async () => {
		const calls: unknown[] = [];
		const clients = createTelclaudeLiveMcpRelayClients({
			ledger: testLedger(),
			providerProxy: async (request) => {
				calls.push(request);
				return { status: "ok", data: { messages: [{ id: "m1" }] } };
			},
		});

		await expect(
			clients.providerRead(
				providerRead({
					providerId: "google",
					service: "google",
					action: "gmail.search",
					params: { q: "from:clinic" },
				}),
			),
		).resolves.toEqual({ messages: [{ id: "m1" }] });
		expect(calls).toEqual([
			{
				providerId: "google",
				path: "/v1/fetch",
				method: "POST",
				body: JSON.stringify({
					service: "gmail",
					action: "search",
					params: { q: "from:clinic" },
				}),
				userId: "operator",
			},
		]);

		const failing = createTelclaudeLiveMcpRelayClients({
			ledger: testLedger(),
			providerProxy: async () => ({
				status: "error",
				error: "upstream token sk-ant-thisshouldberedacted1234567890",
			}),
		});
		await expect(failing.providerRead(providerRead())).rejects.toThrow("provider read failed");
		await expect(failing.providerRead(providerRead())).rejects.not.toThrow("sk-ant-");
	});

	it("prepares provider and outbound side effects in the shared ledger without executing them", async () => {
		const ledger = testLedger();
		let providerProxyCalled = false;
		const clients = createTelclaudeLiveMcpRelayClients({
			ledger,
			makeApprovalRequestId: makeApprovalIds(),
			providerProxy: async () => {
				providerProxyCalled = true;
				return { status: "ok", data: {} };
			},
			providerWriteApproverActorId: "operator:provider-approver",
		});

		const providerPrepared = (await clients.providerPrepareWrite(
			providerPrepare({
				service: "bank",
				action: "transfer.execute",
				params: { amount: 100, currency: "ILS" },
				idempotencyKey: "idem-provider",
			}),
		)) as { actionRef: string; approvalRequestId: string };
		expect(providerProxyCalled).toBe(false);
		expect(providerPrepared.approvalRequestId).toBe("approval-1");
		expect(ledger.get(providerPrepared.actionRef)).toMatchObject({
			kind: "provider",
			status: "prepared",
			actorId: "operator",
			approverActorId: "operator:provider-approver",
			providerId: "bank",
			service: "bank",
			action: "transfer.execute",
			params: { amount: 100, currency: "ILS" },
			idempotencyKey: "idem-provider",
		});

		const outboundPrepared = (await clients.outboundPrepare(
			outboundPrepare({
				channel: "whatsapp",
				recipient: "+15551234567",
				content: "I'll pick up dinner at 19:00.",
				mediaRefs: ["att_menu"],
			}),
		)) as { outboundRef: string; approvalRequestId: string };
		expect(outboundPrepared.approvalRequestId).toBe("approval-2");
		expect(ledger.get(outboundPrepared.outboundRef)).toMatchObject({
			kind: "outbound",
			status: "prepared",
			actorId: "operator",
			channel: "whatsapp",
			destination: "+15551234567",
			renderedBody: "I'll pick up dinner at 19:00.",
			mediaRefs: ["att_menu"],
			conversationRef: "whatsapp:+15551234567",
		});
	});

	it("fails provider write preparation closed without a distinct relay-side approver", async () => {
		const missingApproverLedger = testLedger();
		const missingApproverClients = createTelclaudeLiveMcpRelayClients({
			ledger: missingApproverLedger,
		});
		await expect(missingApproverClients.providerPrepareWrite(providerPrepare())).rejects.toThrow(
			"provider write approval denied: providerWriteApproverActorId is not configured",
		);
		expect(missingApproverLedger.list()).toEqual([]);

		const selfApproverLedger = testLedger();
		const selfApproverClients = createTelclaudeLiveMcpRelayClients({
			ledger: selfApproverLedger,
			providerWriteApproverActorId: "operator",
		});
		await expect(selfApproverClients.providerPrepareWrite(providerPrepare())).rejects.toThrow(
			"provider write approval denied: providerWriteApproverActorId must differ from actorId",
		);
		expect(selfApproverLedger.list()).toEqual([]);
	});

	it("returns attachment metadata only and validates refs against the authority actor", async () => {
		const clients = createTelclaudeLiveMcpRelayClients({
			ledger: testLedger(),
			validateAttachment: (ref, options) => {
				if (options?.actorUserId !== "operator") {
					return { valid: false, reason: "Actor mismatch" };
				}
				return {
					valid: true,
					attachment: {
						ref,
						actorUserId: "operator",
						providerId: "bank",
						filepath: "/private/provider/raw.pdf",
						filename: "statement.pdf",
						mimeType: "application/pdf",
						size: 1234,
						createdAt: 1000,
						expiresAt: 2000,
					} satisfies AttachmentRef,
				};
			},
		});

		const result = await clients.attachmentGet(attachmentGet({ ref: "att_statement" }));
		expect(result).toEqual({
			ref: "att_statement",
			providerId: "bank",
			filename: "statement.pdf",
			mimeType: "application/pdf",
			size: 1234,
			createdAt: 1000,
			expiresAt: 2000,
		});
		expect(result).not.toHaveProperty("filepath");
		expect(result).not.toHaveProperty("actorUserId");
	});

	it("redacts audit payloads before handing them to the audit sink", async () => {
		const auditEntries: unknown[] = [];
		const clients = createTelclaudeLiveMcpRelayClients({
			ledger: testLedger(),
			auditNote: (entry) => {
				auditEntries.push(entry);
			},
		});

		await expect(
			clients.auditNote({
				...privateStamp(),
				kind: "provider.debug",
				payload: {
					message: "token sk-proj-abcdefghijklmnopqrstuvwxyz1234567890",
				},
			}),
		).resolves.toEqual({ stored: true });
		expect(JSON.stringify(auditEntries)).not.toContain("sk-proj-abcdefghijklmnopqrstuvwxyz");
	});

	it("uses a real default audit sink instead of silently faking storage", async () => {
		const clients = createTelclaudeLiveMcpRelayClients({ ledger: testLedger() });

		await expect(
			clients.auditNote({
				...privateStamp(),
				kind: "memory.review",
				payload: { summary: "operator-visible event" },
			}),
		).resolves.toEqual({ stored: true });
	});

	it("runtime factory wires adapters to the same ledger used for execute authorization", async () => {
		const runtime = await startTelclaudeLiveMcpRuntime({
			nowMs: () => 2_000,
			config: {
				enabled: true,
				host: "127.0.0.1",
				port: 0,
				path: "/mcp",
				networkName: "telclaude-hermes-relay",
			},
			createRelayClients: ({ ledger }) =>
				createTelclaudeLiveMcpRelayClients({
					ledger,
					makeApprovalRequestId: () => "runtime-approval",
					providerWriteApproverActorId: "operator:provider-approver",
				}),
		});
		try {
			const prepared = await runtime.issueProbeTokenBundle({
				privateConnection: {
					sessionKey: "telegram:ops",
					profileId: "ops",
					endpointId: "endpoint-private",
					networkNamespace: "netns-private",
				},
				wrongConnection: {
					sessionKey: "telegram:social",
					profileId: "social",
					endpointId: "endpoint-social",
					networkNamespace: "netns-social",
				},
				privateAuthority: {
					...privateStamp(),
					providerScopes: ["bank"],
					outboundChannels: ["whatsapp"],
				},
				nowMs: 1_000,
				ttlMs: 60_000,
				peerAddress: "127.0.0.1",
			});
			const response = await postRpc(runtime.endpoint?.url, prepared.allowed.authorizationHeader, {
				jsonrpc: "2.0",
				id: "prepare",
				method: "tools/call",
				params: {
					name: "tc_provider_prepare_write",
					arguments: {
						service: "bank",
						action: "transfer.execute",
						params: { amount: 10 },
					},
				},
			});
			const body = response.body as { result?: { actionRef?: string } };
			expect(response.httpStatus).toBe(200);
			expect(runtime.ledger?.get(body.result?.actionRef ?? "")).toMatchObject({
				kind: "provider",
				status: "prepared",
				params: { amount: 10 },
			});
		} finally {
			await runtime.stop();
		}
	});
});

function testLedger() {
	return createTelclaudeMcpSideEffectLedger({
		makeRef: makeRefs(),
		verifyApproval: async () => ({
			ok: false,
			code: "approval_required",
			reason: "test verifier not used by prepare",
		}),
	});
}

function makeRefs(): () => string {
	let ref = 0;
	return () => `effect-test-${++ref}`;
}

function makeApprovalIds(): () => string {
	let id = 0;
	return () => `approval-${++id}`;
}

function privateStamp(
	overrides: Partial<TelclaudeMcpAuthorityStamp> = {},
): TelclaudeMcpAuthorityStamp {
	return {
		actorId: "operator",
		profileId: "ops",
		domain: "private",
		memorySource: "telegram:ops",
		writableNamespace: "private:ops",
		endpointId: "endpoint-private",
		networkNamespace: "netns-private",
		...overrides,
	};
}

function socialStamp(
	overrides: Partial<TelclaudeMcpAuthorityStamp> = {},
): TelclaudeMcpAuthorityStamp {
	return {
		actorId: "social-agent",
		profileId: "social",
		domain: "social",
		memorySource: "social",
		writableNamespace: "social:public",
		endpointId: "endpoint-social",
		networkNamespace: "netns-social",
		...overrides,
	};
}

function memorySearch(
	overrides: Partial<TelclaudeMcpMemorySearchRequest> = {},
): TelclaudeMcpMemorySearchRequest {
	return {
		...privateStamp(),
		query: "operator",
		limit: 10,
		...overrides,
	};
}

function memoryWrite(
	overrides: Partial<TelclaudeMcpMemoryWriteRequest> = {},
): TelclaudeMcpMemoryWriteRequest {
	return {
		...privateStamp(),
		id: "private-1",
		category: "profile",
		content: "operator memory",
		trust: "trusted",
		...overrides,
	};
}

function providerRead(
	overrides: Partial<TelclaudeMcpProviderReadRequest> = {},
): TelclaudeMcpProviderReadRequest {
	return {
		...privateStamp(),
		providerId: "bank",
		service: "bank",
		action: "balances.list",
		params: {},
		...overrides,
	};
}

function providerPrepare(
	overrides: Partial<TelclaudeMcpProviderPrepareWriteRequest> = {},
): TelclaudeMcpProviderPrepareWriteRequest {
	return {
		...privateStamp(),
		providerId: "bank",
		service: "bank",
		action: "transfer.execute",
		params: { amount: 10 },
		...overrides,
	};
}

function outboundPrepare(
	overrides: Partial<TelclaudeMcpOutboundPrepareRequest> = {},
): TelclaudeMcpOutboundPrepareRequest {
	return {
		...privateStamp(),
		channel: "whatsapp",
		recipient: "+15551234567",
		content: "hello",
		mediaRefs: [],
		...overrides,
	};
}

function attachmentGet(
	overrides: Partial<TelclaudeMcpAttachmentGetRequest> = {},
): TelclaudeMcpAttachmentGetRequest {
	return {
		...privateStamp(),
		ref: "att_123",
		...overrides,
	};
}

async function postRpc(
	url: string | undefined,
	authorizationHeader: string,
	body: Record<string, unknown>,
): Promise<{ httpStatus: number; body: unknown }> {
	if (!url) throw new Error("runtime endpoint URL missing");
	const response = await fetch(url, {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			Authorization: authorizationHeader,
		},
		body: JSON.stringify(body),
	});
	return {
		httpStatus: response.status,
		body: (await response.json()) as unknown,
	};
}
