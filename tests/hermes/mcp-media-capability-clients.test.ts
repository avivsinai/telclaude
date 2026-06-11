import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resetConfigCache } from "../../src/config/config.js";
import { TelclaudeEdgeRuntime } from "../../src/hermes/edge-adapter-runtime.js";
import type {
	TelclaudeMcpAuthorityStamp,
	TelclaudeMcpImageGenerateRequest,
	TelclaudeMcpTtsRequest,
} from "../../src/hermes/mcp/bridge.js";
import {
	createTelclaudeLiveMcpRelayClients,
	type TelclaudeLiveMcpAuditEntry,
} from "../../src/hermes/mcp/live-relay-clients.js";
import { createTelclaudeMcpSideEffectLedger } from "../../src/hermes/mcp/side-effect-ledger.js";
import { createRelayConversationStore } from "../../src/hermes/relay-conversation-store.js";
import {
	listAttachmentRefsByActor,
	validateAttachmentRef,
} from "../../src/storage/attachment-refs.js";
import { resetDatabase } from "../../src/storage/db.js";

const imagesGenerate = vi.hoisted(() => vi.fn());
const speechCreate = vi.hoisted(() => vi.fn());

// Mock at the OpenAI client boundary only: media-store writes, attachment-ref
// minting/validation, rate limiting, and the ffmpeg voice conversion all run
// for real.
vi.mock("../../src/services/openai-client.js", () => ({
	getOpenAIClient: async () => ({
		images: { generate: (...args: unknown[]) => imagesGenerate(...args) },
		audio: { speech: { create: (...args: unknown[]) => speechCreate(...args) } },
	}),
	isOpenAIConfigured: async () => true,
	isOpenAIConfiguredSync: () => true,
}));

const ONE_BY_ONE_PNG = Buffer.from(
	"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMBAAZ9pW0AAAAASUVORK5CYII=",
	"base64",
);

const SAVED_ENV_KEYS = [
	"TELCLAUDE_DATA_DIR",
	"TELCLAUDE_WORKSPACE",
	"TELCLAUDE_CONFIG",
	"TELCLAUDE_MEDIA_INBOX_DIR",
	"TELCLAUDE_MEDIA_OUTBOX_DIR",
	"TELCLAUDE_CAPABILITIES_URL",
	"TELEGRAM_RPC_RELAY_PRIVATE_KEY",
] as const;
const savedEnv = new Map<string, string | undefined>();

describe("Telclaude live MCP media capability clients", () => {
	let tempDir: string;

	beforeEach(() => {
		for (const key of SAVED_ENV_KEYS) savedEnv.set(key, process.env[key]);
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tc-live-mcp-media-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		process.env.TELCLAUDE_WORKSPACE = tempDir;
		process.env.TELCLAUDE_CONFIG = path.join(tempDir, "telclaude.json");
		process.env.TELEGRAM_RPC_RELAY_PRIVATE_KEY = "test-relay-attachment-signing-key";
		// The live MCP runs in the relay process: media services must call OpenAI
		// directly, never the agent-side capabilities route.
		delete process.env.TELCLAUDE_CAPABILITIES_URL;
		delete process.env.TELCLAUDE_MEDIA_INBOX_DIR;
		delete process.env.TELCLAUDE_MEDIA_OUTBOX_DIR;
		resetConfigCache();
		resetDatabase();
		imagesGenerate.mockReset();
		speechCreate.mockReset();
	});

	afterEach(() => {
		resetDatabase();
		resetConfigCache();
		fs.rmSync(tempDir, { recursive: true, force: true });
		for (const key of SAVED_ENV_KEYS) {
			const value = savedEnv.get(key);
			if (value === undefined) {
				delete process.env[key];
			} else {
				process.env[key] = value;
			}
		}
	});

	it("generates an image and returns a relay-owned attachment ref, never raw bytes", async () => {
		imagesGenerate.mockResolvedValueOnce({
			data: [{ b64_json: ONE_BY_ONE_PNG.toString("base64"), revised_prompt: "a calmer owl" }],
		});
		const auditEntries: TelclaudeLiveMcpAuditEntry[] = [];
		const clients = makeClients({ auditEntries });

		const result = (await clients.imageGenerate(imageGen())) as {
			attachmentRef: string;
			sizeBytes: number;
			model: string;
			revisedPrompt?: string;
			expiresAt: number;
		};

		expect(imagesGenerate).toHaveBeenCalledWith(
			expect.objectContaining({
				model: "gpt-image-1.5",
				prompt: "an owl perched on a telephone wire at dusk",
				output_format: "png",
				n: 1,
			}),
		);
		expect(result.attachmentRef).toMatch(/^att_[0-9a-f]{8}\.\d+\.[0-9a-f]{16}$/);
		expect(result.sizeBytes).toBe(ONE_BY_ONE_PNG.length);
		expect(result.model).toBe("gpt-image-1.5");
		expect(result.revisedPrompt).toBe("a calmer owl");
		expect(result.expiresAt).toBeGreaterThan(Date.now());
		// No raw bytes or local paths in the tool result.
		const serialized = JSON.stringify(result);
		expect(serialized).not.toContain(tempDir);
		expect(serialized).not.toContain(ONE_BY_ONE_PNG.toString("base64"));
		expect(serialized).not.toContain(".png");

		// The minted ref round-trips through the same owner-bound validation that
		// tc_attachment_get and the outbound media path use.
		const validated = validateAttachmentRef(result.attachmentRef, { actorUserId: "operator" });
		expect(validated.valid).toBe(true);
		if (!validated.valid) throw new Error("unreachable");
		expect(validated.attachment.providerId).toBe("tc_image_generate:private");
		expect(fs.readFileSync(validated.attachment.filepath)).toEqual(ONE_BY_ONE_PNG);

		const metadata = (await clients.attachmentGet({
			...privateStamp(),
			ref: result.attachmentRef,
		})) as Record<string, unknown>;
		expect(metadata).toMatchObject({
			ref: result.attachmentRef,
			providerId: "tc_image_generate:private",
			mimeType: "image/png",
			size: ONE_BY_ONE_PNG.length,
		});
		expect(metadata).not.toHaveProperty("filepath");

		// A different actor (e.g. the social authority) cannot resolve the ref.
		await expect(
			clients.attachmentGet({ ...socialStamp(), ref: result.attachmentRef }),
		).rejects.toThrow("attachment unavailable: Actor mismatch");

		expect(auditEntries).toEqual([
			expect.objectContaining({
				actorId: "operator",
				domain: "private",
				kind: "media.image",
				payload: expect.objectContaining({
					attachmentRef: result.attachmentRef,
					model: "gpt-image-1.5",
					sizeBytes: ONE_BY_ONE_PNG.length,
				}),
			}),
		]);
	});

	it("synthesizes Telegram voice audio through real ffmpeg conversion and mints a ref", async () => {
		speechCreate.mockResolvedValueOnce({ arrayBuffer: async () => toArrayBuffer(silentWav()) });
		const clients = makeClients();

		const result = (await clients.tts(ttsReq({ speed: 1.25 }))) as {
			attachmentRef: string;
			sizeBytes: number;
			format: string;
			voice: string;
			estimatedDurationSeconds: number;
		};

		expect(speechCreate).toHaveBeenCalledWith(
			expect.objectContaining({
				input: "hello from the relay",
				voice: "alloy",
				speed: 1.25,
				response_format: "opus",
			}),
		);
		expect(result.format).toBe("ogg");
		expect(result.voice).toBe("alloy");
		expect(result.sizeBytes).toBeGreaterThan(0);
		expect(result.estimatedDurationSeconds).toBeGreaterThan(0);

		const validated = validateAttachmentRef(result.attachmentRef, { actorUserId: "operator" });
		expect(validated.valid).toBe(true);
		if (!validated.valid) throw new Error("unreachable");
		expect(validated.attachment.providerId).toBe("tc_tts:private");
		expect(validated.attachment.mimeType).toBe("audio/ogg");
		// Real OGG container produced by the actual ffmpeg conversion.
		const audio = fs.readFileSync(validated.attachment.filepath);
		expect(audio.subarray(0, 4).toString("ascii")).toBe("OggS");
		expect(audio.length).toBe(result.sizeBytes);
	});

	it("rejects unsupported TTS voices before any provider call", async () => {
		const clients = makeClients();

		await expect(clients.tts(ttsReq({ voice: "bowser" }))).rejects.toThrow(
			"tts voice not supported: bowser",
		);
		expect(speechCreate).not.toHaveBeenCalled();
		expect(listAttachmentRefsByActor("operator")).toEqual([]);
	});

	it("prepares an outbound send carrying the minted ref through real ref validation", async () => {
		imagesGenerate.mockResolvedValueOnce({
			data: [{ b64_json: ONE_BY_ONE_PNG.toString("base64") }],
		});
		const ledger = testLedger();
		const edgeRuntime = new TelclaudeEdgeRuntime();
		const clients = createTelclaudeLiveMcpRelayClients({
			ledger,
			makeApprovalRequestId: () => "approval-media-outbound",
			outboundApproverActorId: "operator:outbound-approver",
			edgeRuntime,
			// Owner-bound resolver: validates the storage ref against the sending
			// actor, then quarantines the validated file into the edge runtime so
			// the real edge attachment checks run during prepareOutbound.
			resolveOutboundMediaRefs: (refs, { request, conversation }) => {
				const validated = refs.map((ref) => {
					const result = validateAttachmentRef(ref, { actorUserId: request.actorId });
					if (!result.valid) {
						throw new Error(`outbound media denied: ${result.reason}`);
					}
					return result.attachment;
				});
				const event = edgeRuntime.ingest({
					channel: "whatsapp",
					domain: "private",
					conversationId: conversation.conversationId,
					threadId: conversation.threadId,
					profileId: conversation.profileId,
					attachments: validated.map((attachment) => ({
						attachmentId: attachment.ref,
						mediaType: attachment.mimeType ?? "application/octet-stream",
						sizeBytes: attachment.size ?? 0,
						localPath: attachment.filepath,
					})),
				});
				return event.normalized.mediaRefs;
			},
		});

		const image = (await clients.imageGenerate(imageGen())) as { attachmentRef: string };
		const { token } = mintWhatsappConversation("media-outbound");
		const turnConversationRef = mintWhatsappTurn(token, "media-outbound");

		const prepared = (await clients.outboundPrepare({
			...privateStamp(),
			conversationToken: token,
			turnConversationRef,
			body: "here is your owl",
			mediaRefs: [image.attachmentRef],
			outboundChannels: ["whatsapp"],
		})) as { outboundRef: string; edgePreparedRef: string };

		expect(prepared.edgePreparedRef).toMatch(/^edge-out:/);
		expect(ledger.get(prepared.outboundRef)).toMatchObject({
			kind: "outbound",
			status: "prepared",
			mediaRefs: [image.attachmentRef],
			preparedMediaRefs: [
				expect.objectContaining({
					quarantineId: expect.stringMatching(/^edge-quarantine:/),
					contentHash: expect.any(String),
				}),
			],
		});

		// A ref minted for a different actor fails the same validation closed.
		imagesGenerate.mockResolvedValueOnce({
			data: [{ b64_json: ONE_BY_ONE_PNG.toString("base64") }],
		});
		const foreign = (await clients.imageGenerate(imageGen({ actorId: "other-operator" }))) as {
			attachmentRef: string;
		};
		const foreignTurn = mintWhatsappTurn(token, "media-outbound-foreign");
		await expect(
			clients.outboundPrepare({
				...privateStamp(),
				conversationToken: token,
				turnConversationRef: foreignTurn,
				body: "stolen attachment",
				mediaRefs: [foreign.attachmentRef],
				outboundChannels: ["whatsapp"],
			}),
		).rejects.toThrow("outbound media denied: Actor mismatch");
		expect(ledger.list()).toHaveLength(1);
	});

	it("enforces the existing image and tts rate limits in independent buckets", async () => {
		fs.writeFileSync(
			path.join(tempDir, "telclaude.json"),
			JSON.stringify({
				imageGeneration: { maxPerHourPerUser: 1, maxPerDayPerUser: 1 },
				tts: { maxPerHourPerUser: 1, maxPerDayPerUser: 1 },
			}),
		);
		resetConfigCache();
		imagesGenerate.mockResolvedValue({
			data: [{ b64_json: ONE_BY_ONE_PNG.toString("base64") }],
		});
		speechCreate.mockResolvedValue({ arrayBuffer: async () => toArrayBuffer(silentWav()) });
		const clients = makeClients();

		await expect(clients.imageGenerate(imageGen())).resolves.toBeTruthy();
		await expect(clients.imageGenerate(imageGen())).rejects.toThrow(/Hourly limit reached/);
		expect(imagesGenerate).toHaveBeenCalledTimes(1);

		// tts has its own bucket: still allowed once, then limited.
		await expect(clients.tts(ttsReq())).resolves.toBeTruthy();
		await expect(clients.tts(ttsReq())).rejects.toThrow(/Hourly limit reached/);
		expect(speechCreate).toHaveBeenCalledTimes(1);
	});

	it("wraps provider failures in a typed error with no key material and mints nothing", async () => {
		const secret = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890";
		imagesGenerate.mockRejectedValueOnce(new Error(`upstream rejected key ${secret}`));
		const auditEntries: TelclaudeLiveMcpAuditEntry[] = [];
		const clients = makeClients({ auditEntries });

		const error = (await clients.imageGenerate(imageGen()).catch((err: unknown) => err)) as Error;
		expect(error).toMatchObject({
			name: "TelclaudeLiveMcpMediaGenerationError",
			code: "mcp_media_generation_failed",
		});
		expect(error.message).toContain("tc_image_generate failed");
		expect(error.message).not.toContain(secret);
		expect(listAttachmentRefsByActor("operator")).toEqual([]);
		expect(auditEntries).toEqual([]);
	});
});

function makeClients(options: { auditEntries?: TelclaudeLiveMcpAuditEntry[] } = {}) {
	return createTelclaudeLiveMcpRelayClients({
		ledger: testLedger(),
		...(options.auditEntries
			? {
					auditNote: (entry: TelclaudeLiveMcpAuditEntry) => {
						options.auditEntries?.push(entry);
					},
				}
			: {}),
	});
}

function testLedger() {
	return createTelclaudeMcpSideEffectLedger({
		verifyApproval: async () => ({
			ok: false,
			code: "approval_required",
			reason: "test verifier not used by prepare",
		}),
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

function socialStamp(): TelclaudeMcpAuthorityStamp {
	return {
		actorId: "social-agent",
		profileId: "social",
		domain: "social",
		memorySource: "social",
		writableNamespace: "social:public",
		endpointId: "endpoint-social",
		networkNamespace: "netns-social",
	};
}

function imageGen(
	overrides: Partial<TelclaudeMcpImageGenerateRequest> = {},
): TelclaudeMcpImageGenerateRequest {
	return {
		...privateStamp(),
		prompt: "an owl perched on a telephone wire at dusk",
		...overrides,
	};
}

function ttsReq(overrides: Partial<TelclaudeMcpTtsRequest> = {}): TelclaudeMcpTtsRequest {
	return {
		...privateStamp(),
		text: "hello from the relay",
		...overrides,
	};
}

function mintWhatsappConversation(suffix: string): { token: string } {
	return createRelayConversationStore().mint({
		channel: "whatsapp",
		conversationId: `conversation-${suffix}`,
		threadId: `thread-${suffix}`,
		profileId: "ops",
		domain: "private",
		routingSession: {
			sessionId: `session-${suffix}`,
			routeKey: `route-${suffix}`,
		},
		members: [
			{
				actorId: "operator",
				principalId: "+15557654321",
				role: "sender",
				scopes: ["message:reply"],
			},
			{
				actorId: `actor:${suffix}:recipient`,
				principalId: "+15551234567",
				role: "recipient",
			},
		],
	});
}

function mintWhatsappTurn(conversationToken: string, suffix: string): string {
	const { turnRef } = createRelayConversationStore().mintInboundTurn({
		conversationToken,
		inboundMessageId: `message-${suffix}`,
		senderActorId: "operator",
	});
	return turnRef;
}

/** Minimal valid mono 16-bit PCM WAV (0.2s of silence) for real ffmpeg input. */
function silentWav(): Buffer {
	const sampleRate = 16_000;
	const samples = sampleRate / 5;
	const dataSize = samples * 2;
	const wav = Buffer.alloc(44 + dataSize);
	wav.write("RIFF", 0, "ascii");
	wav.writeUInt32LE(36 + dataSize, 4);
	wav.write("WAVE", 8, "ascii");
	wav.write("fmt ", 12, "ascii");
	wav.writeUInt32LE(16, 16);
	wav.writeUInt16LE(1, 20);
	wav.writeUInt16LE(1, 22);
	wav.writeUInt32LE(sampleRate, 24);
	wav.writeUInt32LE(sampleRate * 2, 28);
	wav.writeUInt16LE(2, 32);
	wav.writeUInt16LE(16, 34);
	wav.write("data", 36, "ascii");
	wav.writeUInt32LE(dataSize, 40);
	return wav;
}

function toArrayBuffer(buffer: Buffer): ArrayBuffer {
	return buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
}
