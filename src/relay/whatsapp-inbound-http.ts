import { z } from "zod";
import { loadConfig, type TelclaudeConfig } from "../config/config.js";
import { type EffectiveOperatorProfile, getOperatorProfile } from "../config/profiles.js";
import { type InboundEvent, InboundEventSchema } from "../hermes/edge-adapter-contract.js";
import {
	createRelayConversationStore,
	type RelayConversationStore,
} from "../hermes/relay-conversation-store.js";
import { getChildLogger } from "../logging.js";
import { normalizeWhatsAppAddressRef } from "../whatsapp/address.js";
import {
	type AttachmentQuarantineStore,
	createAttachmentQuarantineStore,
} from "./attachment-quarantine-store.js";
import type { InboundMediaProcessingInput } from "./inbound-media-processor.js";
import {
	combineWhatsAppIdentityResolvers,
	createWhatsAppHouseholdIdentityResolver,
} from "./whatsapp-household-bindings.js";
import {
	type CreateWhatsAppInboundCl1PipelineOptions,
	createOperatorWhatsAppIdentityResolver,
	createWhatsAppInboundCl1Pipeline,
	type WhatsAppIdentityResolution,
	type WhatsAppIdentityResolver,
	type WhatsAppInboundBridgeEvent,
	WhatsAppInboundBridgeEventSchema,
	type WhatsAppInboundCl1Result,
} from "./whatsapp-inbound-cl1.js";
import {
	dispatchWhatsAppInboundToHermes,
	type WhatsAppInboundDispatchInput,
	type WhatsAppInboundDispatchResult,
} from "./whatsapp-inbound-dispatcher.js";
import {
	logWhatsAppInboundReplyOutcome,
	WhatsAppInboundReplyError,
	type WhatsAppInboundReplySender,
} from "./whatsapp-inbound-reply.js";
import type { WhatsAppMediaActionConfirmationInterceptor } from "./whatsapp-media-action-confirmation-interceptor.js";
import type { WhatsAppProviderChallengeInterceptor } from "./whatsapp-provider-challenge-interceptor.js";
import type { WhatsAppReminderConfirmationInterceptor } from "./whatsapp-reminder-confirmation-interceptor.js";

const logger = getChildLogger({ module: "whatsapp-inbound-http" });

export const WHATSAPP_INBOUND_BRIDGE_PATH = "/v1/whatsapp/inbound";
export const WHATSAPP_INBOUND_SIGNATURE_HEADER = "x-telclaude-whatsapp-inbound-signature";
export const TELCLAUDE_WHATSAPP_INBOUND_SECRET_ENV = "TELCLAUDE_WHATSAPP_INBOUND_SECRET";
export const TELCLAUDE_WHATSAPP_INBOUND_OPERATOR_ADDRESSES_ENV =
	"TELCLAUDE_WHATSAPP_INBOUND_OPERATOR_ADDRESSES";
export const TELCLAUDE_WHATSAPP_INBOUND_PROFILE_ID_ENV = "TELCLAUDE_WHATSAPP_INBOUND_PROFILE_ID";
export const TELCLAUDE_WHATSAPP_INBOUND_ACTOR_ID_ENV = "TELCLAUDE_WHATSAPP_INBOUND_ACTOR_ID";
export const TELCLAUDE_WHATSAPP_INBOUND_DISPLAY_NAME_ENV =
	"TELCLAUDE_WHATSAPP_INBOUND_DISPLAY_NAME";

const BodySchema = z
	.object({
		event: WhatsAppInboundBridgeEventSchema,
	})
	.strict();

export type WhatsAppInboundDispatch = (
	input: WhatsAppInboundDispatchInput,
) => Promise<WhatsAppInboundDispatchResult>;

export type WhatsAppInboundBridgeHttpOptions = {
	readonly signatureSecret?: string;
	readonly operatorAddressRefs?: readonly string[];
	readonly profileId?: string;
	readonly actorId?: string;
	readonly displayName?: string;
	readonly config?: TelclaudeConfig;
	readonly profile?: EffectiveOperatorProfile;
	readonly conversationStore?: RelayConversationStore;
	readonly quarantineStore?: AttachmentQuarantineStore;
	readonly dispatch?: WhatsAppInboundDispatch;
	readonly replySender?: WhatsAppInboundReplySender;
	readonly processInboundMedia?: (input: InboundMediaProcessingInput) => Promise<InboundEvent>;
	readonly nowMs?: () => number;
	readonly cwd?: string;
	readonly timeoutMs?: number;
	readonly interceptBeforePersistence?: CreateWhatsAppInboundCl1PipelineOptions["interceptBeforePersistence"];
	readonly handleHouseholdEmergency?: CreateWhatsAppInboundCl1PipelineOptions["handleHouseholdEmergency"];
	readonly providerChallengeInterceptor?: WhatsAppProviderChallengeInterceptor;
	readonly reminderConfirmationInterceptor?: WhatsAppReminderConfirmationInterceptor;
	readonly mediaActionConfirmationInterceptor?: WhatsAppMediaActionConfirmationInterceptor;
};

let defaultWhatsAppInboundBridgeOptions: WhatsAppInboundBridgeHttpOptions | undefined;

export function composeWhatsAppInboundInterceptors(input: {
	readonly providerChallenge?: WhatsAppProviderChallengeInterceptor;
	readonly reminderConfirmation?: WhatsAppReminderConfirmationInterceptor;
	readonly mediaActionConfirmation?: WhatsAppMediaActionConfirmationInterceptor;
}): CreateWhatsAppInboundCl1PipelineOptions["interceptBeforePersistence"] | undefined {
	const interceptors = [
		input.providerChallenge,
		input.reminderConfirmation,
		input.mediaActionConfirmation,
	].filter(
		(interceptor): interceptor is NonNullable<typeof interceptor> => interceptor !== undefined,
	);
	if (interceptors.length === 0) return undefined;
	return async (context) => {
		for (const interceptor of interceptors) {
			const result = await interceptor(context);
			if (result.handled) return result;
		}
		return { handled: false };
	};
}

export function setDefaultWhatsAppInboundBridgeOptions(
	options: WhatsAppInboundBridgeHttpOptions | null,
): void {
	defaultWhatsAppInboundBridgeOptions = options ?? undefined;
}

type WhatsAppInboundBridgeHttpFailure = {
	readonly ok: false;
	readonly status: number;
	readonly payload: Record<string, unknown>;
};

export type WhatsAppInboundBridgeHttpResult =
	| WhatsAppInboundBridgeHttpFailure
	| {
			readonly ok: true;
			readonly status: number;
			readonly payload: Record<string, unknown>;
	  };

export type WhatsAppInboundRelayOutcome =
	| {
			readonly kind: "accepted";
			readonly duplicate: boolean;
			readonly intercepted: boolean;
			readonly dispatched: false;
	  }
	| {
			readonly kind: "accepted";
			readonly duplicate: false;
			readonly intercepted: false;
			readonly dispatched: true;
			readonly toolUses: number;
			readonly toolResults: number;
			readonly outboundToolUses: number;
	  }
	| { readonly kind: "failed"; readonly code: string };

export type WhatsAppInboundRelayLogSink = {
	info(bindings: Record<string, unknown>, msg: string): void;
	warn(bindings: Record<string, unknown>, msg: string): void;
};

export function logWhatsAppInboundRelayOutcome(
	sink: WhatsAppInboundRelayLogSink,
	outcome: WhatsAppInboundRelayOutcome,
): void {
	if (outcome.kind === "accepted") {
		const bindings: Record<string, unknown> = {
			outcome: "accepted",
			duplicate: outcome.duplicate,
			intercepted: outcome.intercepted,
			dispatched: outcome.dispatched,
		};
		if (outcome.dispatched) {
			bindings.toolUses = outcome.toolUses;
			bindings.toolResults = outcome.toolResults;
			bindings.outboundToolUses = outcome.outboundToolUses;
		}
		sink.info(bindings, "WhatsApp inbound POST");
		return;
	}
	sink.warn({ outcome: "failed", code: outcome.code }, "WhatsApp inbound POST");
}

export async function handleWhatsAppInboundBridgePost(input: {
	readonly body: string;
	readonly signatureHeader: string | readonly string[] | undefined;
	readonly options?: WhatsAppInboundBridgeHttpOptions | false;
}): Promise<WhatsAppInboundBridgeHttpResult> {
	if (input.options === false) {
		return failure(503, "whatsapp_inbound_disabled", "WhatsApp inbound bridge is disabled");
	}
	const resolved = resolveOptions(input.options);
	if (!resolved.ok) return resolved;
	const signature = normalizeHeader(input.signatureHeader);
	if (!signature) {
		return failure(
			401,
			"whatsapp_inbound_signature_missing",
			"WhatsApp inbound bridge signature header is required",
		);
	}
	let parsedJson: unknown;
	try {
		parsedJson = JSON.parse(input.body);
	} catch {
		return failure(400, "whatsapp_inbound_json_invalid", "Invalid JSON.");
	}
	const parsed = BodySchema.safeParse(parsedJson);
	if (!parsed.success) {
		return failure(
			400,
			"whatsapp_inbound_body_invalid",
			"WhatsApp inbound bridge body must contain only a strict event object",
		);
	}

	const pipeline = createWhatsAppInboundCl1Pipeline({
		signatureSecret: resolved.signatureSecret,
		conversationStore: resolved.conversationStore,
		quarantineStore: resolved.quarantineStore,
		resolveIdentity: resolved.resolveIdentity,
		...(resolved.interceptBeforePersistence
			? { interceptBeforePersistence: resolved.interceptBeforePersistence }
			: {}),
		...(resolved.handleHouseholdEmergency
			? { handleHouseholdEmergency: resolved.handleHouseholdEmergency }
			: {}),
		...(resolved.nowMs ? { nowMs: resolved.nowMs } : {}),
	});
	const cl1 = await pipeline.ingest({
		event: parsed.data.event,
		signature,
	});
	if (!cl1.ok) return cl1Failure(cl1);
	if (cl1.duplicate) {
		logWhatsAppInboundRelayOutcome(logger, {
			kind: "accepted",
			duplicate: true,
			intercepted: false,
			dispatched: false,
		});
		return {
			ok: true,
			status: 200,
			payload: {
				ok: true,
				duplicate: true,
				duplicateHandling: cl1.duplicateHandling,
				reason: cl1.reason,
			},
		};
	}
	if (cl1.intercepted) {
		logWhatsAppInboundRelayOutcome(logger, {
			kind: "accepted",
			duplicate: false,
			intercepted: true,
			dispatched: false,
		});
		return {
			ok: true,
			status: 202,
			payload: { ok: true, duplicate: false, intercepted: true, templateId: cl1.templateId },
		};
	}
	const dispatchProfile = resolved.resolveProfile(cl1.identity);
	if (!dispatchProfile) {
		return failure(
			503,
			"whatsapp_inbound_profile_missing",
			`WhatsApp inbound profile is not configured: ${cl1.identity.profileId}`,
		);
	}
	logWhatsAppInboundRelayOutcome(logger, {
		kind: "accepted",
		duplicate: false,
		intercepted: false,
		dispatched: false,
	});
	scheduleWhatsAppInboundDispatch({
		dispatch: resolved.dispatch,
		event: cl1.event,
		conversation: cl1.conversation,
		turn: cl1.turn,
		config: resolved.config,
		profile: dispatchProfile,
		identity: cl1.identity,
		replyAddressRef:
			cl1.identity.domain === "household" ? cl1.identity.replyAddressRef : cl1.identity.principalId,
		...(resolved.replySender ? { replySender: resolved.replySender } : {}),
		...(resolved.processInboundMedia ? { processInboundMedia: resolved.processInboundMedia } : {}),
		...(resolved.cwd ? { cwd: resolved.cwd } : {}),
		...(resolved.timeoutMs !== undefined ? { timeoutMs: resolved.timeoutMs } : {}),
	});

	return {
		ok: true,
		status: 202,
		payload: {
			ok: true,
			duplicate: false,
			dispatched: false,
			dispatchPending: true,
			sourceAudit: cl1.event.sourceAudit,
			ordering: cl1.event.ordering,
		},
	};
}

function scheduleWhatsAppInboundDispatch(
	input: WhatsAppInboundDispatchInput & {
		readonly dispatch: WhatsAppInboundDispatch;
		readonly processInboundMedia?: (input: InboundMediaProcessingInput) => Promise<InboundEvent>;
		readonly replyAddressRef: string;
		readonly replySender?: WhatsAppInboundReplySender;
	},
): void {
	void Promise.resolve()
		.then(async () => {
			let dispatchEvent = input.event;
			if (input.processInboundMedia) {
				try {
					dispatchEvent = InboundEventSchema.parse(
						await input.processInboundMedia({
							event: input.event,
							identity: input.identity,
							conversation: input.conversation,
							turn: input.turn,
						}),
					);
				} catch {
					logWhatsAppInboundRelayOutcome(logger, {
						kind: "failed",
						code: "whatsapp_inbound_media_processing_failed",
					});
					return;
				}
			}
			const dispatch = await input.dispatch({
				event: dispatchEvent,
				conversation: input.conversation,
				turn: input.turn,
				config: input.config,
				profile: input.profile,
				identity: input.identity,
				...(input.cwd ? { cwd: input.cwd } : {}),
				...(input.timeoutMs !== undefined ? { timeoutMs: input.timeoutMs } : {}),
			});
			if (!dispatch.ok) {
				logWhatsAppInboundRelayOutcome(logger, { kind: "failed", code: dispatch.code });
				return;
			}
			logWhatsAppInboundRelayOutcome(logger, {
				kind: "accepted",
				duplicate: false,
				intercepted: false,
				dispatched: true,
				toolUses: dispatch.toolUses,
				toolResults: dispatch.toolResults,
				outboundToolUses: dispatch.outboundToolUses,
			});
			const response = dispatch.response.trim();
			if (!response) {
				logWhatsAppInboundReplyOutcome(logger, { kind: "reply_skipped_empty" });
				return;
			}
			if (!input.replySender) {
				logWhatsAppInboundReplyOutcome(logger, {
					kind: "reply_failed",
					code: "whatsapp_inbound_reply_sender_missing",
				});
				return;
			}
			try {
				const receipt = await input.replySender({
					conversation: input.conversation,
					recipientAddressRef: input.replyAddressRef,
					body: response,
					turnRef: input.turn.ref,
				});
				if (receipt.deliveryStatus === "failed" || receipt.deliveryStatus === "dead_lettered") {
					logWhatsAppInboundReplyOutcome(logger, {
						kind: "reply_failed",
						code: "whatsapp_inbound_reply_delivery_failed",
					});
					return;
				}
				logWhatsAppInboundReplyOutcome(logger, { kind: "reply_sent" });
			} catch (error) {
				logWhatsAppInboundReplyOutcome(logger, {
					kind: "reply_failed",
					code:
						error instanceof WhatsAppInboundReplyError
							? error.code
							: "whatsapp_inbound_reply_exception",
				});
			}
		})
		.catch(() => {
			logWhatsAppInboundRelayOutcome(logger, {
				kind: "failed",
				code: "whatsapp_inbound_dispatch_exception",
			});
		});
}

function resolveOptions(options: WhatsAppInboundBridgeHttpOptions | undefined):
	| {
			readonly ok: true;
			readonly signatureSecret: string;
			readonly resolveIdentity: WhatsAppIdentityResolver;
			readonly resolveProfile: (
				identity: WhatsAppIdentityResolution,
			) => EffectiveOperatorProfile | null;
			readonly config: Pick<TelclaudeConfig, "hermes">;
			readonly conversationStore: RelayConversationStore;
			readonly quarantineStore: AttachmentQuarantineStore;
			readonly dispatch: WhatsAppInboundDispatch;
			readonly replySender?: WhatsAppInboundReplySender;
			readonly processInboundMedia?: (input: InboundMediaProcessingInput) => Promise<InboundEvent>;
			readonly nowMs?: () => number;
			readonly cwd?: string;
			readonly timeoutMs?: number;
			readonly interceptBeforePersistence?: CreateWhatsAppInboundCl1PipelineOptions["interceptBeforePersistence"];
			readonly handleHouseholdEmergency?: CreateWhatsAppInboundCl1PipelineOptions["handleHouseholdEmergency"];
	  }
	| WhatsAppInboundBridgeHttpFailure {
	options ??= defaultWhatsAppInboundBridgeOptions;
	const env = process.env;
	const signatureSecret = requiredOption(
		options?.signatureSecret ?? env[TELCLAUDE_WHATSAPP_INBOUND_SECRET_ENV],
		"whatsapp_inbound_secret_missing",
		`${TELCLAUDE_WHATSAPP_INBOUND_SECRET_ENV} is required`,
	);
	if (!signatureSecret.ok) return signatureSecret;
	const config = options?.config ?? loadConfig();
	const operatorAddressRefs =
		options?.operatorAddressRefs ?? csvEnv(env[TELCLAUDE_WHATSAPP_INBOUND_OPERATOR_ADDRESSES_ENV]);
	const householdAddresses = new Set(
		(config.profiles ?? [])
			.flatMap((profile) =>
				(profile.whatsappHouseholdBindings ?? []).map((binding) =>
					normalizeWhatsAppAddressRef(binding.address),
				),
			)
			.filter((address): address is string => address !== null),
	);
	if (operatorAddressRefs.length === 0 && householdAddresses.size === 0) {
		return failure(
			503,
			"whatsapp_inbound_operator_addresses_missing",
			`${TELCLAUDE_WHATSAPP_INBOUND_OPERATOR_ADDRESSES_ENV} or a household binding is required`,
		);
	}
	const profileId =
		options?.profileId?.trim() ||
		env[TELCLAUDE_WHATSAPP_INBOUND_PROFILE_ID_ENV]?.trim() ||
		"default";
	const operatorProfile =
		operatorAddressRefs.length > 0
			? (options?.profile ?? getOperatorProfile(profileId, config))
			: null;
	if (operatorAddressRefs.length > 0 && !operatorProfile) {
		return failure(
			503,
			"whatsapp_inbound_profile_missing",
			`WhatsApp inbound profile is not configured: ${profileId}`,
		);
	}
	const actorId = options?.actorId?.trim() || env[TELCLAUDE_WHATSAPP_INBOUND_ACTOR_ID_ENV]?.trim();
	const displayName =
		options?.displayName?.trim() || env[TELCLAUDE_WHATSAPP_INBOUND_DISPLAY_NAME_ENV]?.trim();
	let operatorResolver: WhatsAppIdentityResolver | null = null;
	if (operatorAddressRefs.length > 0 && operatorProfile) {
		const normalizedOperators = operatorAddressRefs.map(normalizeWhatsAppAddressRef);
		if (normalizedOperators.some((address) => !address)) {
			return failure(
				503,
				"whatsapp_inbound_operator_addresses_invalid",
				`${TELCLAUDE_WHATSAPP_INBOUND_OPERATOR_ADDRESSES_ENV} contains an invalid address`,
			);
		}
		if (normalizedOperators.some((address) => address && householdAddresses.has(address))) {
			return failure(
				503,
				"whatsapp_inbound_identity_overlap",
				"A WhatsApp address may not be both operator-private and household-bound",
			);
		}
		operatorResolver = createOperatorWhatsAppIdentityResolver({
			operatorAddressRefs,
			profileId: operatorProfile.id,
			...(actorId ? { actorId } : {}),
			...(displayName ? { displayName } : {}),
		});
	}
	const householdResolver = createWhatsAppHouseholdIdentityResolver(config);
	const resolveIdentity = operatorResolver
		? combineWhatsAppIdentityResolvers(operatorResolver, householdResolver)
		: householdResolver;
	const composedInterceptor =
		options?.interceptBeforePersistence ??
		composeWhatsAppInboundInterceptors({
			providerChallenge: options?.providerChallengeInterceptor,
			reminderConfirmation: options?.reminderConfirmationInterceptor,
			mediaActionConfirmation: options?.mediaActionConfirmationInterceptor,
		});
	return {
		ok: true,
		signatureSecret: signatureSecret.value,
		resolveIdentity,
		resolveProfile: (identity) =>
			identity.domain === "private"
				? operatorProfile
				: getOperatorProfile(identity.profileId, config),
		config,
		conversationStore: options?.conversationStore ?? createRelayConversationStore(),
		quarantineStore: options?.quarantineStore ?? createAttachmentQuarantineStore(),
		dispatch: options?.dispatch ?? dispatchWhatsAppInboundToHermes,
		...(options?.replySender ? { replySender: options.replySender } : {}),
		...(options?.processInboundMedia ? { processInboundMedia: options.processInboundMedia } : {}),
		...(composedInterceptor ? { interceptBeforePersistence: composedInterceptor } : {}),
		...(options?.handleHouseholdEmergency
			? { handleHouseholdEmergency: options.handleHouseholdEmergency }
			: {}),
		...(options?.nowMs ? { nowMs: options.nowMs } : {}),
		...(options?.cwd ? { cwd: options.cwd } : {}),
		...(options?.timeoutMs !== undefined ? { timeoutMs: options.timeoutMs } : {}),
	};
}

function cl1Failure(result: Extract<WhatsAppInboundCl1Result, { ok: false }>) {
	const status =
		result.code === "whatsapp_inbound_signature_invalid" ||
		result.code === "whatsapp_inbound_signature_stale"
			? 401
			: result.code === "whatsapp_inbound_sender_unlinked" ||
					result.code === "whatsapp_inbound_group_unsupported"
				? 403
				: result.code === "whatsapp_inbound_cursor_untrusted"
					? 409
					: 400;
	return failure(status, result.code, result.reason, result.retryable);
}

function requiredOption(
	value: string | undefined,
	code: string,
	reason: string,
): { readonly ok: true; readonly value: string } | WhatsAppInboundBridgeHttpFailure {
	const trimmed = value?.trim();
	if (!trimmed) return failure(503, code, reason);
	return { ok: true, value: trimmed };
}

function failure(
	status: number,
	code: string,
	reason: string,
	retryable = false,
): WhatsAppInboundBridgeHttpFailure {
	logWhatsAppInboundRelayOutcome(logger, { kind: "failed", code });
	return {
		ok: false,
		status,
		payload: {
			ok: false,
			code,
			reason,
			retryable,
		},
	};
}

function normalizeHeader(value: string | readonly string[] | undefined): string | null {
	const candidate = Array.isArray(value) ? value[0] : value;
	const trimmed = candidate?.trim();
	return trimmed || null;
}

function csvEnv(value: string | undefined): string[] {
	return (value ?? "")
		.split(",")
		.map((entry) => entry.trim())
		.filter(Boolean);
}

export function whatsappInboundBridgeBody(event: WhatsAppInboundBridgeEvent): string {
	return JSON.stringify({ event });
}
