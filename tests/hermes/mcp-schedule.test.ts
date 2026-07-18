import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { TelclaudeConfig } from "../../src/config/config.js";
import { setHomeTarget } from "../../src/config/sessions.js";
import { addCronJob, getCronJob, listCronJobs } from "../../src/cron/store.js";
import {
	createTelclaudeMcpBridge,
	type TelclaudeMcpAuthority,
	type TelclaudeMcpAuthorityStamp,
	type TelclaudeMcpBridgeDependencies,
} from "../../src/hermes/mcp/bridge.js";
import {
	createTelclaudeLiveMcpRelayClients,
	type ScheduleOwnerResolver,
} from "../../src/hermes/mcp/live-relay-clients.js";
import { createTelclaudeMcpSideEffectLedger } from "../../src/hermes/mcp/side-effect-ledger.js";
import { resolveHouseholdReminderContext } from "../../src/household-reminders/binding.js";
import {
	confirmHouseholdReminderProposal,
	createAppointmentDerivedHouseholdReminder,
	getHouseholdReminderForAuthority,
	getPendingHouseholdReminderProposal,
	rejectHouseholdReminderProposal,
} from "../../src/household-reminders/store.js";
import { resolveJerusalemOneShot } from "../../src/household-reminders/time.js";
import { resetDatabase } from "../../src/storage/db.js";

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

describe("Telclaude live MCP schedule tools", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tc-mcp-schedule-"));
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

	it("creates a future 'at' job with home delivery and authority-derived owner", async () => {
		// The operator's home target is keyed by the authority's subjectUserId.
		setHomeTarget("local-operator", { chatId: 4242, threadId: 7 });
		const clients = createTelclaudeLiveMcpRelayClients({ ledger: testLedger() });

		const future = new Date(Date.now() + 60 * 60 * 1000).toISOString();
		const result = (await clients.scheduleCreate({
			...privateStamp({ subjectUserId: "local-operator" }),
			schedule: { kind: "at", at: future },
			prompt: "remind me to call the clinic",
			label: "clinic call",
		})) as { jobId: string; nextRunAt: string | null };

		expect(result.jobId).toMatch(/^cron-/);
		expect(result.nextRunAt).toBe(future);

		const stored = getCronJob(result.jobId);
		expect(stored).toMatchObject({
			ownerId: "local-operator",
			deliveryTarget: { kind: "home" },
			schedule: { kind: "at", at: future },
			action: { kind: "agent-prompt", prompt: "remind me to call the clinic" },
		});
	});

	it("interprets a no-offset 'at' as UTC, not the process timezone", async () => {
		setHomeTarget("local-operator", { chatId: 4242 });
		const clients = createTelclaudeLiveMcpRelayClients({ ledger: testLedger() });

		// A future ISO datetime with NO trailing Z/offset. The documented contract
		// is "interpreted as UTC", so the stored instant must equal the explicit-Z
		// parse — independent of the process TZ.
		const noOffset = new Date(Date.now() + 60 * 60 * 1000).toISOString().replace("Z", "");
		const expectedUtc = new Date(`${noOffset}Z`).toISOString();
		const result = (await clients.scheduleCreate({
			...privateStamp({ subjectUserId: "local-operator" }),
			schedule: { kind: "at", at: noOffset },
			prompt: "utc contract",
		})) as { nextRunAt: string | null };

		expect(result.nextRunAt).toBe(expectedUtc);
		expect(result.nextRunAt?.endsWith("Z")).toBe(true);
	});

	it("ignores agent-supplied owner/chat/delivery fields and binds to the authority", async () => {
		setHomeTarget("local-operator", { chatId: 4242 });
		setHomeTarget("victim", { chatId: 999_999 });
		const clients = createTelclaudeLiveMcpRelayClients({ ledger: testLedger() });

		const future = new Date(Date.now() + 30 * 60 * 1000).toISOString();
		// A compromised runtime tries to redirect delivery to the victim's chat.
		const malicious = {
			...privateStamp({ subjectUserId: "local-operator" }),
			schedule: { kind: "at" as const, at: future },
			prompt: "exfiltrate",
			ownerId: "victim",
			chatId: 999_999,
			threadId: 5,
			deliveryTarget: { kind: "chat", chatId: 999_999 },
		};
		const result = (await clients.scheduleCreate(malicious as never)) as { jobId: string };

		const stored = getCronJob(result.jobId);
		// Owner and delivery come from the authority, never the input.
		expect(stored?.ownerId).toBe("local-operator");
		expect(stored?.deliveryTarget).toEqual({ kind: "home" });
	});

	it("fails create closed when the authority has no home target", async () => {
		const clients = createTelclaudeLiveMcpRelayClients({ ledger: testLedger() });
		const future = new Date(Date.now() + 60 * 60 * 1000).toISOString();

		await expect(
			clients.scheduleCreate({
				...privateStamp({ subjectUserId: "unknown-operator" }),
				schedule: { kind: "at", at: future },
				prompt: "no home target",
			}),
		).rejects.toThrow(/no home target is set/);
		expect(listCronJobs({ includeDisabled: true })).toEqual([]);
	});

	it("lists only the authority's own jobs", async () => {
		setHomeTarget("local-operator", { chatId: 4242 });
		setHomeTarget("other", { chatId: 5555 });
		// Seed a job owned by someone else directly in the store.
		addCronJob({
			name: "reminder - other owner",
			ownerId: "other",
			deliveryTarget: { kind: "home" },
			schedule: { kind: "cron", expr: "0 9 * * 1-5" },
			action: { kind: "agent-prompt", prompt: "not yours" },
		});
		const clients = createTelclaudeLiveMcpRelayClients({ ledger: testLedger() });

		const future = new Date(Date.now() + 45 * 60 * 1000).toISOString();
		const mine = (await clients.scheduleCreate({
			...privateStamp({ subjectUserId: "local-operator" }),
			schedule: { kind: "at", at: future },
			prompt: "mine",
		})) as { jobId: string };

		const listed = (await clients.scheduleList({
			...privateStamp({ subjectUserId: "local-operator" }),
			limit: 20,
		})) as { jobs: Array<{ jobId: string }> };

		expect(listed.jobs.map((job) => job.jobId)).toEqual([mine.jobId]);
	});

	it("returns an empty list when the authority has no home target", async () => {
		setHomeTarget("other", { chatId: 5555 });
		addCronJob({
			name: "reminder - other owner",
			ownerId: "other",
			deliveryTarget: { kind: "home" },
			schedule: { kind: "every", everyMs: 3_600_000 },
			action: { kind: "agent-prompt", prompt: "not yours" },
		});
		const clients = createTelclaudeLiveMcpRelayClients({ ledger: testLedger() });

		const listed = (await clients.scheduleList({
			...privateStamp({ subjectUserId: "no-home" }),
			limit: 20,
		})) as { jobs: unknown[] };
		expect(listed.jobs).toEqual([]);
	});

	it("cancels an owned job but denies cancelling another owner's job", async () => {
		setHomeTarget("local-operator", { chatId: 4242 });
		setHomeTarget("other", { chatId: 5555 });
		const others = addCronJob({
			name: "reminder - other owner",
			ownerId: "other",
			deliveryTarget: { kind: "home" },
			schedule: { kind: "cron", expr: "0 9 * * *" },
			action: { kind: "agent-prompt", prompt: "not yours" },
		});
		const clients = createTelclaudeLiveMcpRelayClients({ ledger: testLedger() });

		const future = new Date(Date.now() + 45 * 60 * 1000).toISOString();
		const mine = (await clients.scheduleCreate({
			...privateStamp({ subjectUserId: "local-operator" }),
			schedule: { kind: "at", at: future },
			prompt: "mine",
		})) as { jobId: string };

		// Cancelling the other owner's job is denied with a generic not-found.
		await expect(
			clients.scheduleCancel({
				...privateStamp({ subjectUserId: "local-operator" }),
				jobId: others.id,
			}),
		).rejects.toThrow(/not found/);
		expect(getCronJob(others.id)).not.toBeNull();

		const cancelled = (await clients.scheduleCancel({
			...privateStamp({ subjectUserId: "local-operator" }),
			jobId: mine.jobId,
		})) as { cancelled: boolean };
		expect(cancelled.cancelled).toBe(true);
		expect(getCronJob(mine.jobId)).toBeNull();
	});

	it("rejects a past 'at' timestamp and malformed cron/every schedules", async () => {
		setHomeTarget("local-operator", { chatId: 4242 });
		const clients = createTelclaudeLiveMcpRelayClients({ ledger: testLedger() });
		const stamp = privateStamp({ subjectUserId: "local-operator" });

		await expect(
			clients.scheduleCreate({
				...stamp,
				schedule: { kind: "at", at: new Date(Date.now() - 1000).toISOString() },
				prompt: "past",
			}),
		).rejects.toThrow(/must be in the future/);

		await expect(
			clients.scheduleCreate({
				...stamp,
				schedule: { kind: "at", at: "not-a-timestamp" },
				prompt: "bad",
			}),
		).rejects.toThrow(/ISO-8601/);

		await expect(
			clients.scheduleCreate({
				...stamp,
				schedule: { kind: "cron", expr: "not a cron" },
				prompt: "bad cron",
			}),
		).rejects.toThrow(/schedule denied/);

		await expect(
			clients.scheduleCreate({
				...stamp,
				schedule: { kind: "every", everyMs: 1000 },
				prompt: "too frequent",
			}),
		).rejects.toThrow(/at least/);

		expect(listCronJobs({ includeDisabled: true })).toEqual([]);
	});

	it("routes household schedule tools to confirmation-bound reminder proposals without cron rows", async () => {
		const clients = createTelclaudeLiveMcpRelayClients({
			ledger: testLedger(),
			householdReminderConfig: householdConfig,
		});
		const stamp = householdStamp();
		const firstTime = futureJerusalemMinute(60);
		const created = (await clients.scheduleCreate({
			...stamp,
			schedule: { kind: "at", at: firstTime },
			prompt: "להביא מסמכים",
			label: "מרפאה",
		})) as {
			reminderId: string;
			status: string;
			confirmationRequired: boolean;
			confirmationPrompt: string;
		};

		expect(created).toMatchObject({
			status: "pending_confirmation",
			confirmationRequired: true,
		});
		expect(created.confirmationPrompt).toContain("1. אישור");
		expect(created.confirmationPrompt).toContain("2. ביטול");
		expect(listCronJobs({ includeDisabled: true })).toEqual([]);

		const listed = (await clients.scheduleList({ ...stamp, limit: 20 })) as {
			reminders: Array<{ reminderId: string; status: string }>;
		};
		expect(listed.reminders).toEqual([
			expect.objectContaining({
				reminderId: created.reminderId,
				status: "pending_confirmation",
			}),
		]);

		const context = resolveHouseholdReminderContext(stamp, householdConfig);
		expect(context).not.toBeNull();
		if (!context) throw new Error("test household reminder context missing");
		const pending = getPendingHouseholdReminderProposal(context.authority, context.binding);
		expect(pending?.proposalHash).toMatch(/^sha256:/);
		if (!pending) throw new Error("test household reminder proposal missing");
		expect(
			confirmHouseholdReminderProposal({
				proposalRef: pending.ref,
				...context,
			}),
		).toMatchObject({ ok: true, reminder: { status: "scheduled" } });

		const updated = (await clients.scheduleUpdate({
			...stamp,
			jobId: created.reminderId,
			schedule: { kind: "at", at: futureJerusalemMinute(120) },
			prompt: "להביא מסמכים והפניה",
		})) as { status: string; confirmationPrompt: string };
		expect(updated.status).toBe("paused_confirmation");
		expect(updated.confirmationPrompt).toContain("1. אישור");
		const expectDisabledWakeUp = () => {
			const jobs = listCronJobs({ includeDisabled: true });
			expect(jobs).toHaveLength(1);
			expect(jobs[0]).toMatchObject({
				id: `household-reminder:${created.reminderId}`,
				enabled: false,
				nextRunAtMs: null,
				ownerId: null,
				deliveryTarget: { kind: "origin" },
				action: {
					kind: "household-reminder",
					reminderId: created.reminderId,
					revision: 1,
				},
			});
			expect(jobs[0]?.action).toEqual({
				kind: "household-reminder",
				reminderId: created.reminderId,
				revision: 1,
			});
			expect(JSON.stringify(jobs[0])).not.toMatch(/להביא|תזכורת:|body|chatId|channel|subject/);
		};
		expectDisabledWakeUp();
		const updateProposal = getPendingHouseholdReminderProposal(context.authority, context.binding);
		if (!updateProposal) throw new Error("test household update proposal missing");
		expect(
			rejectHouseholdReminderProposal({
				proposalRef: updateProposal.ref,
				...context,
			}),
		).toMatchObject({ ok: true, reminder: { status: "scheduled" } });

		const cancelled = (await clients.scheduleCancel({
			...stamp,
			jobId: created.reminderId,
		})) as { status: string; confirmationPrompt: string };
		expect(cancelled.status).toBe("paused_confirmation");
		expect(cancelled.confirmationPrompt).toContain("לאשר את ביטול התזכורת");
		expectDisabledWakeUp();
	});

	it("directly cancels an appointment-derived reminder for the exact household authority", async () => {
		const clients = createTelclaudeLiveMcpRelayClients({
			ledger: testLedger(),
			householdReminderConfig: householdConfig,
		});
		const stamp = householdStamp();
		const context = resolveHouseholdReminderContext(stamp, householdConfig);
		if (!context) throw new Error("test household reminder context missing");
		const observationChars = ["8", "9", "a"] as const;
		let observationIndex = 0;
		const createDerived = () => {
			const observationChar = observationChars[observationIndex++];
			if (!observationChar) throw new Error("test appointment observation exhausted");
			return createAppointmentDerivedHouseholdReminder({
				...context,
				text: "תור אצל רופאת המשפחה",
				schedule: resolveJerusalemOneShot(futureJerusalemMinute(1_440)),
				observationHash: `sha256:${observationChar.repeat(64)}` as const,
				addresseeGender: context.addresseeGender,
			}).reminder;
		};
		const derived = createDerived();

		await expect(clients.scheduleCancel({ ...stamp, jobId: derived.id })).resolves.toMatchObject({
			reminderId: derived.id,
			status: "cancelled",
			confirmationRequired: false,
			message: "התזכורת בוטלה.",
		});
		expect(getPendingHouseholdReminderProposal(context.authority, context.binding)).toBeNull();

		const protectedDerived = createDerived();
		await expect(
			clients.scheduleCancel({
				...stamp,
				actorId: "household:whatsapp:parent-b",
				jobId: protectedDerived.id,
			}),
		).rejects.toThrow(/binding or consent is unavailable|context unavailable/i);
		expect(getHouseholdReminderForAuthority(protectedDerived.id, context.authority)?.status).toBe(
			"scheduled",
		);

		const subjectProtectedDerived = createDerived();
		await expect(
			clients.scheduleCancel({
				...stamp,
				subjectUserId: "household:parent-b",
				jobId: subjectProtectedDerived.id,
			}),
		).rejects.toThrow(/subject must equal memory source/i);
		expect(
			getHouseholdReminderForAuthority(subjectProtectedDerived.id, context.authority)?.status,
		).toBe("scheduled");
	});

	it("declines recurring household input and keeps private schedule behavior unchanged", async () => {
		const clients = createTelclaudeLiveMcpRelayClients({
			ledger: testLedger(),
			householdReminderConfig: householdConfig,
		});
		await expect(
			clients.scheduleCreate({
				...householdStamp(),
				schedule: { kind: "every", everyMs: 86_400_000 },
				prompt: "לקחת תרופה",
			}),
		).rejects.toThrow("אני יכול לקבוע תזכורת חד-פעמית");

		setHomeTarget("local-operator", { chatId: 4242 });
		const privateResult = (await clients.scheduleCreate({
			...privateStamp({ subjectUserId: "local-operator" }),
			schedule: { kind: "at", at: new Date(Date.now() + 3_600_000).toISOString() },
			prompt: "private unchanged",
		})) as { jobId: string };
		expect(getCronJob(privateResult.jobId)?.action).toEqual({
			kind: "agent-prompt",
			prompt: "private unchanged",
		});
		await expect(
			clients.scheduleUpdate({
				...privateStamp(),
				jobId: privateResult.jobId,
				schedule: { kind: "at", at: new Date(Date.now() + 7_200_000).toISOString() },
				prompt: "must not mutate",
			}),
		).rejects.toThrow(/only for household/i);
		expect(getCronJob(privateResult.jobId)?.action).toEqual({
			kind: "agent-prompt",
			prompt: "private unchanged",
		});
	});

	it("denies tc_schedule_create without schedule.write and tc_schedule_list without schedule.read", async () => {
		const ledger = testLedger();
		const clients = createTelclaudeLiveMcpRelayClients({
			ledger,
			// Resolver that would otherwise succeed — the scope gate must fire first.
			resolveScheduleOwner: () => ({ ownerId: "local-operator" }),
		});

		// schedule.write missing → create denied, fail-closed.
		const noWriteBridge = createTelclaudeMcpBridge(
			authority({ capabilityScopes: ["schedule.read"] }),
			bridgeDeps(clients),
		);
		await expect(
			noWriteBridge.tc_schedule_create({
				schedule: { kind: "at", at: new Date(Date.now() + 3_600_000).toISOString() },
				prompt: "denied",
			}),
		).rejects.toThrow("capability scope denied: schedule.write");

		// schedule.read missing → list denied, fail-closed.
		const noReadBridge = createTelclaudeMcpBridge(
			authority({ capabilityScopes: ["schedule.write"] }),
			bridgeDeps(clients),
		);
		await expect(noReadBridge.tc_schedule_list({})).rejects.toThrow(
			"capability scope denied: schedule.read",
		);

		// No capability scopes at all → both denied (verify-live canary shape).
		const noScopeBridge = createTelclaudeMcpBridge(authority({}), bridgeDeps(clients));
		await expect(noScopeBridge.tc_schedule_cancel({ jobId: "cron-x" })).rejects.toThrow(
			"capability scope denied: schedule.write",
		);
		await expect(
			noScopeBridge.tc_schedule_update({
				jobId: "reminder-x",
				schedule: { kind: "at", at: "2026-08-01T09:00" },
				prompt: "denied",
			}),
		).rejects.toThrow("capability scope denied: schedule.write");
	});

	it("retires the relay-side conversational-cron regex (no relay interception)", () => {
		const repoRoot = path.resolve(fileURLToPath(new URL(".", import.meta.url)), "../..");
		// The module that used to intercept "every weekday at 9am ..." in the relay
		// is gone — scheduling now goes through tc_schedule_* served MCP tools.
		expect(fs.existsSync(path.join(repoRoot, "src/telegram/conversational-cron.ts"))).toBe(false);
		const autoReplySrc = fs.readFileSync(path.join(repoRoot, "src/telegram/auto-reply.ts"), "utf8");
		expect(autoReplySrc).not.toContain("conversational-cron");
		expect(autoReplySrc).not.toContain("tryHandleConversationalCronRequest");
		// The old short-circuit reply ("Scheduled `<id>` for ...") must not survive.
		expect(autoReplySrc).not.toMatch(/Scheduled `\$\{job\.id\}`/);
	});

	it("strips agent-supplied authority fields at the bridge before the schedule client sees them", async () => {
		const seen: TelclaudeMcpAuthorityStamp[] = [];
		const resolveScheduleOwner: ScheduleOwnerResolver = (request) => {
			seen.push(request);
			return { ownerId: "local-operator" };
		};
		setHomeTarget("local-operator", { chatId: 4242 });
		const clients = createTelclaudeLiveMcpRelayClients({
			ledger: testLedger(),
			resolveScheduleOwner,
		});
		const bridge = createTelclaudeMcpBridge(
			authority({ actorId: "operator", capabilityScopes: ["schedule.write"] }),
			bridgeDeps(clients),
		);

		// The agent attempts to assert a different actorId/profileId; the bridge
		// rejects any client-supplied authority field outright.
		await expect(
			bridge.tc_schedule_create({
				schedule: { kind: "at", at: new Date(Date.now() + 3_600_000).toISOString() },
				prompt: "x",
				actorId: "attacker",
			}),
		).rejects.toThrow("MCP clients may not supply MCP authority field: actorId");
		expect(seen).toEqual([]);
	});
});

function testLedger() {
	return createTelclaudeMcpSideEffectLedger({
		makeRef: makeRefs(),
		verifyApproval: async () => ({
			ok: false,
			code: "approval_required",
			reason: "test verifier not used by schedule tools",
		}),
	});
}

function makeRefs(): () => string {
	let ref = 0;
	return () => `effect-test-${++ref}`;
}

function privateStamp(
	overrides: Partial<TelclaudeMcpAuthorityStamp> = {},
): TelclaudeMcpAuthorityStamp {
	return {
		actorId: "operator",
		subjectUserId: "local-operator",
		profileId: "ops",
		domain: "private",
		memorySource: "telegram:ops",
		writableNamespace: "private:ops",
		endpointId: "endpoint-private",
		networkNamespace: "netns-private",
		...overrides,
	};
}

function householdStamp(): TelclaudeMcpAuthorityStamp & { subjectUserId: string } {
	return {
		actorId: "household:whatsapp:parent-a",
		subjectUserId: "household:parent-a",
		profileId: "parent-a",
		domain: "household",
		memorySource: "household:parent-a",
		writableNamespace: "household:parent-a",
		endpointId: "endpoint-household",
		networkNamespace: "netns-household",
	};
}

function futureJerusalemMinute(minutesFromNow: number): string {
	const parts = new Intl.DateTimeFormat("en-CA", {
		timeZone: "Asia/Jerusalem",
		year: "numeric",
		month: "2-digit",
		day: "2-digit",
		hour: "2-digit",
		minute: "2-digit",
		hourCycle: "h23",
	}).formatToParts(Date.now() + minutesFromNow * 60_000);
	const value = (name: string) => parts.find((part) => part.type === name)?.value;
	return `${value("year")}-${value("month")}-${value("day")}T${value("hour")}:${value("minute")}`;
}

const householdConfig = {
	householdReminders: { enabled: true },
	profiles: [
		{
			id: "parent-a",
			label: "Parent A",
			allowedSkills: [],
			providerScopes: ["clalit"],
			capabilityScopes: ["schedule.read", "schedule.write"],
			outboundChannels: ["whatsapp"],
			whatsappHouseholdBindings: [
				{
					bindingId: "parent-a",
					remindersEnabled: true,
					addresseeGender: "f",
					address: "whatsapp:+15557654321",
					replyAddress: "whatsapp:+15557654321",
					displayName: "Parent A",
					subjectUserId: "household:parent-a",
					reminderConsent: {
						state: "granted",
						ceremonyVersion: "phase0.v1",
						ceremonyHash: `sha256:${"a".repeat(64)}`,
						verifiedChannelHash:
							"sha256:a0237ae1db3c517ae525a8b60cb1b956bf87d4369f0b7533204cd7706236bce6",
						categories: {
							proactiveDelivery: true,
							scheduleManagement: true,
							retentionDisclosure: true,
						},
						recordedAt: "2026-07-17T09:00:00.000Z",
						operatorId: "operator:phase0-admin",
					},
				},
			],
		},
	],
} as TelclaudeConfig;

function authority(overrides: Partial<TelclaudeMcpAuthority>): TelclaudeMcpAuthority {
	return {
		actorId: "operator",
		subjectUserId: "local-operator",
		profileId: "ops",
		domain: "private",
		memorySource: "telegram:ops",
		writableNamespace: "private:ops",
		providerScopes: [],
		outboundChannels: [],
		endpointId: "endpoint-private",
		networkNamespace: "netns-private",
		...overrides,
	};
}

/**
 * Build the bridge dependency surface from the schedule-relevant relay clients.
 * Non-schedule tools throw if invoked, which is fine: these tests only exercise
 * the three schedule tools.
 */
function bridgeDeps(
	clients: Pick<
		TelclaudeMcpBridgeDependencies,
		"scheduleCreate" | "scheduleList" | "scheduleCancel" | "scheduleUpdate"
	>,
): TelclaudeMcpBridgeDependencies {
	const fail = async (): Promise<never> => {
		throw new Error("not used by schedule tests");
	};
	return {
		providerRead: fail,
		providerPrepareWrite: fail,
		providerExecuteWrite: fail,
		memorySearch: fail,
		memoryWrite: fail,
		attachmentGet: fail,
		outboundPrepare: fail,
		outboundExecute: fail,
		auditNote: fail,
		webFetch: fail,
		webSearch: fail,
		imageGenerate: fail,
		tts: fail,
		skillRequest: fail,
		scheduleCreate: clients.scheduleCreate,
		scheduleList: clients.scheduleList,
		scheduleCancel: clients.scheduleCancel,
		scheduleUpdate: clients.scheduleUpdate,
	};
}
