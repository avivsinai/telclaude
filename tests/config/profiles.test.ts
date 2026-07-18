import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

describe("operator profile resolution", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-profiles-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		const { resetDatabase } = await import("../../src/storage/db.js");
		resetDatabase();
	});

	afterEach(async () => {
		const { resetDatabase } = await import("../../src/storage/db.js");
		resetDatabase();
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) {
			delete process.env.TELCLAUDE_DATA_DIR;
		} else {
			process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
		}
	});

	it("resolves unbound chats to the implicit default profile", async () => {
		const { resolveChatProfile } = await import("../../src/config/profiles.js");
		const resolved = resolveChatProfile(123, { profiles: [] } as never);

		expect(resolved.profile).toMatchObject({
			id: "default",
			label: "Default",
			implicit: true,
		});
		expect(resolved.warnings).toEqual([]);
	});

	it("resolves chat bindings to configured profiles", async () => {
		const { setChatActiveProfileId } = await import("../../src/config/sessions.js");
		const { resolveChatProfile } = await import("../../src/config/profiles.js");
		setChatActiveProfileId(123, "engineer", 1_234);

		const resolved = resolveChatProfile(123, {
			profiles: [
				{
					id: "engineer",
					label: "Engineer",
					allowedSkills: ["telegram-reply"],
					providerScopes: ["google"],
					capabilityScopes: ["web.search"],
					outboundChannels: ["whatsapp"],
				},
			],
		} as never);

		expect(resolved.profile).toMatchObject({
			id: "engineer",
			label: "Engineer",
			implicit: false,
			allowedSkills: ["telegram-reply"],
			providerScopes: ["google"],
			capabilityScopes: ["web.search"],
			outboundChannels: ["whatsapp"],
		});
	});

	it("falls back to default when a stored binding is stale", async () => {
		const { setChatActiveProfileId } = await import("../../src/config/sessions.js");
		const { resolveChatProfile } = await import("../../src/config/profiles.js");
		setChatActiveProfileId(123, "missing", 1_234);

		const resolved = resolveChatProfile(123, { profiles: [] } as never);

		expect(resolved.profile.id).toBe("default");
		expect(resolved.missingProfileId).toBe("missing");
		expect(resolved.warnings[0]).toContain("missing");
	});

	it("resolves household WhatsApp senders to disjoint profile and subject bindings", async () => {
		const { resolveWhatsAppHouseholdBinding } = await import("../../src/config/profiles.js");
		const reminderConsent = {
			state: "granted",
			ceremonyVersion: "phase0.v1",
			ceremonyHash: `sha256:${"c".repeat(64)}`,
			verifiedChannelHash: `sha256:${"d".repeat(64)}`,
			categories: {
				proactiveDelivery: true,
				scheduleManagement: true,
				retentionDisclosure: true,
			},
			recordedAt: "2026-07-17T09:00:00.000Z",
			operatorId: "operator:phase0-admin",
		};
		const cfg = {
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
							address: "whatsapp:+15551234567",
							replyAddress: "whatsapp:+15551234567",
							displayName: "Parent A",
							subjectUserId: "household:parent-a",
							reminderConsent,
						},
					],
				},
				{
					id: "parent-b",
					label: "Parent B",
					allowedSkills: [],
					providerScopes: ["clalit"],
					capabilityScopes: ["schedule.read", "schedule.write"],
					outboundChannels: ["whatsapp"],
					whatsappHouseholdBindings: [
						{
							bindingId: "parent-b",
							address: "whatsapp:+15557654321",
							replyAddress: "whatsapp:+15557654321",
							displayName: "Parent B",
							subjectUserId: "household:parent-b",
						},
					],
				},
			],
		} as never;

		expect(resolveWhatsAppHouseholdBinding("+15551234567", cfg)).toMatchObject({
			bindingId: "parent-a",
			actorId: "household:whatsapp:parent-a",
			subjectUserId: "household:parent-a",
			memorySource: "household:parent-a",
			writableNamespace: "household:parent-a",
			domain: "household",
			reminderConsent,
			profile: { id: "parent-a" },
		});
		expect(resolveWhatsAppHouseholdBinding("whatsapp:+15557654321", cfg)).toMatchObject({
			bindingId: "parent-b",
			actorId: "household:whatsapp:parent-b",
			subjectUserId: "household:parent-b",
			memorySource: "household:parent-b",
			profile: { id: "parent-b" },
		});
		expect(resolveWhatsAppHouseholdBinding("whatsapp:+15550000000", cfg)).toBeNull();
	});
});
