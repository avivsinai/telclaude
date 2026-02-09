import crypto from "node:crypto";
import type { Command } from "commander";
import { fetchMemorySnapshot, proposeMemory, quarantineMemory } from "../agent/memory-client.js";
import type { MemoryCategory, TrustLevel } from "../memory/types.js";

export function registerMemoryCommands(program: Command): void {
	const memory = program.command("memory").description("Memory management commands");

	memory
		.command("read")
		.description("Read memory entries from the relay")
		.option(
			"--categories <csv>",
			"Comma-separated categories (profile,interests,meta,threads,posts)",
		)
		.option("--trust <csv>", "Comma-separated trust levels (trusted,untrusted,quarantined)")
		.option("--limit <n>", "Max entries to return", "50")
		.option("--chat-id <id>", "Chat ID for scoping", process.env.TELCLAUDE_CHAT_ID)
		.action(
			async (opts: { categories?: string; trust?: string; limit?: string; chatId?: string }) => {
				try {
					const result = await fetchMemorySnapshot({
						categories: opts.categories
							?.split(",")
							.map((s) => s.trim())
							.filter(Boolean) as MemoryCategory[],
						trust: opts.trust
							?.split(",")
							.map((s) => s.trim())
							.filter(Boolean) as TrustLevel[],
						limit: opts.limit ? Number.parseInt(opts.limit, 10) : undefined,
						chatId: opts.chatId,
					});
					console.log(JSON.stringify(result, null, 2));
				} catch (err) {
					console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
					process.exitCode = 1;
				}
			},
		);

	memory
		.command("write")
		.description("Write a memory entry via the relay")
		.argument("<content>", "Memory content (max 500 chars)")
		.option("--category <cat>", "Memory category", "meta")
		.option("--id <id>", "Entry ID (auto-generated if omitted)")
		.option("--user-id <id>", "User ID for attribution")
		.option("--chat-id <id>", "Chat ID for scoping", process.env.TELCLAUDE_CHAT_ID)
		.action(
			async (
				content: string,
				opts: { category?: string; id?: string; userId?: string; chatId?: string },
			) => {
				try {
					const entryId = opts.id ?? `mem-${crypto.randomUUID().slice(0, 12)}`;
					const result = await proposeMemory(
						[
							{
								id: entryId,
								category: (opts.category ?? "meta") as MemoryCategory,
								content,
							},
						],
						{ userId: opts.userId, chatId: opts.chatId },
					);
					console.log(JSON.stringify({ ok: true, id: entryId, ...result }, null, 2));
				} catch (err) {
					console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
					process.exitCode = 1;
				}
			},
		);

	memory
		.command("quarantine")
		.description("Quarantine a post idea for Moltbook (Telegram only)")
		.argument("<content>", "Post idea content")
		.option("--id <id>", "Entry ID (auto-generated if omitted)")
		.option("--user-id <id>", "User ID for attribution")
		.option("--chat-id <id>", "Chat ID for scoping", process.env.TELCLAUDE_CHAT_ID)
		.action(async (content: string, opts: { id?: string; userId?: string; chatId?: string }) => {
			try {
				const entryId = opts.id ?? `mem-${crypto.randomUUID().slice(0, 12)}`;
				const result = await quarantineMemory(entryId, content, {
					userId: opts.userId,
					chatId: opts.chatId,
				});
				console.log(JSON.stringify({ ok: true, ...result }, null, 2));
			} catch (err) {
				console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
				process.exitCode = 1;
			}
		});

	memory
		.command("gc")
		.description("Garbage-collect old memory entries over quota")
		.option("--dry-run", "Show what would be deleted without deleting")
		.action(async (opts: { dryRun?: boolean }) => {
			try {
				const result = await fetchMemorySnapshot({ limit: 500 });
				const count = result.entries.length;
				console.log(`Total entries: ${count}`);
				if (opts.dryRun) {
					console.log("(dry run - no deletions)");
				} else {
					console.log("Use --dry-run to preview. Manual cleanup not yet implemented.");
				}
			} catch (err) {
				console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
				process.exitCode = 1;
			}
		});
}
