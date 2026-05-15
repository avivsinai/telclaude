import type { Command } from "commander";
import { runCuratorScan } from "../curator/actions.js";
import { decideCuratorItem, getCuratorItem, listCuratorItems } from "../curator/store.js";
import type { CuratorItem, CuratorItemStatus } from "../curator/types.js";

function formatItem(item: CuratorItem): string {
	return [
		`${item.shortId} ${item.severity.toUpperCase()} ${item.kind} ${item.status}`,
		`  ${item.title}`,
		`  ${item.summary}`,
		`  entity: ${item.entityRef}`,
	].join("\n");
}

export function registerCuratorCommand(program: Command): void {
	const curator = program
		.command("curator")
		.description("Review local Curator suggestions for safer, more useful automation");

	curator
		.command("scan")
		.description("Scan local telclaude state for reviewable suggestions")
		.option("--json", "Output as JSON")
		.action((opts: { json?: boolean }) => {
			const result = runCuratorScan({ producerKind: "system" });
			if (opts.json) {
				console.log(JSON.stringify(result, null, 2));
				return;
			}
			console.log(
				`Curator scan created/updated ${result.createdOrUpdated} item(s); ${result.openItems} open.`,
			);
		});

	curator
		.command("list")
		.description("List Curator suggestions")
		.option("--status <status>", "open, accepted, rejected, expired, or all", "open")
		.option("--json", "Output as JSON")
		.action((opts: { status?: string; json?: boolean }) => {
			const status = opts.status === "all" ? "all" : (opts.status ?? "open");
			if (!["open", "accepted", "rejected", "expired", "all"].includes(status)) {
				console.error("Error: --status must be open, accepted, rejected, expired, or all");
				process.exitCode = 1;
				return;
			}
			const items = listCuratorItems({ status: status as CuratorItemStatus | "all" });
			if (opts.json) {
				console.log(JSON.stringify({ items }, null, 2));
				return;
			}
			if (items.length === 0) {
				console.log("No curator items.");
				return;
			}
			console.log(items.map(formatItem).join("\n\n"));
		});

	curator
		.command("show")
		.description("Show one Curator suggestion")
		.argument("<id>", "Curator id or short id")
		.option("--json", "Output as JSON")
		.action((id: string, opts: { json?: boolean }) => {
			const item = getCuratorItem(id);
			if (!item) {
				console.error(`Error: unknown curator item '${id}'`);
				process.exitCode = 1;
				return;
			}
			if (opts.json) {
				console.log(JSON.stringify({ item }, null, 2));
				return;
			}
			console.log(formatItem(item));
		});

	curator
		.command("accept")
		.description("Accept a Curator suggestion without performing the privileged action")
		.argument("<id>", "Curator id or short id")
		.option("--actor <id>", "Actor id for audit", "cli:operator")
		.action((id: string, opts: { actor?: string }) => {
			const item = decideCuratorItem({
				id,
				status: "accepted",
				actor: opts.actor ?? "cli:operator",
			});
			if (!item) {
				console.error(`Error: unknown curator item '${id}'`);
				process.exitCode = 1;
				return;
			}
			console.log(`Accepted ${item.shortId}. Next action remains manual: ${item.entityRef}`);
		});

	curator
		.command("reject")
		.description("Reject a Curator suggestion")
		.argument("<id>", "Curator id or short id")
		.option("--actor <id>", "Actor id for audit", "cli:operator")
		.option("--reason <text>", "Optional decision reason")
		.action((id: string, opts: { actor?: string; reason?: string }) => {
			const item = decideCuratorItem({
				id,
				status: "rejected",
				actor: opts.actor ?? "cli:operator",
				...(opts.reason ? { reason: opts.reason } : {}),
			});
			if (!item) {
				console.error(`Error: unknown curator item '${id}'`);
				process.exitCode = 1;
				return;
			}
			console.log(`Rejected ${item.shortId}.`);
		});
}
