// Dashboard UI — vanilla JS, no frameworks. Served same-origin from /.
// Keep this dependency-free; the server owns all sensitive filtering.

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

const state = {
	authed: false,
	activeTab: "sessions",
};

function node(tag, className, text) {
	const el = document.createElement(tag);
	if (className) el.className = className;
	if (text !== undefined && text !== null) el.textContent = String(text);
	return el;
}

function clear(el) {
	el.replaceChildren();
}

function setText(sel, value) {
	const el = $(sel);
	if (el) el.textContent = value;
}

function setAuthed(v) {
	state.authed = v;
	$("#login-card").hidden = v;
	$("#main-panels").hidden = !v;
	$("#logout-btn").hidden = !v;
	$("#refresh-btn").hidden = !v;
	$("#session-indicator").textContent = v ? "signed in" : "not signed in";
	$("#session-indicator").classList.toggle("pill-ok", v);
	$("#session-indicator").classList.toggle("pill-muted", !v);
}

async function api(path, opts = {}) {
	const res = await fetch(path, {
		method: opts.method ?? "GET",
		credentials: "same-origin",
		headers: {
			accept: "application/json",
			...(opts.body ? { "content-type": "application/json" } : {}),
		},
		body: opts.body ? JSON.stringify(opts.body) : undefined,
	});
	let body;
	try {
		body = await res.json();
	} catch {
		body = null;
	}
	if (res.status === 401) {
		setAuthed(false);
		return { ok: false, error: "authentication required", status: 401, body };
	}
	return { ok: res.ok, status: res.status, body };
}

function pillClassFor(status) {
	if (["ok", "healthy", "success", "completed", "active", "enabled"].includes(status)) {
		return "pill pill-ok";
	}
	if (
		["degraded", "warn", "warning", "unknown", "idle", "queued", "running", "blocked"].includes(
			status,
		)
	) {
		return "pill pill-warn";
	}
	if (
		["unhealthy", "unreachable", "auth_expired", "error", "failed", "timeout", "stale"].includes(
			status,
		)
	) {
		return "pill pill-bad";
	}
	return "pill pill-muted";
}

function fmtTs(v) {
	if (v == null) return "-";
	const d = typeof v === "number" ? new Date(v) : new Date(String(v));
	if (Number.isNaN(d.getTime())) return "-";
	return d.toISOString().replace("T", " ").slice(0, 19);
}

function fmtDuration(ms) {
	if (ms == null) return "-";
	if (ms < 1000) return `${Math.max(0, Math.round(ms))}ms`;
	const sec = Math.round(ms / 1000);
	if (sec < 60) return `${sec}s`;
	const min = Math.round(sec / 60);
	if (min < 60) return `${min}m`;
	return `${Math.round(min / 60)}h`;
}

function appendPill(parent, status, label = status) {
	const pill = node("span", pillClassFor(status), label);
	parent.append(pill);
	return pill;
}

function renderEmpty(parent, text, tag = "li") {
	const item = node(tag, "muted", text);
	parent.append(item);
}

function renderTable(tbody, rows, renderCells, emptyText, colSpan) {
	clear(tbody);
	if (!rows || rows.length === 0) {
		const tr = node("tr");
		const td = node("td", "muted", emptyText);
		td.colSpan = colSpan;
		tr.append(td);
		tbody.append(tr);
		return;
	}
	for (const row of rows) {
		const tr = node("tr");
		for (const cell of renderCells(row)) {
			const td = node("td");
			if (cell instanceof Node) td.append(cell);
			else td.textContent = cell == null ? "-" : String(cell);
			tr.append(td);
		}
		tbody.append(tr);
	}
}

function activateTab(tab) {
	state.activeTab = tab;
	for (const btn of $$(".tab-btn")) {
		const active = btn.dataset.tab === tab;
		btn.setAttribute("aria-selected", String(active));
		btn.classList.toggle("is-active", active);
	}
	for (const panel of $$(".tab-panel")) {
		panel.hidden = panel.dataset.panel !== tab;
	}
	if (state.authed) refreshActiveTab();
}

async function renderHealth() {
	const res = await api("/api/health");
	if (!res.ok) return;
	const snap = res.body?.snapshot;
	if (!snap) return;
	const overall = $("#overall-health");
	overall.textContent = `${snap.overallStatus} · ${snap.issueCount} issue(s)`;
	overall.className = pillClassFor(snap.overallStatus);
	setText("#health-collected", `updated ${fmtTs(snap.collectedAtMs)}`);

	const list = $("#health-items");
	clear(list);
	for (const item of snap.items ?? []) {
		const li = node("li", "item");
		const left = node("span", "item-label", item.label);
		const right = node("span", "item-row");
		appendPill(right, item.status);
		const detail = node("span", "item-detail", item.detail ?? "");
		right.append(detail);
		if (item.remediationCommand) {
			right.append(node("code", "command-chip", item.remediationCommand));
		}
		li.append(left, right);
		list.append(li);
	}
	if (!snap.items?.length) renderEmpty(list, "(no health signals)");
}

async function renderSessions() {
	const res = await api("/api/operator/sessions-runs?limit=50");
	if (!res.ok) return;
	const sessions = res.body?.sessions ?? [];
	const runs = res.body?.runs ?? [];
	setText("#sessions-summary", `${sessions.length} sessions · ${runs.length} recent runs`);
	renderTable(
		$("#sessions-table tbody"),
		sessions,
		(row) => [
			row.source,
			row.persona,
			row.model ?? "-",
			(() => {
				const wrap = node("span");
				appendPill(wrap, row.status);
				return wrap;
			})(),
			fmtTs(row.updatedAtMs),
			row.sessionRef,
			row.errorSummary ?? "-",
		],
		"(no tracked sessions)",
		7,
	);
	renderTable(
		$("#runs-table tbody"),
		runs,
		(row) => [
			row.id,
			row.source,
			row.persona,
			row.model ?? "-",
			(() => {
				const wrap = node("span");
				appendPill(wrap, row.status);
				return wrap;
			})(),
			fmtTs(row.startedAtMs),
			fmtTs(row.finishedAtMs),
			fmtDuration(row.durationMs),
			row.errorSummary ?? "-",
		],
		"(no recent runs)",
		9,
	);
}

async function renderLogs() {
	const level = $("#log-level").value;
	const component = $("#log-component").value.trim();
	const params = new URLSearchParams({ limit: "100" });
	if (level !== "all") params.set("level", level);
	if (component) params.set("component", component);
	const [logsRes, providerRes] = await Promise.all([
		api(`/api/operator/logs?${params.toString()}`),
		api("/api/operator/provider-health"),
	]);
	if (logsRes.ok) {
		const logs = logsRes.body?.entries ?? [];
		setText("#logs-summary", `${logs.length} log entries`);
		const list = $("#logs-list");
		clear(list);
		for (const entry of logs) {
			const li = node("li", "log-line");
			const meta = node("span", "log-meta", `${fmtTs(entry.timestamp)} ${entry.component}`);
			const levelPill = node("span", pillClassFor(entry.level), entry.level);
			const msg = node("span", "log-message", entry.message);
			li.append(meta, levelPill, msg);
			list.append(li);
		}
		if (!logs.length) renderEmpty(list, "(no matching logs)");
	}
	if (providerRes.ok) {
		const providers = providerRes.body?.providers ?? [];
		setText("#providers-summary", `${providers.length} providers`);
		const list = $("#provider-health-list");
		clear(list);
		for (const provider of providers) {
			const li = node("li", "item");
			li.append(node("span", "item-label", provider.id));
			const right = node("span", "item-row");
			appendPill(right, provider.status);
			right.append(node("span", "item-detail", `${provider.failureCount} issue(s)`));
			li.append(right);
			list.append(li);
		}
		if (!providers.length) renderEmpty(list, "(no providers configured)");

		const transitions = $("#provider-transitions-list");
		clear(transitions);
		for (const entry of providerRes.body?.transitions ?? []) {
			const li = node("li", "item");
			li.append(node("span", "item-label", `${fmtTs(entry.timestamp)} · ${entry.provider ?? "provider"}`));
			const right = node("span", "item-row");
			appendPill(right, entry.level);
			right.append(node("span", "item-detail", entry.message));
			li.append(right);
			transitions.append(li);
		}
		if (!providerRes.body?.transitions?.length) renderEmpty(transitions, "(no recent transitions)");
	}
}

async function renderJobs() {
	const status = $("#job-status").value;
	const params = new URLSearchParams({ limit: "50" });
	if (status !== "all") params.set("status", status);
	const res = await api(`/api/operator/background-jobs?${params.toString()}`);
	if (!res.ok) return;
	const jobs = res.body?.jobs ?? [];
	setText("#jobs-summary", `${jobs.length} background jobs`);
	renderTable(
		$("#jobs-table tbody"),
		jobs,
		(row) => [
			row.shortId,
			row.title,
			(() => {
				const wrap = node("span");
				appendPill(wrap, row.status);
				return wrap;
			})(),
			row.payloadKind,
			row.tier,
			fmtTs(row.createdAtMs),
			fmtTs(row.startedAtMs),
			row.errorSummary ?? "-",
			(() => {
				const wrap = node("span");
				if (row.canCancel) {
					const btn = node("button", "btn-small", "Cancel");
					btn.type = "button";
					btn.dataset.cancelJob = row.shortId;
					wrap.append(btn);
				} else {
					wrap.textContent = "-";
				}
				return wrap;
			})(),
		],
		"(no background jobs)",
		9,
	);
}

async function cancelJob(shortId) {
	const res = await api(`/api/operator/background-jobs/${encodeURIComponent(shortId)}/cancel`, {
		method: "POST",
	});
	if (!res.ok) {
		setText("#jobs-error", res.body?.error ?? "cancel failed");
		return;
	}
	setText("#jobs-error", res.body?.transitioned ? `cancelled ${shortId}` : "job was already terminal");
	await renderJobs();
}

async function renderCron() {
	const res = await api("/api/operator/cron");
	if (!res.ok) return;
	const jobs = res.body?.jobs ?? [];
	const summary = res.body?.summary;
	setText(
		"#cron-summary",
		summary
			? `${summary.enabledJobs}/${summary.totalJobs} enabled · ${summary.runningJobs} running · next ${fmtTs(summary.nextRunAtMs)}`
			: `${jobs.length} jobs`,
	);
	renderTable(
		$("#cron-table tbody"),
		jobs,
		(row) => [
			row.id,
			row.name,
			(() => {
				const wrap = node("span");
				appendPill(wrap, row.running ? "running" : row.enabled ? "enabled" : "disabled");
				return wrap;
			})(),
			row.schedule,
			row.actionSummary,
			row.delivery,
			fmtTs(row.nextRunAtMs),
			row.lastStatus ?? "-",
			row.lastErrorSummary ?? "-",
		],
		"(no cron jobs)",
		9,
	);
}

async function renderSocial() {
	const res = await api("/api/operator/social-queue");
	if (!res.ok) return;
	const pending = res.body?.pending ?? [];
	const promoted = res.body?.promoted ?? [];
	setText(
		"#social-summary",
		`${pending.length} pending · ${promoted.length} promoted · next: ${res.body?.nextOperatorAction ?? "-"}`,
	);
	renderTable(
		$("#social-pending-table tbody"),
		pending,
		(row) => [row.id, row.source, row.trust, row.status, fmtTs(row.createdAtMs), row.nextAction],
		"(no pending drafts)",
		6,
	);
	renderTable(
		$("#social-promoted-table tbody"),
		promoted,
		(row) => [row.id, row.source, row.status, fmtTs(row.promotedAtMs), row.nextAction],
		"(no promoted drafts waiting for heartbeat)",
		5,
	);
	const services = $("#social-services-list");
	clear(services);
	for (const svc of res.body?.services ?? []) {
		const li = node("li", "item");
		li.append(node("span", "item-label", `${svc.id} · ${svc.type}`));
		const right = node("span", "item-row");
		appendPill(right, svc.enabled ? "enabled" : "disabled");
		right.append(node("span", "item-detail", `heartbeat ${svc.heartbeatEnabled ? "on" : "off"}`));
		li.append(right);
		services.append(li);
	}
	if (!res.body?.services?.length) renderEmpty(services, "(no social services configured)");
}

async function renderPersonas() {
	const [personasRes, skillsRes, approvalsRes] = await Promise.all([
		api("/api/operator/personas"),
		api("/api/skills"),
		api("/api/approvals/allowlist"),
	]);
	if (personasRes.ok) {
		const body = personasRes.body;
		setText("#personas-summary", `security profile: ${body.securityProfile}`);
		renderPersonaBox("#private-persona", body.privatePersona);
		renderPersonaBox("#social-persona", body.socialPersona);
	}
	if (skillsRes.ok) {
		renderChips("#skills-active", skillsRes.body?.active ?? []);
		renderChips("#skills-drafts", skillsRes.body?.drafts ?? []);
	}
	if (approvalsRes.ok) {
		const entries = approvalsRes.body?.entries ?? [];
		setText("#approvals-summary", `${entries.length} allowlist entries`);
		renderTable(
			$("#approvals-table tbody"),
			entries,
			(row) => [
				row.userId,
				row.tier,
				row.toolKey,
				row.scope,
				fmtTs(row.grantedAt),
				row.expiresAt == null ? "(none)" : fmtTs(row.expiresAt),
			],
			"(no allowlist entries)",
			6,
		);
	}
}

function renderPersonaBox(sel, persona) {
	const box = $(sel);
	clear(box);
	if (!persona) {
		box.append(node("p", "muted", "(unavailable)"));
		return;
	}
	const head = node("div", "persona-head");
	head.append(node("strong", null, persona.source));
	appendPill(head, persona.status);
	box.append(head);
	const counts = persona.memoryCounts ?? {};
	box.append(
		node(
			"p",
			"muted",
			`profile ${counts.profile ?? 0} · interests ${counts.interests ?? 0} · meta ${counts.meta ?? 0}`,
		),
	);
	if (persona.summary) {
		box.append(node("p", "item-detail", persona.summary));
	}
	const facts = node("dl", "persona-facts");
	const addFact = (label, value) => {
		if (value == null || value === "") return;
		facts.append(node("dt", null, label), node("dd", null, String(value)));
	};
	addFact("profile", persona.profile?.claudeHome ?? persona.profile?.source);
	addFact(
		"agent",
		persona.agent
			? `${persona.agent.reachability} · ${persona.agent.source}${
					persona.agent.endpoint ? ` · ${persona.agent.endpoint}` : ""
				}`
			: null,
	);
	addFact(
		"skills",
		persona.skills
			? `${persona.skills.policy} · ${persona.skills.effectiveCount ?? 0} effective · ${
					persona.skills.activeCatalogCount ?? 0
				} catalog`
			: null,
	);
	addFact(
		"plugins",
		persona.plugins
			? `${persona.plugins.enabledCount ?? 0} enabled · ${persona.plugins.installedCount ?? 0} installed`
			: null,
	);
	addFact("filesystem", persona.filesystem?.summary);
	addFact("providers", persona.providers?.summary);
	if (persona.boundaries) {
		addFact(
			"boundaries",
			`social memory in private: ${persona.boundaries.privateProcessesSocialMemory}; social workspace: ${persona.boundaries.socialHasWorkspaceMount}`,
		);
	}
	if (facts.childNodes.length > 0) {
		box.append(facts);
	}
	if (Array.isArray(persona.services)) {
		const list = node("ul", "stack compact");
		for (const svc of persona.services) {
			const li = node("li", "item");
			li.append(node("span", "item-label", svc.id));
			const right = node("span", "item-row");
			appendPill(right, svc.enabled ? "enabled" : "disabled");
			right.append(node("span", "item-detail", `${svc.allowedSkillsCount} skills`));
			li.append(right);
			list.append(li);
		}
		box.append(list);
	}
}

function renderChips(sel, items) {
	const list = $(sel);
	clear(list);
	if (!items?.length) {
		const li = node("li", "muted", "(none)");
		list.append(li);
		return;
	}
	for (const name of items) {
		list.append(node("li", null, name));
	}
}

async function refreshActiveTab() {
	switch (state.activeTab) {
		case "sessions":
			return renderSessions();
		case "logs":
			return renderLogs();
		case "jobs":
			return renderJobs();
		case "cron":
			return renderCron();
		case "social":
			return renderSocial();
		case "personas":
			return renderPersonas();
	}
}

async function refreshAll() {
	await renderHealth();
	await refreshActiveTab();
}

$("#login-form").addEventListener("submit", async (ev) => {
	ev.preventDefault();
	const err = $("#login-error");
	err.hidden = true;
	err.textContent = "";
	const btn = $("#login-submit");
	btn.disabled = true;
	try {
		const result = await api("/api/auth/verify", {
			method: "POST",
			body: {
				localUserId: $("#localUserId").value.trim(),
				code: $("#code").value.trim(),
			},
		});
		if (!result.ok) {
			err.textContent = result.body?.error ?? "verification failed";
			err.hidden = false;
			return;
		}
		setAuthed(true);
		await refreshAll();
	} finally {
		btn.disabled = false;
	}
});

$("#logout-btn").addEventListener("click", async () => {
	await api("/api/auth/logout", { method: "POST" });
	setAuthed(false);
});

$("#refresh-btn").addEventListener("click", refreshAll);
$("#log-level").addEventListener("change", renderLogs);
$("#log-component").addEventListener("change", renderLogs);
$("#job-status").addEventListener("change", renderJobs);

$("#jobs-table").addEventListener("click", (ev) => {
	const target = ev.target;
	if (!(target instanceof HTMLElement)) return;
	const shortId = target.dataset.cancelJob;
	if (shortId) cancelJob(shortId);
});

for (const btn of $$(".tab-btn")) {
	btn.addEventListener("click", () => activateTab(btn.dataset.tab));
}

$("#doctor-run-btn").addEventListener("click", async () => {
	const btn = $("#doctor-run-btn");
	const out = $("#doctor-output");
	out.textContent = "running...";
	btn.disabled = true;
	try {
		const res = await api("/api/doctor/run", { method: "POST" });
		if (!res.ok) {
			out.textContent = `error: ${res.body?.error ?? "doctor failed"}`;
			return;
		}
		out.textContent = JSON.stringify(res.body.report, null, 2);
	} finally {
		btn.disabled = false;
	}
});

(async () => {
	const r = await api("/api/health");
	if (r.ok) {
		setAuthed(true);
		await refreshAll();
	} else {
		setAuthed(false);
	}
})();
