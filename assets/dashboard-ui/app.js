// Dashboard UI — vanilla JS, no frameworks. Served same-origin from /.
// Keep this file small and dependency-free; it runs against the localhost API.

const $ = (sel) => document.querySelector(sel);

const state = {
	authed: false,
};

function setAuthed(v) {
	state.authed = v;
	$("#login-card").hidden = v;
	$("#main-panels").hidden = !v;
	$("#logout-btn").hidden = !v;
	$("#session-indicator").textContent = v ? "signed in" : "not signed in";
	$("#session-indicator").classList.toggle("pill-ok", v);
	$("#session-indicator").classList.toggle("pill-muted", !v);
}

// --- API helpers ----------------------------------------------------------

async function api(path, opts = {}) {
	const res = await fetch(path, {
		method: opts.method ?? "GET",
		credentials: "same-origin",
		headers: { accept: "application/json", ...(opts.body ? { "content-type": "application/json" } : {}) },
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
		return { ok: false, error: "authentication required", status: 401 };
	}
	return { ok: res.ok, status: res.status, body };
}

// --- Auth -----------------------------------------------------------------

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

// --- Panels ---------------------------------------------------------------

function pillClassFor(status) {
	if (status === "ok") return "pill pill-ok";
	if (status === "degraded" || status === "unknown") return "pill pill-warn";
	return "pill pill-bad";
}

async function renderHealth() {
	const res = await api("/api/health");
	if (!res.ok) return;
	const snap = res.body?.snapshot;
	if (!snap) return;
	const overall = $("#overall-health");
	overall.textContent = `${snap.overallStatus} · ${snap.issueCount} issue(s)`;
	overall.className = pillClassFor(snap.overallStatus);
	const list = $("#health-items");
	list.innerHTML = "";
	for (const item of snap.items ?? []) {
		const li = document.createElement("li");
		li.className = "item";
		const label = document.createElement("span");
		label.className = "item-label";
		label.textContent = item.label;
		const right = document.createElement("span");
		const statusPill = document.createElement("span");
		statusPill.className = pillClassFor(item.status);
		statusPill.textContent = item.status;
		const detail = document.createElement("span");
		detail.className = "item-detail";
		detail.textContent = item.detail ?? "";
		right.append(statusPill, " ", detail);
		li.append(label, right);
		list.append(li);
	}
}

async function renderProviders() {
	const res = await api("/api/providers");
	if (!res.ok) return;
	const { catalog, configured } = res.body ?? {};
	const summary = $("#providers-summary");
	const list = $("#providers-list");
	list.innerHTML = "";
	const configuredIds = new Set((configured ?? []).map((c) => c.id));
	summary.textContent = `${configured?.length ?? 0} configured · ${catalog?.length ?? 0} in catalog`;
	for (const entry of catalog ?? []) {
		const li = document.createElement("li");
		li.className = "item";
		const label = document.createElement("span");
		label.className = "item-label";
		label.textContent = `${entry.displayName} (${entry.id})`;
		const pill = document.createElement("span");
		pill.className = configuredIds.has(entry.id) ? "pill pill-ok" : "pill pill-muted";
		pill.textContent = configuredIds.has(entry.id) ? "configured" : "available";
		li.append(label, pill);
		list.append(li);
	}
}

async function renderSkills() {
	const res = await api("/api/skills");
	if (!res.ok) return;
	const { active, drafts } = res.body ?? {};
	renderChips("#skills-active", active);
	renderChips("#skills-drafts", drafts, "(none)");
}

function renderChips(sel, items, emptyMsg) {
	const list = document.querySelector(sel);
	list.innerHTML = "";
	if (!items || items.length === 0) {
		const li = document.createElement("li");
		li.textContent = emptyMsg ?? "(none)";
		li.classList.add("muted");
		list.append(li);
		return;
	}
	for (const name of items) {
		const li = document.createElement("li");
		li.textContent = name;
		list.append(li);
	}
}

function fmtTs(v) {
	if (v == null) return "-";
	const d = typeof v === "number" ? new Date(v) : new Date(String(v));
	if (Number.isNaN(d.getTime())) return "-";
	return d.toISOString().replace("T", " ").slice(0, 19);
}

async function renderApprovals() {
	const res = await api("/api/approvals/allowlist");
	if (!res.ok) return;
	const tbody = document.querySelector("#approvals-table tbody");
	tbody.innerHTML = "";
	const entries = res.body?.entries ?? [];
	if (entries.length === 0) {
		const tr = document.createElement("tr");
		const td = document.createElement("td");
		td.colSpan = 6;
		td.textContent = "(no allowlist entries)";
		td.classList.add("muted");
		tr.append(td);
		tbody.append(tr);
		return;
	}
	for (const entry of entries) {
		const tr = document.createElement("tr");
		for (const cell of [
			entry.userId,
			entry.tier,
			entry.toolKey,
			entry.scope,
			fmtTs(entry.grantedAt),
			entry.expiresAt == null ? "(none)" : fmtTs(entry.expiresAt),
		]) {
			const td = document.createElement("td");
			td.textContent = String(cell);
			tr.append(td);
		}
		tbody.append(tr);
	}
}

async function renderAudit() {
	const res = await api("/api/audit/tail?limit=50");
	if (!res.ok) return;
	const list = $("#audit-list");
	list.innerHTML = "";
	const entries = res.body?.entries ?? [];
	if (!res.body?.enabled) {
		const li = document.createElement("li");
		li.classList.add("muted");
		li.textContent = "(audit logging disabled)";
		list.append(li);
		return;
	}
	if (entries.length === 0) {
		const li = document.createElement("li");
		li.classList.add("muted");
		li.textContent = "(no recent entries)";
		list.append(li);
		return;
	}
	for (const entry of entries.slice().reverse()) {
		const li = document.createElement("li");
		li.className = "item";
		const label = document.createElement("span");
		label.className = "item-label";
		label.textContent = `${fmtTs(entry.timestamp)} · ${entry.telegramUserId}`;
		const right = document.createElement("span");
		const pill = document.createElement("span");
		pill.textContent = entry.outcome;
		pill.className =
			entry.outcome === "success"
				? "pill pill-ok"
				: entry.outcome === "blocked" || entry.outcome === "rate_limited"
					? "pill pill-warn"
					: entry.outcome === "error"
						? "pill pill-bad"
						: "pill pill-muted";
		const preview = document.createElement("span");
		preview.className = "item-detail";
		const msg = (entry.messagePreview ?? "").slice(0, 80);
		preview.textContent = msg;
		right.append(pill, " ", preview);
		li.append(label, right);
		list.append(li);
	}
}

$("#doctor-run-btn").addEventListener("click", async () => {
	const btn = $("#doctor-run-btn");
	const out = $("#doctor-output");
	out.textContent = "running…";
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

$("#refresh-btn").addEventListener("click", refreshAll);

async function refreshAll() {
	await Promise.all([renderHealth(), renderProviders(), renderSkills(), renderApprovals(), renderAudit()]);
}

// --- Bootstrap ------------------------------------------------------------

(async () => {
	// Probe auth: a health fetch will 401 if we have no cookie.
	const r = await api("/api/health");
	if (r.ok) {
		setAuthed(true);
		await refreshAll();
	} else {
		setAuthed(false);
	}
})();
