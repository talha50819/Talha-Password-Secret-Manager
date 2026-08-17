// Vaultkeep GUI frontend. Deliberately vanilla JS, no build step, no framework — matches the
// project's "minimal dependency surface" principle (docs/01-research-and-discovery.md §1.6)
// and keeps the whole UI auditable in one file. All vault logic lives in Rust (vault-core);
// this file only renders state and calls Tauri commands.

const { invoke } = window.__TAURI__.core;
const clipboard = window.__TAURI__.clipboardManager;

const CLIPBOARD_CLEAR_MS = 20_000;
const IDLE_POLL_MS = 5_000;

let selectedId = null;
let lastEntryDetail = null; // last fetched detail, reused when opening the edit modal
let editingOriginalPassword = null; // tracked so an untouched password field doesn't spuriously rotate password_history
let clipboardClearTimer = null;
let clipboardClearGuardText = null;

// ------------------------------------------------------------------ small DOM helpers ------

const $ = (id) => document.getElementById(id);
const show = (el) => el.classList.remove("hidden");
const hide = (el) => el.classList.add("hidden");

function toast(message) {
  const el = $("toast");
  el.textContent = message;
  show(el);
  clearTimeout(toast._t);
  toast._t = setTimeout(() => hide(el), 2500);
}

function escapeHtml(s) {
  return (s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

async function copyToClipboard(text, label) {
  await clipboard.writeText(text);
  clipboardClearGuardText = text;
  clearTimeout(clipboardClearTimer);
  clipboardClearTimer = setTimeout(async () => {
    // Hash-guarded clear (mirrors crates/vault-cli/src/clipboard.rs): only clear if the
    // clipboard still holds exactly what we put there, so a newer manual copy is never
    // clobbered.
    try {
      const current = await clipboard.readText();
      if (current === clipboardClearGuardText) {
        await clipboard.clear();
      }
    } catch (_) {
      /* clipboard read can fail if another app holds it; nothing to do */
    }
  }, CLIPBOARD_CLEAR_MS);
  toast(`${label} copied — clipboard clears in ${CLIPBOARD_CLEAR_MS / 1000}s`);
}

// ------------------------------------------------------------------ auth screen ------------

async function initAuthScreen() {
  const exists = await invoke("vault_exists");
  $("auth-path").textContent = await invoke("vault_path_display");
  if (exists) {
    $("auth-subtitle").textContent = "Enter your master password to unlock.";
    show($("form-unlock"));
    hide($("form-create"));
    $("unlock-password").focus();
  } else {
    $("auth-subtitle").textContent = "No vault found here yet — create one.";
    show($("form-create"));
    hide($("form-unlock"));
    $("create-password").focus();
  }
}

$("form-unlock").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("unlock-error").textContent = "";
  try {
    await invoke("unlock_vault", { password: $("unlock-password").value });
    $("unlock-password").value = "";
    await enterMain();
  } catch (err) {
    $("unlock-error").textContent = String(err);
  }
});

$("form-create").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("create-error").textContent = "";
  try {
    await invoke("create_vault", { password: $("create-password").value, confirm: $("create-confirm").value });
    $("create-password").value = "";
    $("create-confirm").value = "";
    await enterMain();
  } catch (err) {
    $("create-error").textContent = String(err);
  }
});

async function enterMain() {
  hide($("screen-auth"));
  show($("screen-main"));
  selectedId = null;
  await refreshList();
  startIdleWatch();
}

async function backToAuth(message) {
  stopIdleWatch();
  hide($("screen-main"));
  show($("screen-auth"));
  await initAuthScreen();
  if (message) toast(message);
}

// ------------------------------------------------------------------ idle-lock polling ------

let idleTimer = null;
function startIdleWatch() {
  idleTimer = setInterval(async () => {
    const unlocked = await invoke("is_unlocked");
    if (!unlocked) {
      await backToAuth("Locked after inactivity");
    }
  }, IDLE_POLL_MS);
}
function stopIdleWatch() {
  clearInterval(idleTimer);
}

$("btn-lock").addEventListener("click", async () => {
  await invoke("lock_vault");
  await backToAuth("Locked");
});

// ------------------------------------------------------------------ entry list -------------

async function refreshList() {
  const query = $("search-box").value.trim();
  const entries = query ? await invoke("search_entries", { query }) : await invoke("list_entries", { tag: null });
  renderList(entries);
}

function renderList(entries) {
  $("entry-count").textContent = `${entries.length} entr${entries.length === 1 ? "y" : "ies"}`;
  const list = $("entry-list");
  list.innerHTML = "";
  for (const e of entries) {
    const row = document.createElement("div");
    row.className = "entry-row" + (e.id === selectedId ? " active" : "");
    row.innerHTML = `
      <div class="title">${escapeHtml(e.title)}</div>
      <div class="sub muted">${escapeHtml(e.username || "")}</div>
      <div class="tags">${(e.tags || []).map((t) => `<span class="tag">${escapeHtml(t)}</span>`).join("")}${e.has_totp ? '<span class="tag">TOTP</span>' : ""}</div>
    `;
    row.addEventListener("click", () => selectEntry(e.id));
    list.appendChild(row);
  }
  if (entries.length === 0) {
    list.innerHTML = `<p class="muted" style="padding:14px;">No entries${query ? " match your search" : " yet"}.</p>`;
  }
}

$("search-box").addEventListener("input", () => refreshList());

// ------------------------------------------------------------------ detail pane ------------

async function selectEntry(id) {
  selectedId = id;
  await refreshList();
  try {
    const detail = await invoke("get_entry", { id });
    lastEntryDetail = detail;
    renderDetail(detail);
  } catch (err) {
    toast(String(err));
  }
}

function renderDetail(e) {
  const pane = $("detail-pane");
  pane.innerHTML = `
    <h2>${escapeHtml(e.title)}</h2>
    ${e.username ? field("Username", escapeHtml(e.username), true, false) : ""}
    ${field("Password", "•".repeat(12), true, true)}
    ${e.url ? field("URL", escapeHtml(e.url), false, false) : ""}
    ${e.totp_seed ? `<div class="field-label">TOTP</div><div class="field-row"><span class="field-value totp-code" id="totp-code">------</span><button id="btn-copy-totp">Copy</button></div>` : ""}
    ${e.notes ? field("Notes", escapeHtml(e.notes), false, false) : ""}
    ${(e.tags || []).length ? `<div class="field-label">Tags</div><div>${e.tags.map((t) => `<span class="tag">${escapeHtml(t)}</span>`).join("")}</div>` : ""}
    <div class="detail-actions">
      <button id="btn-edit">Edit</button>
      <button id="btn-delete">Delete</button>
    </div>
  `;

  if (e.username) $("btn-copy-username")?.addEventListener("click", () => copyToClipboard(e.username, "Username"));
  $("btn-copy-password")?.addEventListener("click", () => copyToClipboard(e.password, "Password"));
  $("btn-show-password")?.addEventListener("click", (ev) => {
    const valueEl = $("field-value-password");
    if (valueEl.textContent.includes("•")) {
      valueEl.textContent = e.password;
      ev.target.textContent = "Hide";
    } else {
      valueEl.textContent = "•".repeat(12);
      ev.target.textContent = "Show";
    }
  });

  if (e.totp_seed) {
    refreshTotp(e.id);
    $("btn-copy-totp").addEventListener("click", async () => {
      const code = $("totp-code").textContent.replace(/\s/g, "");
      await copyToClipboard(code, "TOTP code");
    });
  }

  $("btn-edit").addEventListener("click", () => openEntryModal(e));
  $("btn-delete").addEventListener("click", () => deleteEntry(e.id));
}

function field(label, value, copyable, isPassword) {
  const valueId = isPassword ? "field-value-password" : "";
  return `
    <div class="field-label">${label}</div>
    <div class="field-row">
      <span class="field-value" ${valueId ? `id="${valueId}"` : ""}>${value}</span>
      ${isPassword ? `<button id="btn-show-password">Show</button>` : ""}
      ${copyable ? `<button id="btn-copy-${label.toLowerCase()}">Copy</button>` : ""}
    </div>
  `;
}

let totpInterval = null;
async function refreshTotp(id) {
  clearInterval(totpInterval);
  const tick = async () => {
    try {
      const [code, secondsRemaining] = await invoke("totp_code", { id });
      const el = $("totp-code");
      if (el) el.textContent = `${code}  (${secondsRemaining}s)`;
    } catch (_) {
      clearInterval(totpInterval);
    }
  };
  await tick();
  totpInterval = setInterval(tick, 1000);
}

async function deleteEntry(id) {
  if (!confirm("Delete this entry? This cannot be undone.")) return;
  try {
    await invoke("remove_entry", { id });
    selectedId = null;
    $("detail-pane").innerHTML = `<p class="muted empty-state">Select an entry, or add a new one.</p>`;
    await refreshList();
    toast("Entry deleted");
  } catch (err) {
    toast(String(err));
  }
}

// ------------------------------------------------------------------ add/edit modal ---------

function openEntryModal(existing) {
  $("entry-error").textContent = "";
  $("entry-modal-title").textContent = existing ? "Edit entry" : "Add entry";
  $("entry-id").value = existing ? existing.id : "";
  $("entry-title").value = existing ? existing.title : "";
  $("entry-username").value = existing ? existing.username || "" : "";
  $("entry-password").value = existing ? existing.password : "";
  editingOriginalPassword = existing ? existing.password : null;
  $("entry-url").value = existing ? existing.url || "" : "";
  $("entry-tags").value = existing ? (existing.tags || []).join(", ") : "";
  $("entry-totp").value = existing ? existing.totp_seed || "" : "";
  $("entry-notes").value = existing ? existing.notes || "" : "";
  show($("modal-entry"));
  $("entry-title").focus();
}

$("btn-add").addEventListener("click", () => openEntryModal(null));
$("btn-entry-cancel").addEventListener("click", () => hide($("modal-entry")));

$("btn-generate-inline").addEventListener("click", async () => {
  try {
    const pw = await invoke("generate_password", {
      length: Number($("gen-length").value),
      useUpper: $("gen-upper").checked,
      useLower: $("gen-lower").checked,
      useDigits: $("gen-digits").checked,
      useSymbols: $("gen-symbols").checked,
      avoidAmbiguous: $("gen-ambiguous").checked,
    });
    $("entry-password").value = pw;
  } catch (err) {
    $("entry-error").textContent = String(err);
  }
});

$("form-entry").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("entry-error").textContent = "";
  const id = $("entry-id").value;
  const tags = $("entry-tags").value.split(",").map((t) => t.trim()).filter(Boolean);
  const passwordValue = $("entry-password").value;
  const common = {
    username: $("entry-username").value || null,
    url: $("entry-url").value || null,
    notes: $("entry-notes").value || null,
    tags,
    totpSeed: $("entry-totp").value || null,
  };
  try {
    if (id) {
      // Only send `password` if it actually changed — an untouched field must not spuriously
      // push a new (identical) entry onto password_history on every unrelated edit.
      const password = passwordValue !== editingOriginalPassword ? passwordValue : null;
      await invoke("edit_entry", { id, password, ...common });
    } else {
      await invoke("add_entry", { title: $("entry-title").value, password: passwordValue, ...common });
    }
    hide($("modal-entry"));
    await refreshList();
    if (id) await selectEntry(id);
    toast(id ? "Entry updated" : "Entry added");
  } catch (err) {
    $("entry-error").textContent = String(err);
  }
});

// ------------------------------------------------------------------ change master password -

$("btn-passwd").addEventListener("click", () => {
  $("passwd-error").textContent = "";
  $("passwd-new").value = "";
  $("passwd-confirm").value = "";
  show($("modal-passwd"));
});
$("btn-passwd-cancel").addEventListener("click", () => hide($("modal-passwd")));
$("form-passwd").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("passwd-error").textContent = "";
  try {
    await invoke("change_master_password", { newPassword: $("passwd-new").value, confirm: $("passwd-confirm").value });
    hide($("modal-passwd"));
    toast("Master password changed");
  } catch (err) {
    $("passwd-error").textContent = String(err);
  }
});

// ------------------------------------------------------------------ check / activity -------

$("btn-check").addEventListener("click", async () => {
  const results = await invoke("check_all", { staleAfterDays: 365 });
  const rows = results
    .map(
      (r) => `<tr>
        <td>${escapeHtml(r.title)}</td>
        <td>${r.level}</td>
        <td>${r.is_common_password ? "⚠ common" : ""}</td>
        <td>${r.reused_in.length ? `⚠ reused ×${r.reused_in.length}` : ""}</td>
        <td>${r.stale ? "⚠ stale" : ""}</td>
      </tr>`
    )
    .join("");
  $("check-results").innerHTML = results.length
    ? `<table><thead><tr><th>Title</th><th>Strength</th><th></th><th></th><th></th></tr></thead><tbody>${rows}</tbody></table>`
    : `<p class="muted">No entries yet.</p>`;
  show($("modal-check"));
});
$("btn-check-close").addEventListener("click", () => hide($("modal-check")));

$("btn-activity").addEventListener("click", async () => {
  const records = await invoke("audit_log", { tail: 50 });
  const rows = records
    .slice()
    .reverse()
    .map((r) => `<tr><td>${new Date(r.ts).toLocaleString()}</td><td>${r.op}</td></tr>`)
    .join("");
  $("activity-results").innerHTML = records.length
    ? `<table><thead><tr><th>When</th><th>Operation</th></tr></thead><tbody>${rows}</tbody></table>`
    : `<p class="muted">No activity recorded yet.</p>`;
  show($("modal-activity"));
});
$("btn-activity-close").addEventListener("click", () => hide($("modal-activity")));

// ------------------------------------------------------------------ boot -------------------

initAuthScreen();
