# GHOSTSHELL — Phase 16 Deep Dive

**Focus:** Side Panel Governance — **Settings → Navigation & Visibility**
*(turn the Sidebar into a policy-aware, user-customizable control surface: show/hide, reorder, group, pin, and lock features)*

---

## 1) Objectives & Success Criteria

**Objectives**

* Add a **Settings → Navigation & Visibility** section to enable/disable which features appear in the left **Side Panel** (Sidebar).
* Support **reordering**, **grouping**, and **pinning** entries with instant reflection in the UI.
* Make visibility **policy-aware** (role/org policy can force-hide or lock on).
* Persist layouts securely in **GhostVault** (config secret), PQ-sign exports, and support **profile presets** (Analyst, Ops, Auditor, Minimal, Custom).
* Provide **per-workspace** layouts (e.g., “Prod Ops”, “IR Sprint”) and **per-theme** icon variants (neon vs exec).

**Success Criteria**

* Users can toggle modules on/off, reorder by drag & drop, and create groups (e.g., “Recon”, “Live”, “Compliance”).
* Sidebar updates **live** with no restart.
* Role/policy overrides are honored with a clear lock indicator.
* Layouts can be **saved, exported (.ghostnav.json), imported**, and rolled back.
* All changes are **logged in GhostLog** and signed.

---

## 2) Scope (Phase 16 delivery)

**Modules controllable from Settings**

* Core: **Terminal**, **SSH Manager**, **GhostVPN**, **GhostBrowse**, **Vault**, **Notifications**, **Theme Manager**.
* Tools: **Layers**, **Surveyor**, **PCAP Studio**, **Topology Visualizer**, **Scripting Console**, **Report Templates**.
* Compliance: **Compliance Dashboard / GhostAlign**, **GhostLog** viewer, **Metrics**.
* Crypto/Research: **Quantum Noise Analyzer (QNAT)**.
* Optional/3rd-party placeholders (future): “Integrations”.

**Controls added**

* **Visibility toggle** (Show/Hide)
* **Lock** (policy enforced; user cannot change)
* **Pin** (always at top under “Pinned”)
* **Group** (custom label + icon)
* **Order** (drag & drop)
* **Contextual visibility** (auto-show on event, e.g., show VPN only if a profile exists)
* **Workspace selector** (named layouts)
* **Import/Export** (PQ-signed), **Reset to preset**

---

## 3) Information Architecture

**Settings → Navigation & Visibility**

* **Presets**: Analyst / Ops / Auditor / Minimal / Exec / Custom
* **Workspace**: dropdown (Manage Workspaces)
* **Modules List** (searchable): each row = module with controls:

  * Toggle (on/off)
  * Lock badge (if policy forces state)
  * Pin star
  * Group dropdown (existing groups or “+ New group”)
  * Drag handle (reorder)
* **Groups Panel**: define order of groups and their collapsible state (default collapsed/expanded).
* **Preview Pane**: live Sidebar mock reflecting current draft.

**Sidebar runtime**

* Pinned (top)
* Groups (user-defined)
* Unassigned (optional tail section)
* **Quick Switcher** (`Ctrl/Cmd+K`) reflects only visible modules.

---

## 4) Data Models

### Layout Schema (Theme-agnostic)

```json
{
  "version": 2,
  "workspace": "Prod Ops",
  "groups": [
    {"id":"grp-pinned","name":"Pinned","collapsed":false,"order":0},
    {"id":"grp-recon","name":"Recon","collapsed":false,"order":1},
    {"id":"grp-live","name":"Live","collapsed":false,"order":2},
    {"id":"grp-compliance","name":"Compliance","collapsed":true,"order":3}
  ],
  "modules": [
    {
      "id":"terminal",
      "visible": true,
      "pinned": true,
      "groupId":"grp-pinned",
      "order":0,
      "iconVariant":"neon",
      "contextual": {"autoShowOn": ["pty_spawn"]},
      "locked": false
    },
    {
      "id":"layers",
      "visible": true,
      "pinned": false,
      "groupId":"grp-recon",
      "order":0,
      "locked": false
    },
    {
      "id":"compliance",
      "visible": false,
      "pinned": false,
      "groupId":"grp-compliance",
      "order":2,
      "locked": true,
      "lockReason":"policy:auditor_only"
    }
  ],
  "themeHints": {"iconSet":"neon","execToning":false},
  "signature":"dilithium-..."
}
```

### Policy Overlay (computed at load)

```json
{
  "policy": {
    "forceHide": ["ghostbrowse"],
    "forceShow": ["notifications","vault"],
    "locks": {"compliance":"auditor_only"}
  }
}
```

---

## 5) Architecture & IPC

**Crates**

```
crates/
  ghost_nav/         # layout model, merge with policy overlay, validators
  ghost_prefs/       # workspace mgmt, presets, persistence in Vault
```

**Tauri Commands**

```rust
// settings.rs
nav_get_layout(workspace?) -> LayoutV2
nav_preview_layout(layoutDraft) -> LayoutV2 // returns resolved + policy overlay
nav_save_layout(layout) -> { id }
nav_list_workspaces() -> [WorkspaceMeta]
nav_set_workspace(name) -> Ok
nav_export_layout(workspace) -> Path // PQ-signed .ghostnav.json
nav_import_layout(path, mode: "merge"|"replace") -> {warnings}
```

**Load flow**

1. Read user layout (Vault) → validate schema → apply **policy overlay** → resolve final.
2. Sidebar renders from resolved final; runtime reacts to events (e.g., show VPN if a profile created).

**Live update**

* Any change in Settings updates Sidebar via event channel; no restart.

---

## 6) Policy Hooks

Examples (TOML):

```toml
[[rules]]
id = "hide-browser-in-prod"
resource = "ui.sidebar"
action  = "visibility"
when    = { env = "prod" , role != "auditor" }
effect  = "deny"
constraints = { module = "ghostbrowse" }

[[rules]]
id = "force-show-vault"
resource = "ui.sidebar"
action  = "visibility"
when    = { }
effect  = "allow"
constraints = { module = "vault", lock = true }

[[rules]]
id = "only-auditor-compliance"
resource = "ui.sidebar"
action  = "visibility"
when    = { role != "auditor" }
effect  = "deny"
constraints = { module = "compliance", lock = true }
```

**Behavior**

* **forceShow** sets `visible=true` and `locked=true`.
* **forceHide** sets `visible=false` and `locked=true` with lock reason.
* Locks render a small lock icon + tooltip (“Policy: auditor\_only”).

---

## 7) UX Details (pixel-level where useful)

**Settings → Navigation & Visibility**

* Two-pane layout: **Left 420px** list | **Right auto** preview.
* List row (56px height):

  * 20px icon → 200px name → toggle → pin star → group dropdown → drag handle.
* Toggles:

  * Enabled: cyan track `#00FFD1` with glow; Disabled: slate `#3A3B40`.
  * Locked state shows a lock chip (amber) replacing the toggle interaction.
* Group dropdown:

  * 240px menu, first items = existing groups, last = “+ New Group”.
* Drag & drop:

  * While dragging, a neon pink guide line appears; `200ms` snap animation.
* Preview:

  * Exact Sidebar replica at **72% scale** (read-only in Settings).
  * Collapsible group disclosure triangles (reflect `collapsed`).
* Workspace bar:

  * Dropdown (Manage) + actions: Save, Reset from preset, Export, Import.
* Import:

  * Validate schema + signature; show **diff modal** (left current, right incoming) with merge/replace choice.

**Sidebar runtime**

* **Pinned** group always on top; can be collapsed.
* Hover on hidden-eligible modules reveals **“…”** menu → “Show temporarily” if policy permits contextual.
* Keyboard:

  * `Ctrl/Cmd+Shift+[` and `]` to move between groups.
  * `Alt+Shift+↑/↓` to reorder (if unlocked).

---

## 8) Presets (shipped, PQ-signed)

* **Analyst**: Terminal, SSH, Layers, Surveyor, PCAP, Topology, Reports, Notifications, Vault.
* **Ops**: Terminal, SSH, VPN, PCAP, Metrics, Notifications, Vault.
* **Auditor**: Compliance, Reports, GhostLog, Vault (others hidden).
* **Minimal**: Terminal, Vault, Notifications.
* **Exec**: Compliance (Exec theme), Reports, Notifications.
* **Custom**: last user-saved.

> Presets are stored as PQ-signed templates. Importing a preset applies policy overlay.

---

## 9) Persistence & Security

* Layout stored as an **encrypted config secret** in **GhostVault**; includes **Dilithium signature**.
* **Export**: `.ghostnav.json` (PQ-signed).
* **Import**: schema + signature verified; policy overlay computed; show diff and warnings.
* **Logging**: GhostLog entry for **save/import/export/workspace switch**, with user, policy locks applied, and layout hash.

---

## 10) Performance & Accessibility

* **Performance**

  * Resolve (layout + policy) ≤ **5 ms**.
  * Drag & drop visual updates ≤ **16 ms** (60 FPS).
* **Accessibility**

  * Full keyboard support for reordering and toggling (except locked).
  * Focus ring: 2px cyan inner, 1px outer soft glow.
  * Reduce Motion: disables reorder slide and glow pulses.
  * High Contrast: boosts borders to `rgba(255,255,255,0.22)` and text to pure white.

---

## 11) Testing & QA

**Unit**

* Schema validator (accepts v2; rejects invalid).
* Policy overlay resolution (forceShow/forceHide/locks precedence).
* Preset loader & signature verification.

**Integration**

* Toggle visibility → Sidebar live update.
* Drag reorder across groups → persists and restores after restart.
* Import a preset under different roles → verify locks/hidden entries.

**Security**

* Tampered export → import rejected (signature mismatch).
* Attempt to show a policy-hidden module → UI shows lock & blocked toast; GhostLog records attempt.
* Workspace switching audited.

**UX**

* Diff modal clarity on import.
* Tooltip clarity for lock reasons.
* No overlap with toasts/intel panel.

---

## 12) Timeline (2–3 weeks)

* **Week 1:** `ghost_nav` + schema v2, policy overlay, presets; Settings UI skeleton + live Sidebar.
* **Week 2:** Drag & drop, groups, workspaces; import/export (PQ-signed); locks UX; GhostLog wiring.
* **Week 3 (buffer):** Perf polish, accessibility, QA matrix, docs.

---

## 13) Deliverables

* **Settings → Navigation & Visibility** with show/hide, reorder, group, pin, workspaces.
* **Policy overlay & locks** (forceShow/forceHide).
* **Presets** (Analyst/Ops/Auditor/Minimal/Exec) + **Import/Export** (PQ-signed).
* **Vault-backed persistence** + **GhostLog** auditing.
* **Live Sidebar updates** with neon cyberpunk visuals and exec-mode compatibility.

---

## 14) Nice-to-Have (stretch, if time remains)

* **Context rules UI** (auto-show module on specific events).
* **Per-role workspace defaults** (applied on first run).
* **AI nudges** (Phase 13): “You never use Surveyor—hide it?” or “IR active—pin PCAP & Topology for 24h.”

This phase makes the Sidebar **yours**—tight, role-aware, and policy-enforced—without compromising the neon aesthetic or our PQ security model.
