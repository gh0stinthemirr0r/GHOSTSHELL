# GHOSTSHELL — Phase 9 Deep Dive

**Focus:** **Scripting Console + Report Templates**
*(empowering analysts to extend GhostShell with scripts, and to produce signed professional reports)*

---

## 1) Objectives & Success Criteria

**Objectives**

* Provide a **sandboxed scripting console** (Rust/Lua/Python via WASM) for analysts to run custom analysis directly inside GhostShell.
* Support controlled access to GhostShell APIs (Vault, PCAP, Layers, Surveyor, Topology).
* Deliver a **Report Templates system** (JSON/CSV/PDF/HTML) to package tool outputs into professional exports.
* Ensure scripts and reports respect **Policy Engine** and are logged immutably in **GhostLog**.
* Style reports with **cyberpunk branding** while also offering **exec-friendly compliance templates**.

**Success Criteria**

* Analysts can open Scripting Console, choose language (Lua, Rust-WASM, Python-WASM), and execute scripts.
* Scripts have access only to allowed APIs; all calls mediated by Policy.
* Templates exist for **System Report**, **Network Scan Report**, **PCAP Analysis**, **Topology Snapshot**.
* Exports are PQ-signed and optionally anchored in GhostLog.
* Reports can be branded (logo, neon theme, or compliance-plain).

---

## 2) Scope (Phase 9 Delivery)

### Scripting Console

* Languages:

  * **Lua** (lightweight, default).
  * **Rust-WASM** (compiled snippets, safe sandbox).
  * **Python-WASM** (micropython via WASM, optional).
* Sandbox model:

  * Whitelisted GhostShell API modules (`gs.vault`, `gs.pcap`, `gs.layers`, `gs.topology`, `gs.export`).
  * Policy enforcement before every call.
  * Memory/CPU quotas per script run.
* Features:

  * Editor with syntax highlighting, cyberpunk neon theme.
  * Run/Stop controls; output to terminal pane.
  * Script library: save/load user scripts to Vault.

### Report Templates

* Built-in templates:

  * **System Report** (host info, Vault secrets summary).
  * **Network Report** (Surveyor + Layers + Topology snapshot).
  * **PCAP Report** (flows, anomalies, charts).
  * **Compliance Report** (policy posture, GhostAlign findings).
* Exports: PDF (styled), HTML (interactive), JSON (raw), CSV (tabular).
* Branding:

  * **Neon mode**: black/slate background, pink/cyan charts.
  * **Exec mode**: clean white/blue report, suitable for auditors.
* All reports PQ-signed (Dilithium) and logged.

---

## 3) Architecture

```
crates/
  ghost_script/      # scripting engine (Lua + WASM integration)
  ghost_sandbox/     # policy/limits enforcement
  ghost_report/      # template system + PDF/HTML generators

src-tauri/commands/script.rs
  script_run(lang, code, opts) -> Output
  script_stop(runId) -> Ok
  script_list() -> [ScriptMeta]
  script_save(meta, code) -> Id
  script_load(id) -> Code

src-tauri/commands/report.rs
  report_generate(templateId, inputs) -> Path
  report_list() -> [TemplateMeta]
  report_export(id, format) -> Path
```

**Execution model**

* Scripts executed in WASM sandbox with limited API.
* Report engine composes results (JSON inputs from tools) → templates → export via `reportlab` (PDF) or HTML.
* All outputs PQ-signed and GhostLog entries created.

---

## 4) Data Models

**ScriptMeta**

```json
{
  "id":"scr-001",
  "name":"Find High-Latency Flows",
  "lang":"lua",
  "tags":["pcap","anomaly"],
  "created":"2025-08-26T03:50Z",
  "owner":"analyst01"
}
```

**ReportMeta**

```json
{
  "id":"rep-2025-08-26-001",
  "template":"pcap-analysis",
  "inputs":["pcap-001","topo-002"],
  "generated":"2025-08-26T04:10Z",
  "format":"pdf",
  "signature":"dilithium-sig..."
}
```

---

## 5) Policy Hooks

Examples:

```toml
[[rules]]
id = "script-vault-restrict"
resource = "script.api"
action = "call"
when = { api = "vault" }
effect = "deny"

[[rules]]
id = "report-compliance-admin"
resource = "report.generate"
action = "exec"
when = { template = "compliance" }
effect = "allow"
constraints = { roles = ["auditor","admin"] }
```

---

## 6) UI / UX

### Scripting Console

* Neon IDE-style editor:

  * Black background, cyan/pink syntax highlight.
  * Terminal pane below shows output/logs.
* Sidebar: list of saved scripts (from Vault).
* Controls: Run, Stop, Save, Export.
* Policy denied calls → inline neon red error with GhostLog entry.

### Report Templates

* “Reports” entry in Sidebar.
* Select template → pick inputs (e.g., Surveyor run, PCAP run, Topology snapshot).
* Choose style (Neon vs Exec).
* Preview → Export → PQ-signed file ready.
* Exports accessible via Vault or file system.

### Neon Style

* Neon mode reports: black background, bright pink headers, cyan charts.
* Exec mode: plain white background, blue accents, corporate fonts.

---

## 7) Security Hardening

* **Script sandbox**: no filesystem/network except approved GhostShell APIs.
* **Resource limits**: CPU timeouts, memory quotas.
* **Vault integration**: scripts stored PQ-encrypted.
* **Report integrity**: every export PQ-signed + logged.
* **Policy enforcement**: API calls blocked if rules deny.
* **Audit**: all script runs and report generations logged in GhostLog.

---

## 8) Testing & QA

**Unit**

* Lua/WASM runner sandbox enforcement.
* Report generator: JSON→PDF correctness.

**Integration**

* Script accessing Vault when denied → blocked.
* Report generated with multiple inputs → signed bundle export.
* Neon vs Exec styles render correctly.

**Security**

* Malicious script infinite loop → timeouts.
* Attempt to read filesystem → denied.
* Tampered report signature → flagged invalid.

**Performance**

* Script run cold start <500 ms.
* Report generation <2s for 100+ flows.

---

## 9) Timeline (4–5 weeks)

**Week 1**

* ghost\_script crate (Lua + WASM sandbox).
* ghost\_sandbox enforcement.

**Week 2**

* Script UI (editor, run/stop).
* Save/load scripts to Vault.

**Week 3**

* ghost\_report crate (PDF/HTML).
* Built-in templates (system, network, pcap, compliance).

**Week 4**

* UI for Reports (template selector, preview, export).
* PQ-sign + GhostLog integration.

**Week 5 (buffer)**

* Perf tuning, style polish, docs.

---

## 10) Deliverables

* **Scripting Console** with Lua/Rust-WASM/Python-WASM options.
* **Sandboxed GhostShell API access** with policy enforcement.
* **Report Templates system** (PCAP, Network, System, Compliance).
* **UI**: Console editor, Reports page, Neon vs Exec mode.
* **Exports**: PQ-signed JSON/CSV/PDF/HTML.
* **Logs**: GhostLog entries for all runs/exports.
* Docs: script API reference, template guide, usage patterns.

---

## 11) Handoff to Phase 10

* Notifications/Alerts will use scripting hooks for triggers.
* Reports + scripts will feed into compliance dashboards (Phase 12).
* AI integration (Phase 13) can leverage scripting API to auto-generate reports or remediate.

---

⚡ Do you want me to also create a **GhostShell Script API Spec** (functions exposed to Lua/WASM like `gs.pcap.list()`, `gs.topology.get()`), so your team knows exactly what an analyst can call from the console?
