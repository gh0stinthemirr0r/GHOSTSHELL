# GHOSTSHELL — GhostLog Deep Dive

**Focus:** **System-Wide Integrated Logging Engine + GUI Search/Rotation**
*(centralized post-quantum secure log management for every GhostShell module)*

---

## 1) Objectives & Success Criteria

**Objectives**

* Deliver **GhostLog**, a **system-wide, per-feature logging subsystem** for GhostShell.
* Unify logs from all modules: **Terminal, SSH, VPN, Vault, Browse, Dash, Align, AI, etc.**
* Provide a **GUI log viewer** with filters, full-text search, export, and theming.
* Enforce a **standard naming convention** for log files & rotations.
* Add **PQ-signed log rotation** to preserve immutability & tamper evidence.
* Support **policy-aware redaction** (e.g., hide secrets or PII).

**Success Criteria**

* All modules log to GhostLog in a normalized schema.
* Users can browse logs via GUI, filter by module, severity, or time.
* Logs auto-rotate with consistent naming convention (date + module).
* Exports are PQ-signed (Dilithium) and validated.
* Full-text search across logs works with <200ms latency for 1M+ entries.

---

## 2) Scope (Phase Delivery)

### Logging Core

* Centralized **GhostLog Daemon** receives log events from all modules via IPC or direct Rust crates.
* **Schema Standardization**: timestamp, module, severity, eventId, message, context.
* **Per-module log streams** (e.g., `ghostlog/ssh/2025-08-27.log`).

### Log Rotation

* Rotation rules: size-based (e.g., 100MB) + time-based (daily).
* Naming convention:

  * `ghostlog/<module>/<YYYY-MM-DD>-<module>-<seq>.log`
  * Example: `ghostlog/ssh/2025-08-27-ssh-001.log`
* Rotated logs are **PQ-signed** & sealed.

### GUI & Search Engine

* **Searchable GUI** inside GhostShell Sidebar (“GhostLog”).
* Search engine supports:

  * Full-text across all logs.
  * Filters: time, severity, module, eventId.
  * Regex & advanced queries.
* Results shown in a **glossy table** with expandable detail view.
* Export: JSON, CSV, or signed bundle.

### Security & Policy

* Logs PQ-signed on write, immutable after rotation.
* Policy can:

  * Enforce retention (e.g., 90 days).
  * Redact sensitive fields before logging.
  * Block log export for non-auditors.

---

## 3) Architecture

```
crates/
  ghost_log/        # core log daemon, rotation, PQ signing
  ghost_index/      # full-text search engine
  ghost_viewer/     # GUI viewer components
```

**Flow**

1. Module generates event → sends to GhostLog.
2. GhostLog daemon normalizes entry, appends to active log.
3. At rotation trigger, closes file, PQ-signs, writes new.
4. Indexer updates search DB.
5. GUI retrieves entries from index, not raw files.

---

## 4) Data Models

**Log Entry**

```json
{
  "ts":"2025-08-27T03:40:12Z",
  "module":"ssh",
  "severity":"warn",
  "eventId":"ssh-conn-fail",
  "msg":"SSH connection failed: expired Vault key",
  "context":{"host":"prod-db","user":"analyst01"},
  "signature":"dilithium-sig..."
}
```

**Log File Manifest**

```json
{
  "file":"ghostlog/ssh/2025-08-27-ssh-001.log",
  "entries":10024,
  "start":"2025-08-27T00:00:00Z",
  "end":"2025-08-27T04:00:00Z",
  "signature":"dilithium-sig..."
}
```

---

## 5) Naming Convention

* Directory per module.
* File per day or size chunk.
* Format:

  * `<YYYY-MM-DD>-<module>-<seq>.log`
  * Examples:

    * `ghostlog/terminal/2025-08-27-terminal-001.log`
    * `ghostlog/vpn/2025-08-27-vpn-002.log`
* Rotation increments `<seq>` when multiple files for same day.
* Each rotated log has a **companion manifest** (`.manifest.json`) PQ-signed.

---

## 6) UI / UX

### Sidebar → GhostLog

* **Filters Panel (left)**:

  * Date/time picker.
  * Module dropdown (multi-select).
  * Severity toggles (Info/Warn/Error/Critical).
  * Search box (regex supported).

* **Results Panel (right)**:

  * Glossy neon table: Timestamp | Module | Severity | EventId | Message.
  * Row hover: cyan glow; Row click → expands to show full context JSON.
  * Severity coloring:

    * Info = cyan, Warn = amber, Error = red glow, Critical = pulsing red.

* **Controls**:

  * Export results (JSON/CSV/PDF bundle).
  * “Live Mode” toggle (stream logs in real time).
  * Snapshot → PQ-signed filtered set stored in Vault.

### Neon Theme

* Frosted panels with pink headers.
* Search hits highlighted neon green.
* Exec mode: white table with blue severity tags.

---

## 7) Security & Policy

* **Tamper-evident**: all entries & rotated files PQ-signed.
* **Audit trail**: log viewer actions (exports, searches) are themselves logged.
* **Policy hooks**:

```toml
[[rules]]
id = "deny-log-export"
resource = "ghostlog.export"
action = "exec"
when = { role != "auditor" }
effect = "deny"

[[rules]]
id = "log-retention-90d"
resource = "ghostlog.retention"
action = "set"
effect = "allow"
constraints = { days = 90 }
```

---

## 8) Testing & QA

**Unit**

* Entry schema validation.
* Rotation triggers (time/size).
* Signature verification.

**Integration**

* Logs flow from Terminal, SSH, VPN.
* GUI search returns results in <200ms for 1M rows.
* Export produces PQ-signed manifest.

**Security**

* Attempt tamper of rotated file → verification fails.
* Attempt export without permission → blocked.

**Performance**

* Sustains 10k log events/sec without loss.
* Indexing 1M entries <5s.

---

## 9) Timeline (3–4 weeks)

**Week 1:** ghost\_log crate; per-module log collectors; rotation.
**Week 2:** PQ signing; manifest system; search indexer.
**Week 3:** GUI viewer; filters; export.
**Week 4 (buffer):** Policy hooks, perf QA, docs.

---

## 10) Deliverables

* **GhostLog v1**: system-wide logging with rotation, PQ signatures, manifests.
* **GUI viewer**: filters, search, exports, real-time mode.
* **Naming convention**: per-module directories, `<date>-<module>-<seq>`.
* **Policy hooks**: retention, export gating.
* **Docs**: schema, usage, policy config.

---

## 11) Future Expansion

* **Behavior analytics**: anomaly detection on log streams.
* **AI assistance** (Phase 13+): contextual log insights + auto-queries.
* **SIEM connector**: forward PQ-signed logs to Splunk/ELK.
* **Immutable store**: optional blockchain/append-only log server anchoring.

---
