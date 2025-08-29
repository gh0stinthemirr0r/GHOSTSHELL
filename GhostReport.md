# GHOSTSHELL — GhostReport Deep Dive

**Focus:** **Automated Reporting Engine from GhostLog & GhostDash Analytics**
*(structured CSV/XLSX/PDF reports with PQ signing, neon-themed preview, and compliance-ready outputs)*

---

## 1) Objectives & Success Criteria

**Objectives**

* Deliver **GhostReport**, a feature for generating **CSV, XLSX, and PDF** reports.
* Reports will be derived from:

  * **GhostLog** → execution logs, policy actions, system-wide events.
  * **GhostDash** → system/network analytics, IP/DNS/routing/connection tables.
* Provide a **GUI report builder** where analysts can select data sources, filters, and output formats.
* Allow **scheduled and on-demand reports**.
* Ensure all reports are **PQ-signed** for authenticity.
* Support **compliance-ready exports** (Exec Mode) and **cyberpunk previews** (Analyst Mode).

**Success Criteria**

* Users can generate reports in one click from GhostLog or GhostDash.
* Filters apply (time window, severity, module, network interface, connection states).
* Reports export as:

  * **CSV** for raw data.
  * **XLSX** with styled tables/charts.
  * **PDF** with full formatting, branding, and signatures.
* Reports PQ-signed, stored in Vault, and linked to GhostLog.

---

## 2) Scope (Phase Delivery)

### Report Sources

* **GhostLog Data**:

  * By module (Terminal, SSH, VPN, Vault, Browse, Script, etc.).
  * By severity (Info/Warn/Error/Critical).
  * By event type (policy actions, errors, rotations, exports).

* **GhostDash Analytics**:

  * System stats (hostname, uptime, OS, CPU/mem/disk).
  * Network stats (interfaces, throughput, packet errors).
  * Tables: ipconfig, DNS servers, routes, netstat connections.

### Output Formats

* **CSV** → flat structured output for data ingestion.
* **XLSX** → styled, multiple sheets (GhostLog on one, GhostDash on another), with charts.
* **PDF** → formatted report: title page, executive summary, charts, signed evidence page.

### Scheduling & Automation

* One-off generation.
* Scheduled (daily, weekly, monthly).
* Triggered by event (e.g., compliance audit, log anomaly).

---

## 3) Architecture

```
crates/
  ghost_report/       # report engine
  ghost_export_csv/   # csv writer
  ghost_export_xlsx/  # xlsx writer (charts, styles)
  ghost_export_pdf/   # pdf writer (reportlab backend)
```

**Flow**

1. User selects sources & filters in Report Builder.
2. Engine queries GhostLog + GhostDash → normalized JSON dataset.
3. Formatter generates CSV, XLSX, or PDF.
4. PQ-signature appended.
5. Report stored in Vault + GhostLog event created.

---

## 4) Data Models

**Report Job**

```json
{
  "id":"report-2025-08-27-001",
  "name":"Weekly Network & Logs",
  "sources":["ghostlog:ssh","ghostdash:interfaces","ghostdash:connections"],
  "filters":{"timeStart":"2025-08-20T00:00Z","timeEnd":"2025-08-27T00:00Z"},
  "formats":["csv","xlsx","pdf"],
  "createdBy":"analyst01",
  "timestamp":"2025-08-27T04:10Z",
  "signature":"dilithium-sig..."
}
```

**Report Artifact**

```json
{
  "reportId":"report-2025-08-27-001",
  "format":"pdf",
  "path":"ghostvault/reports/weekly-2025-08-27.pdf",
  "hash":"sha3-...",
  "signature":"dilithium-sig..."
}
```

---

## 5) Naming Convention

* Vault storage path:

  * `/ghostvault/reports/<YYYY-MM-DD>/<reportName>-<id>.<format>`
* Example:

  * `ghostvault/reports/2025-08-27/weekly-2025-08-27-001.pdf`

---

## 6) UI / UX

### Sidebar Entry → GhostReport

**Report Builder Panel**

* **Source Selector** (checkboxes): GhostLog, GhostDash (sub-select modules/analytics).
* **Filter Config**: time range, severity, module, network interface.
* **Format Options**: CSV, XLSX, PDF.
* **Scheduling**: dropdown (none, daily, weekly, monthly).
* **Buttons**: Generate, Save Template, Run Now.

**Report Archive Panel**

* Glossy table: Report Name | Creator | Sources | Formats | Timestamp | Actions.
* Actions: Open (preview), Export, Verify Signature, Delete.

**Preview Mode**

* Neon Preview (Analyst Mode): frosted acrylic, neon pink headers, glowing charts.
* Exec Mode: clean corporate PDF preview with muted charts and branding.

---

## 7) Security & Policy

* **PQ-Signed Reports**: every artifact Dilithium-signed.
* **Vault Integration**: stored encrypted + access controlled.
* **Policy hooks**:

```toml
[[rules]]
id = "restrict-log-export"
resource = "ghostreport"
action = "export"
when = { role != "auditor" }
effect = "deny"

[[rules]]
id = "auto-weekly-audit"
resource = "ghostreport"
action = "schedule"
when = { framework="NIST" }
effect = "allow"
constraints = { freq="weekly", target="compliance" }
```

* **Audit Trail**: report generation itself logged in GhostLog.

---

## 8) Testing & QA

**Unit**

* CSV/XLSX/PDF generation.
* Signature attach/verify.
* Schema validation for filters.

**Integration**

* GhostLog + GhostDash queries return consistent results.
* Scheduled reports trigger reliably.
* Export bundle validated in Vault.

**Security**

* Attempt to export w/out role → denied + logged.
* Tampered report → signature mismatch flagged.

**Performance**

* Generate 10k-log entry report <3s.
* XLSX with charts under 5s.
* PDF <4s.

---

## 9) Timeline (3–4 weeks)

**Week 1:** ghost\_report crate, source query adapters (GhostLog, GhostDash).
**Week 2:** CSV/XLSX/PDF writers, PQ signing.
**Week 3:** Report Builder UI + Archive Panel.
**Week 4 (buffer):** Scheduling, policy hooks, QA, docs.

---

## 10) Deliverables

* **GhostReport v1**: unified report engine.
* **CSV/XLSX/PDF outputs** with PQ signatures.
* **Report Builder UI** (sources, filters, formats, scheduling).
* **Report Archive** (list, preview, verify).
* **Vault storage** + GhostLog integration.
* **Policy hooks**: export gating, scheduling enforcement.
* **Docs**: schema, usage, compliance mapping.

---

## 11) Future Expansion

* **Custom templates**: user-authored PDF templates with branding.
* **Interactive dashboards** (export HTML reports with neon themes).
* **Direct compliance exports** (OSCAL JSON, SOC 2 binder).
* **AI summaries**: GhostAI generates executive summary text in reports.
* **Correlation**: combine GhostLog events with GhostDash flows (e.g., “VPN drop correlated with routing change”).

---
