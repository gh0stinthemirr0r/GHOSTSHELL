# GHOSTSHELL — Phase 12 Deep Dive

**Focus:** **Compliance Dashboard & GhostAlign**
*(continuous posture assessment mapped to frameworks + executive-grade evidence generation)*

---

## 1) Objectives & Success Criteria

**Objectives**

* Deliver a **Compliance Dashboard** that continuously evaluates GhostShell and connected assets against selected frameworks (NIST CSF/800-53, CIS Controls, ISO 27001, SOC 2, HIPAA—choose per org).
* Operationalize **GhostAlign**: ingest signals from Policy, Vault, SSH/VPN, PCAP, Topology, Reports, and Notifications to compute posture, **gaps**, and **prescriptive remediations**.
* Produce **evidence bundles** (PQ-signed) and **executive reports** with trendlines and audit trails.
* Embed **guardrails**: failing controls raise alerts, block risky actions (policy), or open JIT remediation flows.

**Success Criteria**

* A live dashboard shows **framework → control → status** with confidence and last-evidence timestamp.
* Clicking any control reveals **why status = pass/fail/partial**, the **evidence chain**, and **“Fix it”** actions.
* **Evidence bundles** export as PQ-signed ZIP/PDF/JSON; verifiable against GhostLog.
* Posture improves when analysts apply the suggested remediations (tracked over time).
* All computations are **deterministic and explainable**; no opaque scoring.

---

## 2) Scope (what ships)

### A. Framework Mapping Engine

* Built-in control catalogs: NIST CSF (core), CIS v8, ISO 27001 Annex A, SOC 2 trust criteria.
* Control objects reference **signal queries** (e.g., “Vault → % secrets with rotation ≤ 30d”).
* **Composable mappings**: a single signal can satisfy multiple frameworks.

### B. Signal Ingestion (GhostAlign)

* Signals from:

  * **Policy Engine** (rules present, PQ required, deny/allow ratios, exceptions).
  * **GhostVault** (MFA status, hardware binding use, rotation SLAs, expired secrets).
  * **GhostVPN** (PQ/hybrid usage %, split-tunnel policy, session logs).
  * **SSH Manager/Terminal** (host key pinning %, classical-only sessions).
  * **PCAP/Topology** (unencrypted flows to restricted segments, weak TLS sightings).
  * **Notifications/Alerts** (unacknowledged criticals, mean TTA/MTTR).
  * **Report Templates** (existence of last-month attestations).
* Signals are **time-series**; windowing: last 24h, 7d, 30d, 90d.

### C. Scoring & Posture

* Per-control status: **Pass | Partial | Fail | Unknown** with **confidence** (0–1).
* Posture roll-up: by **domain** (Identify/Protect/Detect/Respond/Recover) and by **framework**.
* Weighting & overrides configurable (e.g., stricter prod posture vs. lab).

### D. Remediation Playbooks

* Each failing control links to a **playbook**:

  * “Enable PQ-only handshake for corp VPN” → deep-link to VPN profile with prefilled settings.
  * “Rotate 12 expired secrets” → batch action in Vault with staged schedule.
  * “Enforce host key pinning on prod” → apply policy preset; regenerate known\_hosts pins.
* Playbooks generate **evidence fragments** automatically when completed.

### E. Evidence & Exports

* **Evidence Graph** per control: pointers to GhostLog entries, signed reports, config hashes.
* One-click **Evidence Bundle** (PQ-signed), including:

  * Control statement + status
  * Evidence artifacts (JSON/PDF/CSV/PCAP hashes, signatures)
  * Verification manifest (Dilithium signatures, SHA3 digests)
* Exports: **Executive Report** (PDF), **Assessor Pack** (ZIP with JSON manifests), **Machine-readable** (OSCAL-lite JSON).

---

## 3) Architecture

```
crates/
  ghost_align/       # signal definitions, evaluators, scoring
  ghost_controls/    # framework catalogs + control→signal mappings
  ghost_evidence/    # evidence graph, bundling, signatures
  ghost_trends/      # time-series posture storage & rollups

src-tauri/commands/compliance.rs
  compliance_frameworks() -> [FrameworkMeta]
  compliance_snapshot(frameworkId) -> SnapshotId
  compliance_control_details(controlId) -> ControlView
  compliance_apply_playbook(controlId, opts) -> TaskId
  compliance_export(snapshotId, format) -> Path
```

**Data flow**

1. **Collectors** pull signals from each module (policy/vault/vpn/ssh/pcap/topology/notify/reports).
2. **Evaluator** runs mapping rules → control statuses with confidence & rationale.
3. **Trends** store aggregated posture.
4. **Evidence** links artifacts to controls and exports signed bundles.

---

## 4) Data Models

**ControlView**

```json
{
  "id": "CIS-4.1",
  "title": "Establish and Maintain a Secure Configuration Process",
  "status": "partial",
  "confidence": 0.82,
  "rationale": [
    "Vault rotation SLA met: 88% (target 95%)",
    "Policy PQ-only enforced on 71% of SSH hosts (target 100%)"
  ],
  "signals": [
    {"key":"vault.rotation.rate30d","value":0.88,"target":0.95},
    {"key":"ssh.pq_required.hosts_fraction","value":0.71,"target":1.0}
  ],
  "evidenceRefs": ["log:2025-08-26-ABCD", "report:rep-2025-08-20-001"],
  "playbooks":[{"id":"pb-rotate-secrets","name":"Rotate Expired Secrets"},{"id":"pb-enforce-pq-ssh","name":"Enforce PQ SSH"}]
}
```

**Evidence Manifest (bundle root)**

```json
{
  "bundleId":"evid-2025-08-26-01",
  "snapshot":"NIST-CSF-2025-08-26T04:00Z",
  "controls":["PR.AC-1","PR.DS-1"],
  "artifacts":[
    {"type":"ghostlog","hash":"sha3-...","sig":"dilithium-..."},
    {"type":"pdf","path":"pcap-report.pdf","hash":"sha3-...","sig":"dilithium-..."}
  ],
  "signature":"dilithium-..."
}
```

---

## 5) Signal Catalog (examples)

* `vault.rotation.rate30d` = rotated / total secrets in last 30 days.
* `vault.mfa.enabled` = boolean % of users with MFA enforced.
* `vpn.pq_fraction` = % of sessions using PQ/hybrid handshake.
* `ssh.pq_required.hosts_fraction` = % of SSH host configs with PQ-required.
* `ssh.hostkey.pin_coverage` = % hosts pinned.
* `pcap.tls.classical_flows` = count of classical-only TLS flows (should trend to zero).
* `topo.policy.violations` = open anomalies in protected segments.
* `notify.critical.unacked_24h` = number of unacknowledged critical alerts in 24h.
* `reports.last_exec.kpis` = time since last executive report generated.

Each signal includes **owner**, **frequency**, **calc function**, and **link** to raw evidence.

---

## 6) Policy Hooks

```toml
[[rules]]
id = "block-noncompliant-ssh"
resource = "tool.ssh"
action = "connect"
when = { hostTag = "prod", compliance = "ssh.pq_required.hosts_fraction < 1.0" }
effect = "deny"
constraints = { notify = "critical" }

[[rules]]
id = "require-remediation"
resource = "vault.secret"
action = "use"
when = { expired = true }
effect = "deny"
constraints = { remediation = "pb-rotate-secrets" }
```

---

## 7) UI / UX

### Compliance Dashboard (main)

* **Framework tabs** across top (NIST, CIS, ISO, SOC 2).
* **Posture cards** for domains (Identify/Protect/Detect/Respond/Recover) with % and trend arrows.
* **Controls table**: status badges (Pass/Partial/Fail/Unknown), last evidence timestamp, confidence.

### Control Drawer (detail view)

* **Rationale** list (why status is what it is).
* **Signals chart** (sparklines / last values vs targets).
* **Evidence** viewer with links to GhostLog entries and artifacts.
* **Playbooks**: “Fix it” actions with required permissions; progress tracker.

### Executive Mode

* One-click export of **Executive Report** (clean style) with posture trends and key gaps, no neon; includes PQ signature.

### Neon Aesthetic

* Analyst UI retains neon glow; fail = neon red pulse; partial = amber; pass = cyan/green.
* Confidence visualized as glowing progress ring.

---

## 8) Security Hardening

* **Evidence immutability**: every artifact hash in GhostLog; bundles Dilithium-signed.
* **Least-privilege reads**: compliance service consumes **summaries**; raw artifacts fetch gated by role/policy.
* **Explainable scoring**: all statuses derive from transparent signal functions.
* **No PII leakage**: reports redact sensitive values; only metadata/hashes.
* **Policy protection**: exporting evidence requires auditor/admin role.

---

## 9) Testing & QA

**Unit**

* Signal computation correctness and windowing.
* Control mapping logic (multi-framework reuse).
* Evidence bundling and signature verification.

**Integration**

* Vault rotation & MFA flags change posture as expected.
* VPN/SSH policy toggles update PQ posture metrics.
* PCAP classical TLS sightings drive “Detect” domain status.
* Playbook execution flips failing controls to pass when completed.

**Security**

* Attempt to export without role → denied, logged.
* Tamper evidence bundle → verify fails with clear error.
* Force mis-scoring (bad mapping) → surfaces “Unknown” with rationale.

**Performance**

* Snapshot compute ≤ 1.5s on 10k signals.
* Dashboard render 60 FPS with 1k controls visible via virtualization.
* Evidence export (100 artifacts) ≤ 5s.

---

## 10) Timeline (4–6 weeks)

**Week 1**

* Framework catalogs & mapping DSL.
* Core signal collectors for Policy/Vault/VPN/SSH.

**Week 2**

* Collectors for PCAP/Topology/Notifications/Reports.
* Scoring engine + confidence calculus.

**Week 3**

* Evidence graph + bundler; Dilithium signing.
* Compliance Dashboard skeleton (list, filters, statuses).

**Week 4**

* Control Drawer (rationale, signals, evidence, playbooks).
* Executive Report export (PDF/OSCAL-lite JSON).

**Week 5 (buffer)**

* Performance tuning, accessibility, policy hooks, docs.
* Default playbooks authored and wired.

**Week 6 (optional)**

* More frameworks or custom corporate profile import.

---

## 11) Deliverables

* **Compliance Dashboard** (framework tabs, domain posture, controls table).
* **GhostAlign** signal engine & scoring with confidence and rationale.
* **Evidence system** with PQ-signed bundles and GhostLog links.
* **Remediation playbooks** tied to failing controls.
* **Executive exports** (PDF/JSON) suitable for audits.
* Docs: framework mapping guide, signal reference, playbook authoring.

---

## 12) Handoff to Phase 13

* Phase 13 (GhostAI) will:

  * Explain **why** a control failed in natural language.
  * Auto-generate **remediation plans** and **policy diffs**.
  * Draft **assessor responses** and schedule rotation/rollouts.
* AI will attach suggestions directly inside the Control Drawer and in alerts.
