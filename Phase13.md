# GHOSTSHELL — Phase 13 Deep Dive

**Focus:** **GhostAI — AI-Assisted Error Responses & Compliance Insight**
*(intelligent assistant woven into Terminal, SSH Manager, and Compliance Dashboard)*

---

## 1) Objectives & Success Criteria

**Objectives**

* Deliver **GhostAI**, an AI copilot module that:

  * Provides **contextual error responses** inside the **Terminal** and **SSH Manager**.
  * Enhances **Compliance Dashboard (GhostAlign)** with natural-language explanations of failed controls and prescriptive fixes.
  * Learns from GhostLog, signals, and evidence bundles to surface **why things fail** and **how to fix them**.
* Tie GhostAI into the **policy engine** so it can recommend compliant fixes, not bypasses.
* Keep AI **bounded, explainable, and auditable**: every suggestion linked to evidence.

**Success Criteria**

* In the **Terminal**: errors (e.g., “Permission denied (publickey)”) trigger GhostAI hints (e.g., “Vault key expired; rotate or rebind in SSH Manager → Playbook link”).
* In the **SSH Manager**: failed connections or policy denials show contextual explanations (with direct fix buttons).
* In the **Compliance Dashboard**: GhostAI explains why a control is failing and offers remediation steps with playbook references.
* All GhostAI suggestions are logged into GhostLog, signed, and tied to the evidence base.

---

## 2) Scope (Phase 13 Delivery)

### Error Response AI

* **Terminal integration**: hook PTY/SSH stderr → error classifier → GhostAI suggestion.
* **SSH Manager**: negotiation failures (PQ-only required but host classical-only), host key mismatches, expired Vault keys → AI annotated hints.
* **Vault**: expired/rotated secrets → AI suggests renewal playbook.

### Compliance AI

* In GhostAlign Control Drawer:

  * Translate signals/rationales into plain English.
  * Suggest remediations mapped to Playbooks.
  * Example:

    * Control: “Vault rotation SLA 95% unmet (88%)”
    * GhostAI → “12 of 100 secrets are expired. Rotate via Vault Playbook. Automate policy enforcement to block expired secrets.”

### Report & Script AI

* Suggests **custom report generation** queries (e.g., “Show only classical TLS flows in last 7d”).
* Drafts **executive summary** text blocks in compliance exports.

### Logging & Governance

* Each suggestion includes:

  * Source (Terminal/SSH/Compliance).
  * Evidence references.
  * Policy alignment (why suggestion is compliant).
* Suggestions themselves PQ-signed and logged.

---

## 3) Architecture

```
crates/
  ghost_ai/          # inference wrapper + classifiers
  ghost_errmap/      # error → cause mapping
  ghost_explain/     # compliance explainers, templates
  ghost_link/        # playbook + policy linkage

src-tauri/commands/ai.rs
  ai_explain_error(context) -> Suggestion
  ai_explain_control(controlId) -> Suggestion
  ai_generate_report(inputs, style) -> ReportText
```

**Execution model**

* Error or control triggers → context object created (error text, session info, signals).
* Classifier maps to category (auth error, policy denial, crypto mismatch, expired secret).
* GhostAI generates structured suggestion with evidence + recommended action.
* Suggestion streamed to UI as neon “AI Tip” chip.

---

## 4) Data Models

**Error Suggestion**

```json
{
  "id":"ai-sug-2025-08-26-01",
  "source":"ssh",
  "error":"Permission denied (publickey)",
  "analysis":"Vault key 'ops-edge' expired yesterday",
  "recommendation":"Rotate secret in Vault, rebind to SSH profile",
  "playbook":"pb-rotate-secrets",
  "evidenceRefs":["vault:sec-001","log:2025-08-26-ABCD"],
  "signature":"dilithium-sig..."
}
```

**Control Suggestion**

```json
{
  "id":"ai-sug-2025-08-26-02",
  "source":"compliance",
  "control":"CIS-4.1",
  "analysis":"12 secrets missed 30-day rotation SLA",
  "recommendation":"Run Vault Playbook → Rotate Expired Secrets",
  "confidence":0.92,
  "evidenceRefs":["vault:stats-30d","log:2025-08-20-XYZ"],
  "signature":"dilithium-sig..."
}
```

---

## 5) Policy Hooks

Examples:

```toml
[[rules]]
id = "ai-block-bypass"
resource = "ai.suggestion"
action = "apply"
when = { recommendation = "disable-policy" }
effect = "deny"

[[rules]]
id = "ai-log-critical"
resource = "ai.suggestion"
action = "generate"
when = { severity = "critical" }
effect = "allow"
constraints = { notify = "true" }
```

---

## 6) UI / UX

### Terminal / SSH Manager

* Inline neon **AI Chip** under error output:

  ```
  Permission denied (publickey)
  [AI Suggestion] Vault key expired. Rotate via Vault → SSH Manager.
  ```
* Hover chip → expand evidence and playbook link.

### Compliance Dashboard

* Control Drawer → GhostAI “Insight” card:

  * Natural-language explanation of failing signals.
  * Action buttons: Apply Playbook, Export Evidence, Open Report.

### Reports / Scripts

* Report Generator → “GhostAI Draft Executive Summary” button.
* Scripting Console → AI suggests API snippets for common tasks.

### Neon Aesthetic

* AI chips glow cyan/purple.
* Critical AI suggestions pulse until acknowledged.

---

## 7) Security Hardening

* **AI guardrails**: cannot suggest disabling security controls.
* **Explainability**: every suggestion tied to evidence + logs.
* **Auditability**: suggestions PQ-signed and stored in GhostLog.
* **Policy-aware**: AI can only recommend **compliant** remediations.
* **Safe sandbox**: no direct command execution; only suggestion output.

---

## 8) Testing & QA

**Unit**

* Error classifiers: map SSH errors → correct AI messages.
* Compliance explainers: signals → rationale text.

**Integration**

* SSH auth fail → AI suggestion points to expired Vault key.
* VPN classical-only connect attempt → AI warns, points to PQ policy toggle.
* Compliance fail → AI Insight explains with evidence refs.

**Security**

* Attempted bypass suggestion → blocked by policy.
* Tampered suggestion → signature mismatch flagged.

**Performance**

* Error suggestion latency ≤ 500 ms.
* Compliance insight generation ≤ 2s for 100 controls.

---

## 9) Timeline (4–6 weeks)

**Week 1**

* ghost\_errmap crate: error classifier for SSH/Terminal.
* ghost\_explain skeleton for Compliance.

**Week 2**

* Terminal/SSH integration; AI Chip UI.
* Vault + Policy context ingestion.

**Week 3**

* Compliance Dashboard integration (Insight cards).
* Playbook linkage.

**Week 4**

* Logging/signing of suggestions in GhostLog.
* Policy guardrails.

**Week 5 (buffer)**

* Exec summary drafting for Reports.
* Scripting Console hint integration.

**Week 6 (optional)**

* Extend error coverage to PCAP/Topology anomalies.

---

## 10) Deliverables

* **GhostAI v1** with error explainers in Terminal + SSH Manager.
* **Compliance Insights** in GhostAlign dashboards.
* **AI Chips** in neon UI with evidence and playbook links.
* **Exec summary drafting** in reports.
* **GhostLog integration**: all suggestions signed + auditable.
* Docs: AI API, error map reference, compliance explainer catalog.

---

## 11) Handoff to Phase 14

* GhostAI prepares groundwork for **GhostBrowse (PQ browser)** (Phase 14): AI will auto-diagnose failed cert handshakes, PQ-negotiation errors, and policy misconfigurations inside the browser module.
* In later phases, GhostAI can evolve into a **proactive posture advisor**, not just error responder.

---

⚡ Do you want me to also draft the **error → AI mapping table** (e.g., SSH errors, TLS handshake failures, Vault expiry, VPN drops → AI responses) so devs have a ready library of cases to implement in GhostAI?
