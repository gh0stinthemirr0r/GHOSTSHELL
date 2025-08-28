# GHOSTSHELL — Phase 10 Deep Dive

**Focus:** **Notifications & Alerts System**
*(real-time neon popups for anomalies, policy events, expired secrets, and tool activity)*

---

## 1) Objectives & Success Criteria

**Objectives**

* Deliver a **centralized alert/notification engine** inside GhostShell.
* Surface real-time **policy violations, anomalies, expired secrets, tool completion, and VPN/SSH/PCAP events**.
* Style notifications in a **cyberpunk neon HUD aesthetic** while remaining functional and non-intrusive.
* Integrate with **Policy Engine**, **GhostVault**, **GhostLog**, and **GhostMetrics**.
* Allow analysts to configure **alert rules** (thresholds, severity, destinations).

**Success Criteria**

* Alerts appear as **neon popups** (toasts, banners, side-panel) with severity coloring.
* All alerts recorded in **GhostLog** with PQ signatures.
* Analysts can filter alerts by type/severity/time.
* Notifications can trigger actions (acknowledge, mute, jump to related tool/panel).
* Policy-driven: e.g., deny event produces neon red “blocked” popup.

---

## 2) Scope (Phase 10 Delivery)

### Notification Engine

* Core daemon in Rust: collects events, applies rules, streams to UI.
* Sources:

  * **Policy Engine** (violations, denials).
  * **GhostVault** (expired secrets, rotation required).
  * **GhostVPN** (disconnects, posture change).
  * **SSH Manager** (failed auth, host key mismatch).
  * **PCAP Studio** (anomalies detected).
  * **Topology Visualizer** (new anomalies, flow spikes).
* Rules: severity levels (info, warn, critical).
* Destinations: UI (toasts, panel), GhostLog, optional external webhook/email (future phase).

### UI Presentation

* **Toast notifications**: top-right neon cards, auto-expire or pin.
* **Notification Center**: sidebar Intel Panel with full history, filters, search.
* **Severity color-coding**:

  * Info → Cyan glow.
  * Warning → Amber glow.
  * Critical → Neon red pulse.
* Interactive: click → open related panel/tool.

### Policy Integration

* Policies can trigger alerts explicitly (e.g., “notify on all Vault access”).
* Rules configurable in **Security & Policy** UI.

### Logging

* Every alert signed into GhostLog with context.
* Alert bundles exportable for compliance reporting.

---

## 3) Architecture

```
crates/
  ghost_notify/     # core engine, rules, dispatcher
  ghost_alert/      # UI models, severity mapping
  ghost_log/        # signed event storage (reused)

src-tauri/commands/notify.rs
  notify_list(filter?) -> [AlertMeta]
  notify_ack(id) -> Ok
  notify_config(rules) -> Ok
```

**Execution Model**

* Rust side subscribes to tool + policy events → normalizes into Alert objects.
* Streamed to UI via IPC channels.
* UI displays as toast + adds to Notification Center.

---

## 4) Data Models

**AlertMeta**

```json
{
  "id":"alert-2025-08-26-001",
  "source":"policy",
  "severity":"critical",
  "msg":"Policy denied SSH connect to prod-db",
  "ts":"2025-08-26T04:30Z",
  "context":{"host":"prod-db","rule":"deny-prod-ssh"},
  "acknowledged":false,
  "signature":"dilithium-sig..."
}
```

**AlertRule**

```json
{
  "id":"rule-ssh-fails",
  "source":"ssh",
  "event":"auth_fail",
  "severity":"warn",
  "notify":true,
  "actions":["log","toast"]
}
```

---

## 5) Policy Hooks

Examples:

```toml
[[rules]]
id = "alert-vault-expiry"
resource = "vault.secret"
action = "expiry"
effect = "allow"
constraints = { notify = "critical" }

[[rules]]
id = "alert-vpn-drop"
resource = "vpn.session"
action = "disconnect"
effect = "allow"
constraints = { notify = "warn" }
```

---

## 6) UI / UX

### Toasts

* Appear top-right, frosted glass background, neon border glow.
* Auto-expire after 5s (info), 15s (warn), persistent until ack (critical).
* Click → deep link into relevant panel/tool.

### Notification Center

* Sidebar panel with:

  * Filter by source/severity.
  * Search bar.
  * Export button (PQ-signed bundle).
* Each alert shows: icon, source, message, context tags.

### Severity Styling

* Info → Cyan glow, subtle animation.
* Warn → Amber neon edge, pulsing bar.
* Critical → Neon red with pulsing halo until ack.

---

## 7) Security Hardening

* **Signed alerts**: every alert hashed + Dilithium-signed in GhostLog.
* **Policy enforcement**: alerts only for permitted categories (no leaking sensitive info).
* **Config storage**: alert rules encrypted in Vault.
* **Anti-spam**: deduplication + rate-limits to prevent floods.
* **Audit trail**: acknowledgements logged with timestamp + user.

---

## 8) Testing & QA

**Unit**

* Severity mapping from events → alerts.
* Ack/unack flow.

**Integration**

* Policy violation → neon red toast + GhostLog entry.
* Vault expiry → amber alert → open secret details.
* VPN drop → amber toast → link to VPN panel.

**Security**

* Tampered alerts → signature mismatch flagged.
* Attempt to disable critical alerts → blocked by policy.

**Performance**

* Handle 500 alerts/minute without UI lag.
* Toast rendering ≤50 ms after event.

---

## 9) Timeline (3–4 weeks)

**Week 1**

* ghost\_notify crate; Alert struct + stream.
* Wire Policy Engine + Vault events.

**Week 2**

* Wire SSH, VPN, PCAP, Topology event hooks.
* Toast UI component.

**Week 3**

* Notification Center sidebar UI.
* Export PQ-signed bundles.

**Week 4 (buffer)**

* Perf tests, polish animations, docs.

---

## 10) Deliverables

* **Notification engine** wired to Policy, Vault, VPN, SSH, PCAP, Topology.
* **UI**: Neon toasts + Notification Center with filters.
* **Policy integration** for configurable alerts.
* **GhostLog integration** with PQ signatures.
* **Docs**: alert rules, severity guide, compliance exports.

---

## 11) Handoff to Phase 11

* Notifications/alerts will later connect to **Theming Engine** (Phase 11) for user-customizable looks.
* Alerts feed into **GhostAlign** (Phase 12) for compliance dashboards.
* Phase 13 AI will provide **contextual recommendations** inline with alerts.

---

⚡ Want me to also design a **default alert ruleset** (policy violations = critical, VPN drop = warn, secret expiry = warn, anomalies = critical) so devs/users have a baseline configuration out of the box?
