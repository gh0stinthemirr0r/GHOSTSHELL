# GHOSTSHELL — Phase 7 Deep Dive

**Focus:** **GhostVPN — Post-Quantum Secure VPN Client**
*(Kyber-based OpenVPN/WireGuard fork integrated into GhostShell sidebar)*

---

## 1) Objectives & Success Criteria

**Objectives**

* Deliver **GhostVPN**, a post-quantum secure VPN client tightly integrated into the GhostShell ecosystem.
* Provide PQ or hybrid handshakes (Kyber for key exchange, Dilithium for signatures).
* Allow **per-tool binding** (e.g., SSH, PCAP, GhostBrowse) to specific VPN tunnels.
* Manage VPN profiles via **GhostVault** with policy enforcement and MFA gating.
* Show **neon visual feedback** (status, latency, throughput) inside the shell.
* Log all tunnel events immutably in **GhostLog**.

**Success Criteria**

* Users can create, store, and launch VPN profiles from Vault.
* VPN tunnel status (up/down, endpoint, latency, throughput) visible in Sidebar and TopBar.
* Tools can bind to VPN sessions explicitly; policy blocks if tool is attempted without VPN when required.
* Tunnels use PQ-hybrid by default; pure classical connections flagged in neon amber.
* All VPN connects/disconnects, failures, and errors are logged and signed.

---

## 2) Scope (Phase 7 Delivery)

### VPN Core

* Protocol support:

  * **WireGuard fork** with Kyber-based handshake.
  * **OpenVPN fork** with PQ KEM + Dilithium signatures (as fallback).
* Profiles stored in GhostVault (endpoint, keys, policy, tags).
* Support for multiple tunnels; per-tool binding.
* Connection lifecycle: start/stop/restart; status queries.
* Route management: full-tunnel vs. split-tunnel.

### Policy Integration

* Enforce VPN-required rules for SSH, PCAP, Browser.
* Deny connects to restricted endpoints.
* Require MFA for certain VPN profiles.
* Control split-tunnel use (on/off per role).

### Observability

* Live metrics: latency, throughput, packet drops.
* Status neon indicator in Sidebar and TopBar (green = PQ, purple = hybrid, amber = classical, red = error).
* Intel Panel charts: throughput timeline, latency jitter, endpoint map.

### Logging

* GhostLog entries: connect, disconnect, profile used, PQ posture, MFA, errors.
* PQ-signed status bundles (Dilithium).

---

## 3) Architecture

```
crates/
  ghost_vpn/        # control + PQ handshake logic (wg + ovpn wrappers)
  ghost_tun/        # TUN/TAP driver abstraction
  ghost_metrics/    # metrics collection + streaming
  ghost_export/     # signed status bundles

src-tauri/commands/vpn.rs
  vpn_list() -> [ProfileMeta]
  vpn_connect(profileId) -> {sessionId}
  vpn_disconnect(sessionId) -> Ok
  vpn_status(sessionId) -> {latency, throughput, pqPosture, state}
  vpn_bind_tool(sessionId, toolId) -> Ok
```

**Execution model**

* VPN sessions run as supervised child processes (WireGuard-Go, OpenVPN PQ).
* Rust side manages TUN/TAP, routes, keys (from Vault).
* Metrics polled every 2s, streamed to UI.

---

## 4) Data Models

**VPN Profile**

```json
{
  "id":"vpn-001",
  "name":"Corp West DC",
  "proto":"wireguard",
  "endpoint":"vpn.corpwest.example.com:51820",
  "vaultKey":"vault://vpn/corpwest",
  "splitTunnel":false,
  "tags":["corp","west"],
  "policy":{"requireMFA":true,"allowSplitTunnel":false}
}
```

**VPN Status**

```json
{
  "sessionId":"sess-123",
  "profile":"vpn-001",
  "state":"connected",
  "latencyMs":34,
  "throughputMbps":120,
  "drops":2,
  "pqPosture":"hybrid",
  "ts":"2025-08-26T01:22Z"
}
```

---

## 5) Policy Hooks

Examples:

```toml
[[rules]]
id = "vpn-required-for-ssh"
resource = "tool.ssh"
action = "connect"
when = { hostTag = "prod" }
effect = "allow"
constraints = { requireVPN = true }

[[rules]]
id = "vpn-split-deny"
resource = "vpn.session"
action = "start"
when = { profileTag = "corp" }
effect = "deny"
constraints = { allowSplitTunnel = false }

[[rules]]
id = "vpn-mfa"
resource = "vpn.session"
action = "start"
when = { profileId = "vpn-001" }
effect = "allow"
constraints = { mfa = "always" }
```

---

## 6) UI / UX

### Sidebar & TopBar

* **Sidebar**: “VPN” entry → collapsible list of profiles.
* **TopBar**: VPN badge shows status:

  * Green = PQ secure
  * Purple = Hybrid
  * Amber = Classical (warning)
  * Red = Error

### Intel Panel

* Profile details: endpoint, tags, policy.
* Live metrics charts: throughput (Mbps), latency jitter timeline.
* Endpoint map: geolocate remote endpoint, neon pulsing marker.
* Log history: connects/disconnects, PQ posture.

### Workflow

* Select profile → click “Connect”.
* MFA prompt (if required) overlays with neon keypad/QR.
* Tunnel starts → Sidebar status flips green/purple/amber.
* Tools (SSH, PCAP, Browser) show “Bind to VPN” dropdown.

### Neon aesthetic

* Status indicators glowing dots with soft bloom.
* Metrics charts in neon cyan/pink lines.
* Endpoint map with glowing connection lines.

---

## 7) Security Hardening

* **Keys**: stored only in Vault, decrypted on connect, injected ephemeral, wiped on disconnect.
* **PQ handshakes**: Kyber KEM + Dilithium signatures; hybrid fallback allowed by policy only.
* **Split-tunnel**: disabled unless policy allows.
* **Logs**: PQ-signed, no plaintext keys or creds.
* **Quotas**: max concurrent sessions enforced by policy.
* **Fail-safe**: if VPN required and tunnel drops, bound tools auto-pause/deny traffic until reconnection.

---

## 8) Testing & QA

**Unit**

* VPN start/stop, profile parsing, PQ handshake verify.
* Metrics collection (latency, throughput).

**Integration**

* Start VPN with MFA → connect → metrics show.
* Deny when split-tunnel not allowed.
* Bind SSH session → confirm traffic routes through VPN.
* Log check: connect/disconnect entries signed.

**Security**

* Attempt to use expired Vault creds → blocked.
* Tamper with profile export → denied at import.
* Drop VPN while SSH bound → traffic halted until reconnection.

**Performance**

* Sustained 1 Gbps throughput with <1% CPU overhead.
* Latency overhead <10 ms for PQ-hybrid handshake.

---

## 9) Timeline (5–6 weeks)

**Week 1**

* ghost\_vpn crate skeleton; WireGuard-Go wrapper.
* PQ handshake integration (Kyber).

**Week 2**

* OpenVPN PQ fallback path.
* Vault integration (profile storage, key fetch).

**Week 3**

* Metrics collection (latency/throughput/drops).
* Policy enforcement hooks.

**Week 4**

* UI: Sidebar list, TopBar badge, Intel Panel metrics.
* MFA integration for profiles.

**Week 5**

* Per-tool binding flows (SSH, PCAP, Browser).
* GhostLog integration for all events.

**Week 6 (buffer)**

* Perf QA, cross-platform quirks (Win/macOS/Linux TUN drivers).
* Docs + training deck.

---

## 10) Deliverables

* **GhostVPN client** supporting PQ-hybrid handshakes.
* **Profiles stored in Vault**, policy/MFA-gated.
* **UI**: Sidebar, TopBar badge, Intel Panel metrics.
* **Per-tool binding** (SSH, PCAP, GhostBrowse).
* **Logging**: GhostLog signed entries.
* **Docs**: policy examples, usage workflows, PQ posture modes.

---

## 11) Handoff to Phase 8

* GhostVPN feeds into **Topology Visualizer** for edge highlighting.
* Metrics exportable into GhostMetrics (Phase 8+).
* Policy groundwork ready for compliance checks (Phase 12).

---

⚡ Do you want me to also draft a **“VPN Profile Policy Set”** (e.g., Corp VPNs = MFA always + no split-tunnel, Lab VPNs = allow hybrid, Prod VPNs = PQ-only) so your team has a ready baseline?
