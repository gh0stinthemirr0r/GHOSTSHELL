# GHOSTSHELL — Phase 4 Deep Dive

**Focus:** **Tools: Layers & Surveyor**
*(first wave of active network probing tools, integrated into the terminal + neon UI)*

---

## 1) Objectives & Success Criteria

**Objectives**

* Deliver the **first integrated analyst tools** (Layers + Surveyor) that live inside GhostShell.
* Ensure tools are **post-quantum secure** (results, logs, exports all PQ-signed, traffic tunneled via GhostVPN if policy requires).
* Provide a **sleek neon visual + terminal output** with optional structured exports.
* Enforce **Policy Engine** decisions before probes run (no wild scans without approval).
* Log all tool usage into **GhostLog** with PQ signatures.

**Success Criteria**

* Users can run **Layers** (OSI probe) and **Surveyor** (throughput + port/service enumeration) from sidebar, command palette, or inside a terminal pane.
* Results stream to terminal pane **and** can open in a frosted **Intel Panel** with structured data + neon charts.
* Policy can restrict targets, ports, frequency. Violations → blocked, logged, and neon alert toast.
* Exports (JSON, CSV, PDF) are PQ-signed and sealed.
* All tool runs emit GhostLog entries (who, when, target, scope, policy decision, signed hash of output).

---

## 2) Scope (Phase 4 delivery)

### **Layers (OSI Probe)**

* Target: host/IP.
* Steps (per layer):

  * L2: ARP/LLDP discovery (if local subnet).
  * L3: ICMP ping, traceroute.
  * L4: TCP/UDP handshake probes (select ports).
  * L5: TLS hello (check PQ/hybrid/ciphers).
  * L6: Application handshakes (SSH banner, HTTP headers, SMTP EHLO).
  * L7: DNS/HTTP requests for metadata.
* Output:

  * Terminal waterfall (layer-by-layer status).
  * Intel Panel summary with collapsible layers.
  * Export: JSON bundle with PQ signature.

### **Surveyor (Throughput + Enumeration)**

* Target: host/IP.
* Functions:

  * Port scan (safe default: 100 common ports; full/range if policy allows).
  * Service enumeration (banner grab, protocol negotiation).
  * Throughput test (iperf-style; PQ-secure sockets preferred).
  * Latency jitter test (multiple pings).
* Output:

  * Terminal table (open ports, services, versions).
  * Intel Panel with neon bar charts (throughput, latency).
  * Export: JSON/CSV/PDF report with PQ signature.

### Shared features

* Policy integration:

  * Rules like `"allow scan only 22,443"` or `"deny sweep of >50 hosts"`.
  * Rate-limiting, scope restrictions.
* Logging: every run hashed + signed in GhostLog.
* Exports: PQ-signed bundles (Dilithium) with verification option.

---

## 3) Architecture

```
crates/
  ghost_layers/      # OSI probe orchestrator
  ghost_surveyor/    # throughput + port/service scanner
  ghost_export/      # signed report generators (JSON, CSV, PDF)
  ghost_chart/       # neon chart rendering helpers (for Intel Panel UI)

src-tauri/commands/
  tools.rs
    layers_run(target, opts) -> RunId
    surveyor_run(target, opts) -> RunId
    tool_status(runId) -> {progress, logs, results}
    tool_export(runId, format) -> Path
```

**Execution model**

* Tools run in Rust side (using `tokio` async).
* Stream progress/events over IPC (event channel).
* UI shows terminal text + optional Intel Panel structured view.
* Results sealed → hash → GhostLog event → optional export.

**Dependencies**

* For scanning: `trust-dns-resolver`, raw sockets (pcap), or `nmap`-like engine (Rust crates: `pnet`, `tokio` sockets).
* For throughput: internal iperf-like Rust crate with PQ TLS handshake (Kyber key exchange, Dilithium signing).

---

## 4) Data Models

**Layers Result**

```json
{
  "target":"10.0.0.5",
  "ts":"2025-08-25T22:01Z",
  "layers":[
    {"layer":2,"arp":"00:11:22:33:44:55","lldp":null},
    {"layer":3,"icmp":"reply in 12ms","traceroute":["10.0.0.1","10.0.0.5"]},
    {"layer":4,"tcp":{"22":"open","443":"open"}},
    {"layer":5,"tls":{"443":"pq-hybrid(kem=kyber768)" }},
    {"layer":6,"ssh":{"banner":"OpenSSH_9.0"}},
    {"layer":7,"http":{"server":"nginx","title":"Gateway"}}
  ],
  "signature":"dilithium-sig..."
}
```

**Surveyor Result**

```json
{
  "target":"db.internal",
  "ts":"2025-08-25T22:05Z",
  "ports":[
    {"port":22,"service":"ssh","version":"OpenSSH_9.0"},
    {"port":443,"service":"https","tls":"pq-hybrid"}
  ],
  "throughput":{"sendMbps":942,"recvMbps":915},
  "latency":{"avgMs":12,"jitterMs":1.3},
  "signature":"dilithium-sig..."
}
```

---

## 5) Policy Hooks

Examples:

```toml
[[rules]]
id = "safe-scan"
resource = "tool.surveyor"
action = "scan"
when = { role = "analyst" }
effect = "allow"
constraints = { max_hosts = 1, max_ports = 100 }

[[rules]]
id = "layers-internal-only"
resource = "tool.layers"
action = "run"
when = { target_cidr = "10.0.0.0/8" }
effect = "allow"

[[rules]]
id = "deny-sweeps"
resource = "tool.surveyor"
action = "scan"
when = { targets = ">50" }
effect = "deny"
```

---

## 6) UI / UX

### Entry points

* **Sidebar Tools menu**: Layers, Surveyor.
* **Command Palette**: “Run Layers on 10.0.0.5”, “Surveyor scan db.internal”.
* **Terminal command**: `:layers 10.0.0.5`, `:surveyor db.internal`.

### Output UX

* **Terminal**:

  * Layers: waterfall like

    ```
    [L2] ARP 00:11:22:33:44:55
    [L3] ICMP reply 12ms
    [L4] TCP 22 OPEN, 443 OPEN
    [L5] TLS PQ-HYBRID Kyber768
    ...
    ```
  * Surveyor: table of ports/services + throughput summary.
* **Intel Panel**:

  * Layers: collapsible by layer; traceroute graph.
  * Surveyor: bar chart throughput; scatter jitter.
  * Export buttons (JSON/CSV/PDF).
* **Neon touches**: glowing progress bar; per-layer icons with accent colors; animated traceroute hops.

### Policy/Log feedback

* If blocked: terminal shows neon red message → “Denied by Policy (Rule: deny-sweeps)”.
* GhostLog entry created with full context.

---

## 7) Security Hardening

* **Rate limiting**: all probes throttled by Policy constraints.
* **Isolation**: spawn as restricted worker (low privilege, no file write except quarantine).
* **Secrecy**: results sealed & signed; no plaintext logs.
* **Vault integration**: credentials (if needed for throughput test) pulled only from Vault; ephemeral use.
* **GhostLog**: signed log per run (who, when, target, scope, hash of result).
* **PQ by default**: throughput test sockets use PQ-TLS (Kyber + Dilithium); else fallback flagged in results.

---

## 8) Testing & QA

**Unit**

* Probe modules (L2, L3, L4, TLS handshake parser).
* Throughput measurement correctness vs iperf baseline.
* Port enumeration detection.

**Integration**

* Run Layers on internal host → see ARP/ICMP/TCP/TLS/HTTP.
* Run Surveyor on host → port scan table + throughput chart.
* Export → verify signature + import preview.

**Policy**

* Deny scan >50 hosts → blocked with log.
* Allow only internal CIDRs → external target blocked.
* MFA prompt if “high sensitivity” tag.

**Performance**

* Layers run typical host in <10s.
* Surveyor scan 100 ports in <5s.
* Throughput run stable up to 1Gbps.

---

## 9) Timeline (4–5 weeks)

**Week 1**

* ghost\_layers crate: ICMP, traceroute, TCP/UDP probes.
* ghost\_surveyor crate: port scan skeleton; throughput engine stub.

**Week 2**

* TLS handshake parsing; service banners.
* Throughput engine PQ TLS handshake; baseline measurement.

**Week 3**

* IPC commands + UI integration; terminal streaming; Intel Panel views.
* Policy hooks enforcement.

**Week 4**

* Export (JSON/CSV/PDF) with PQ signature.
* GhostLog integration; UI polish (charts, traceroute graph).

**Week 5 (buffer)**

* Perf tuning; cross-platform quirks; error UX; docs.

---

## 10) Deliverables

* **Layers tool** (full OSI probe) with terminal + Intel Panel views, PQ-signed exports.
* **Surveyor tool** (ports/services, throughput, latency) with terminal + Intel Panel views, PQ-signed exports.
* **Policy enforcement** for target/port/scope.
* **GhostLog integration** (audit signed entries).
* **UI**: Sidebar entries, Command Palette commands, neon Intel Panel charts.
* Docs: usage, exports, policy examples.

---

## 11) Handoff to Phase 5

* PCAP Studio will use the same export/log pipeline and terminal + Intel Panel model.
* Surveyor throughput engine can be reused for PCAP correlation.
* Layers + Surveyor results will feed into **Topology Visualizer** (Phase 8) as nodes/edges.

---

Would you like me to also design **policy preset templates** (Safe Scan, Internal Only, Red Team Mode) so your team can just drop them in for Surveyor/Layers?
