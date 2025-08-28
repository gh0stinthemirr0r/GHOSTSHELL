# GHOSTSHELL — Phase 5 Deep Dive

**Focus:** **PCAP Studio** — live packet capture + GPU-accelerated analysis

---

## 1) Objectives & Success Criteria

**Objectives**

* Build a **post-quantum secure PCAP capture + analysis engine** inside GhostShell.
* Enable **live capture, offline import, and structured GPU-assisted analysis** (flow breakdown, anomalies, service fingerprinting).
* Integrate with **Policy Engine** (which interfaces, hosts, or BPF filters are allowed) and **GhostVault** (for storing sensitive captures or keys for decryption).
* Provide a **sleek neon UI**: terminal summaries + Intel Panel with charts and filters.
* Record capture runs immutably in **GhostLog**, results sealed with PQ signatures.

**Success Criteria**

* User can **start/stop live captures** on allowed interfaces or **import PCAPs**.
* Policy restrictions (allowed interfaces, filters, max duration) enforced and logged.
* Intel Panel displays **flows, top talkers, service distribution, anomalies** with neon charts.
* Exports available as PQ-signed PCAP bundles, JSON flow summaries, CSV tables, and PDF reports.
* GPU decoding (via wgpu or CUDA/OpenCL) achieves **10+ Gbps parsing** without loss.

---

## 2) Scope (Phase 5 Delivery)

### Capture Engine

* Live capture: interfaces enumerated, only allowed per Policy.
* Filters: BPF expressions, sanitized and validated before use.
* Duration/size limits: enforced by Policy (e.g., max 60s, max 100 MB).
* Secure storage: rolling buffer in memory; optional sealed file in Vault.

### Analysis Features

* Flow reconstruction (5-tuple: src/dst/proto/ports).
* Protocol parsing: TCP/UDP/ICMP/HTTP/SSH/TLS.
* TLS metadata: PQ/hybrid handshake detection.
* Anomaly detection: malformed packets, unusual ports, high latency, retransmits.
* Top-N views: top talkers, top services, protocol breakdown.
* Entropy measure: randomness analysis for PQ crypto streams.

### UI Output

* **Terminal**:

  ```
  [CAPTURE] Started on eth0 filter="tcp port 22"
  Flow: 10.0.0.5:1234 → 10.0.0.1:22 proto=TCP pkts=150 bytes=112k
  Anomaly: malformed TLS handshake (packet #240)
  [CAPTURE] Ended: 12s duration, 112 MB, 150 flows
  ```
* **Intel Panel**:

  * Flow table (sortable, searchable).
  * Neon donut chart: protocols/services.
  * Bar chart: top talkers.
  * Timeline chart: packets/sec, bytes/sec.
  * Alerts list: anomalies flagged in neon red.

### Export Options

* PCAP file (sealed, PQ-signed).
* JSON summary (flows, services, anomalies).
* CSV table (flows).
* PDF report (charts + signed evidence bundle).

---

## 3) Architecture

```
crates/
  ghost_pcap/       # capture & parse engine (tokio + pcap)
  ghost_gpu/        # GPU decode/analysis (wgpu kernels)
  ghost_proto/      # protocol parsers (HTTP, TLS, SSH, DNS)
  ghost_export/     # PQ-signed report/export (reuse from Phase 4)

src-tauri/commands/tools.rs
  pcap_start(iface, filter, opts) -> RunId
  pcap_stop(runId) -> Path
  pcap_status(runId) -> {progress, stats, flows}
  pcap_import(path) -> RunId
  pcap_export(runId, format) -> Path
```

**Execution model**

* Capture workers run in async tasks, pinned to restricted threads.
* GPU kernels handle parsing & flow table generation.
* Events streamed over IPC to UI (terminal + Intel Panel).
* Results sealed and signed on completion.

---

## 4) Data Models

**CaptureMeta**

```json
{
  "runId": "cap-2025-08-25-001",
  "iface": "eth0",
  "filter": "tcp port 22",
  "started": "2025-08-25T23:01Z",
  "ended": "2025-08-25T23:13Z",
  "packets": 124512,
  "bytes": 98765432,
  "flows": 150
}
```

**FlowRecord**

```json
{
  "src":"10.0.0.5","dst":"10.0.0.1","proto":"tcp",
  "sport":1234,"dport":22,
  "pkts":150,"bytes":112340,
  "anomalies":["tls-handshake-malformed"]
}
```

**Export Bundle**

```json
{
  "meta":{...},
  "flows":[...],
  "anomalies":[...],
  "signature":"dilithium-sig..."
}
```

---

## 5) Policy Hooks

Examples:

```toml
[[rules]]
id = "allow-ssh-capture"
resource = "tool.pcap"
action = "capture"
when = { iface = "eth0", filter = "tcp port 22" }
effect = "allow"
constraints = { max_duration_s = 60, max_size_mb = 100 }

[[rules]]
id = "deny-wireless"
resource = "tool.pcap"
action = "capture"
when = { iface = "wlan0" }
effect = "deny"
```

---

## 6) UI / UX

### Entry points

* **Sidebar Tools → PCAP Studio**
* **Command Palette**: `:pcap start eth0 tcp port 22`
* **Terminal**: `:pcap start eth0` → streams events inline

### Intel Panel Layout

* Top: **Capture Meta** (iface, filter, duration, packets).
* Center: **Flow Table** with neon glow selection, sort/filter.
* Right: **Charts**

  * Protocol donut (TCP/UDP/ICMP/Other).
  * Top talkers bar chart.
  * Throughput timeline.
* Bottom: **Anomalies** in neon red panel (click → details).

### Export Panel

* Frosted glass card with export format buttons (JSON/CSV/PDF/PCAP).
* Exports stamped with PQ signature, includes verify button.

---

## 7) Security Hardening

* **Privilege**: capture runs only if policy permits; root/admin requirement flagged.
* **BPF filters** validated against whitelist before run.
* **Quotas**: max packets/bytes/time enforced in Rust worker.
* **Data protection**: in-memory ring buffer; flush to sealed file if saved.
* **Vault integration**: optional encryption keys for TLS/SSH decryption stored in Vault.
* **GhostLog**: signed event for every run (iface, filter, limits, output hash).
* **Export integrity**: Dilithium signature attached to each export bundle.

---

## 8) Testing & QA

**Unit**

* PCAP parsing correctness (pkt headers, timestamps).
* Flow aggregation correctness.
* Protocol parsers: TLS hello, HTTP headers, SSH banners.

**Integration**

* Start/stop capture on allowed interface.
* Deny on restricted iface (policy enforcement).
* Export & verify signature.
* Import external PCAP & analyze.

**Security**

* Malicious filter string injection → sanitized.
* Large PCAP (10GB) → ring buffer enforces limits, no crash.
* Attempt to write outside export dir → blocked.

**Performance**

* GPU decode ≥ 10Gbps sustained with <2% packet loss.
* UI can handle 100k flows without lag (virtualized table).

---

## 9) Timeline (5–6 weeks)

**Week 1**

* ghost\_pcap crate; capture skeleton; BPF filter validation.
* ghost\_gpu crate: baseline GPU decode pipeline.

**Week 2**

* Flow aggregation; protocol parsers (TCP/UDP/ICMP/HTTP/TLS).
* Policy checks + GhostLog integration.

**Week 3**

* Intel Panel UI: flow table, charts, anomalies panel.
* Terminal streaming integration.

**Week 4**

* Export formats (PCAP sealed, JSON/CSV, PDF with charts).
* PQ signing for exports.

**Week 5**

* GPU perf tuning (10 Gbps target).
* UI polish, accessibility (filters, contrast).

**Week 6 (buffer)**

* QA matrix (perf, policy, export verification).
* Docs & training deck.

---

## 10) Deliverables

* **PCAP Studio v1**: live capture + offline import.
* **Intel Panel** with flow table, charts, anomalies.
* **Terminal integration** with streaming summaries.
* **Export formats** (PCAP/JSON/CSV/PDF), PQ-signed.
* **Policy enforcement** (ifaces, filters, quotas).
* **GhostLog integration** with signed capture events.
* GPU acceleration to ≥10 Gbps sustained parse.
* Docs: analyst workflows, policy examples, signature verification guide.

---

## 11) Handoff to Phase 6

* PCAP Studio flows feed directly into **GhostVault** (secrets for decrypt keys) and **Topology Visualizer** (Phase 8).
* Export/signature framework reused by **Report Templates** (Phase 9).
* PQ posture detection in TLS flows will enhance **Compliance Dashboard** (Phase 12).

---

⚡ Do you want me to also draft **an example anomaly-detection ruleset** (like malformed TLS, duplicate MACs, weird ports) that PCAP Studio should flag out of the box? That would give analysts immediate value in day one deploy.
