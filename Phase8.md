# GHOSTSHELL — Phase 8 Deep Dive

**Focus:** **Topology Visualizer + NetFlow/sFlow ingestion**
*(turning Layers, Surveyor, and PCAP results into an interactive neon cyberpunk network map)*

---

## 1) Objectives & Success Criteria

**Objectives**

* Build the **Topology Visualizer**, a GPU-accelerated interactive neon map that fuses data from **Layers**, **Surveyor**, **PCAP Studio**, and **VPN sessions**.
* Add **NetFlow/sFlow ingestion** to integrate passive telemetry for context beyond active probes.
* Provide **analyst workflows**: zoomable graph, drill into nodes/edges, overlay anomalies and policy posture.
* PQ-sign and log topology snapshots for audit and reporting.

**Success Criteria**

* Analyst can launch **Topology Visualizer** from Sidebar or directly from a tool run (Layers/Surveyor/PCAP).
* Nodes/edges drawn in neon, animated layout; colors reflect role/policy/posture.
* NetFlow/sFlow streams ingested and merged with active probe data.
* Anomalies glow red; VPN tunnels appear as glowing arcs.
* Snapshot/export produces PQ-signed JSON/PNG/PDF for compliance or incident reports.

---

## 2) Scope (Phase 8 Delivery)

### Graph Core

* Data ingestion:

  * **Active**: Layers (traceroute, port/services), Surveyor (open ports, throughput), PCAP Studio (flows).
  * **Passive**: NetFlow v5/v9/IPFIX, sFlow.
* Graph model: nodes = hosts/interfaces, edges = flows (active or passive).
* Attributes: latency, throughput, PQ posture, anomalies, tags.
* Time dimension: toggle between “now” and historic slices.

### Visualization

* GPU-accelerated graph (WebGPU via Three.js/Regl or Rust wgpu).
* Layout: force-directed with neon glowing edges.
* Node glyphs:

  * Device type (router, switch, server, endpoint) → icon + color.
  * Role tags (prod, db, vpn, user).
  * Policy posture (green=OK, amber=warning, red=violation).
* Edge styling:

  * Width = throughput.
  * Color = PQ posture (cyan=PQ, purple=hybrid, amber=classical).
  * Pulse animation for live flows.

### Intel Panel Integration

* Node details: tags, services, last probe/flow info.
* Edge details: protocol, throughput, anomalies.
* Filters: by tag, role, posture, anomaly type.
* Export: PQ-signed JSON graph, PNG screenshot, PDF summary.

### Logging

* GhostLog entry for each topology snapshot: hash + Dilithium signature.
* Policy-restricted features (e.g., hide external nodes) enforced.

---

## 3) Architecture

```
crates/
  ghost_topology/     # graph model, merge engine
  ghost_flow/         # NetFlow/sFlow collectors
  ghost_viz/          # GPU viz pipeline, layout
  ghost_export/       # signed graph export

src-tauri/commands/topology.rs
  topo_build(sourceIds[], opts) -> GraphId
  topo_update(graphId, newData) -> Ok
  topo_export(graphId, format) -> Path
  topo_stream_flows() -> EventStream
```

**Execution model**

* Ingest active probe results → normalize into Graph model.
* Flow collectors run async, stream NetFlow/sFlow into Graph.
* GPU renderer in WebView draws graph; interactions trigger IPC queries.
* Export pipeline seals graph state + PQ-signs manifest.

---

## 4) Data Models

**Graph Node**

```json
{
  "id":"host-10.0.0.5",
  "ip":"10.0.0.5",
  "type":"server",
  "tags":["prod","db"],
  "services":[22,443],
  "policyPosture":"ok",
  "metrics":{"latencyMs":12,"throughputMbps":220}
}
```

**Graph Edge**

```json
{
  "src":"host-10.0.0.5",
  "dst":"host-10.0.0.1",
  "proto":"tcp",
  "ports":[22],
  "throughputMbps":50,
  "pqPosture":"hybrid",
  "anomalies":["tls-handshake-malformed"]
}
```

**Graph Export Bundle**

```json
{
  "graphId":"topo-2025-08-26-01",
  "nodes":[...],
  "edges":[...],
  "ts":"2025-08-26T03:15Z",
  "signature":"dilithium-sig..."
}
```

---

## 5) Policy Hooks

Examples:

```toml
[[rules]]
id = "topology-hide-external"
resource = "topology.graph"
action = "build"
when = { nodeType = "external" }
effect = "deny"

[[rules]]
id = "flow-collector-internal-only"
resource = "topology.flow"
action = "ingest"
when = { iface = "corp-lan" }
effect = "allow"
```

---

## 6) UI / UX

### Sidebar & Entry Points

* **Sidebar** → “Topology Visualizer”.
* **Command Palette**: “Visualize topology from last Surveyor run”.
* **Tool outputs**: “Open in Visualizer” button after Layers/Surveyor/PCAP.

### Visualization Window

* **Main Canvas**: neon graph, glowing edges, smooth force layout.
* **Controls**: zoom/pan, toggle layers (L2/L3/L4+), highlight anomalies.
* **Color legend**: PQ posture (cyan/purple/amber).

### Intel Panel

* Left: Node/Edge details.
* Right: Charts (flow counts, protocol breakdown).
* Bottom: timeline slider (select timeframe, replay flows).

### Neon Style

* Nodes glow in pink/blue hues; anomalies pulse in red.
* VPN tunnels = animated arcs with glow intensity based on throughput.
* Hover: neon tooltips with quick metrics.

---

## 7) Security Hardening

* **Policy-gated ingestion**: no external IPs unless explicitly allowed.
* **Data protection**: all flow data PQ-sealed if stored.
* **Access control**: topology export requires role=admin or auditor.
* **Performance guard**: flow ingestion throttled; graph capped at N nodes with collapse/aggregation.
* **GhostLog**: snapshots logged with signature for compliance.

---

## 8) Testing & QA

**Unit**

* Merge engine correctness: active + passive flow normalization.
* NetFlow/sFlow parsers (edge cases, malformed packets).

**Integration**

* Run Layers/Surveyor → open in Visualizer → nodes/edges match.
* Import NetFlow stream → graph updates live.
* Export → PQ signature verification passes.

**Security**

* Attempt to ingest from blocked iface → denied, logged.
* Try to export without role → blocked.
* Graph tampering attempt → PQ signature mismatch.

**Performance**

* Ingest 100k flows/minute → maintain <200 ms update latency.
* Render 1k nodes/10k edges at 60 FPS.

---

## 9) Timeline (5–6 weeks)

**Week 1**

* ghost\_topology crate; graph model; merge logic.
* ghost\_flow NetFlow/sFlow collectors.

**Week 2**

* GPU viz engine skeleton (WebGPU/Three.js).
* Basic node/edge rendering + layout.

**Week 3**

* Intel Panel integration (node/edge details).
* Flow ingestion → graph updates.

**Week 4**

* Export pipeline (PQ-signed JSON, PNG, PDF).
* Policy enforcement on ingestion/export.

**Week 5**

* Performance tuning (10k edges).
* Neon UI polish (animations, anomalies).

**Week 6 (buffer)**

* QA across platforms.
* Docs & analyst training guide.

---

## 10) Deliverables

* **Topology Visualizer v1**: neon GPU graph of active/passive flows.
* **NetFlow/sFlow ingestion** with merge into graph.
* **UI**: Sidebar entry, Intel Panel details, anomaly overlays.
* **Exports**: PQ-signed JSON/PNG/PDF bundles.
* **Policy enforcement** (targets, ifaces, exports).
* **GhostLog integration** for snapshot auditing.
* Docs: workflows, policy templates, analyst guide.

---

## 11) Handoff to Phase 9

* Graph snapshots + flow summaries will feed into **Report Templates** (Phase 9).
* GPU visualization pipeline reused for **PCAP anomaly heatmaps** (future expansion).
* Compliance Dashboard (Phase 12) can overlay policy posture directly on topology view.

---

⚡ Would you like me to also **design the exact node/edge color palette & animation effects** (so your devs know exactly how each role, anomaly, or PQ posture should glow)? That would lock in the cyberpunk aesthetic here.
