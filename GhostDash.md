# GHOSTSHELL — GhostDash Deep Dive

**Focus:** **System Dashboard + Glossy Queryable Network Table**
*(real-time system telemetry, network analytics, and command output in a cyberpunk neon interface)*

---

## 1) Objectives & Success Criteria

**Objectives**

* Deliver **GhostDash**, a comprehensive **system & network dashboard** within GhostShell.
* Provide high-level system health: system name, OS build, CPU load, memory usage.
* Add **network statistics & analytics**: bandwidth, packet loss, latency.
* Include a **queryable “Glossy Table”** with details normally retrieved from CLI commands:

  * `ipconfig /all` (interface details, addresses, DHCP, DNS suffixes).
  * DNS server details.
  * `route print` (routing table).
  * `netstat -an` (ports, connections, states).
* Allow analysts to **search, filter, and export** these datasets in real time.
* Ensure all results are **PQ-signed** and optionally logged into **GhostLog** for audit and forensics.

**Success Criteria**

* Dashboard shows **system card** (hostname, uptime, CPU/memory load).
* Network analytics (live throughput charts, latency, packet error rate).
* Queryable Table with tabs: **Interfaces, DNS, Routes, Connections**.
* Table supports **search, sort, filter, and export** (JSON/CSV/PDF).
* Data refresh intervals are configurable; all pulls run in sandbox with PQ integrity.

---

## 2) Scope (Phase N Delivery)

### Dashboard Overview

* **System Card:** system name, uptime, OS version, hardware ID.
* **Resource Monitor:** CPU %, Memory %, Disk I/O.
* **Network Analytics:** throughput graph, active connections, interface utilization.

### Queryable Tables (Glossy Mode)

1. **Interfaces** (from `ipconfig /all`):

   * Name, MAC, IPv4/IPv6, subnet mask, gateway, DHCP status, DNS suffix.
2. **DNS Servers:**

   * Interface mapping, primary/secondary DNS, resolver status.
3. **Routing Table** (from `route print`):

   * Destination, Netmask, Gateway, Interface, Metric.
4. **Connections** (from `netstat -an`):

   * Protocol, Local Address, Foreign Address, State, PID/Process.

### Actions

* **Search**: full-text across all columns.
* **Filter**: per column (e.g., “state=LISTENING”).
* **Export**: PQ-signed JSON/CSV/PDF.
* **Snapshot**: freeze current state, save to Vault.

---

## 3) Architecture

```
crates/
  ghost_dash/       # dashboard metrics + collectors
  ghost_netstat/    # netstat parser
  ghost_ipconfig/   # interface + DNS collector
  ghost_route/      # routing table parser
  ghost_export/     # table exports w/ PQ signatures
```

**Execution Model**

* Collectors execute native queries (cross-platform backends: Windows WMI/CMD, Linux `ip`/`ss`, macOS `networksetup/netstat`).
* Normalize results into JSON.
* Send to UI via IPC → render into glossy queryable tables.
* Exports PQ-signed with Dilithium.
* Logs optionally appended to GhostLog.

---

## 4) Data Models

**Interface Entry**

```json
{
  "id":"if-001",
  "name":"Ethernet0",
  "mac":"00-1C-42-2E-60-4A",
  "ipv4":"10.0.1.22",
  "ipv6":"fe80::21c:42ff:fe2e:604a",
  "mask":"255.255.255.0",
  "gateway":"10.0.1.1",
  "dhcp":true,
  "dnsSuffix":"corp.local"
}
```

**Route Entry**

```json
{
  "destination":"0.0.0.0",
  "mask":"0.0.0.0",
  "gateway":"10.0.1.1",
  "interface":"Ethernet0",
  "metric":25
}
```

**Connection Entry**

```json
{
  "proto":"TCP",
  "local":"10.0.1.22:443",
  "remote":"192.168.1.10:52345",
  "state":"ESTABLISHED",
  "pid":4221,
  "process":"nginx.exe"
}
```

---

## 5) UI / UX

### Layout

* **Sidebar Entry:** GhostDash.
* **Main View:** Split into **Top System Cards** + **Tabbed Table Panel**.

**Top Section (System Cards)**

* **System Card:** Hostname, OS, uptime, CPU/mem load.
* **Network Card:** total interfaces, throughput, errors, latency.
* **Alerts Card:** warnings (e.g., high packet loss, DNS unreachable).

**Bottom Section (Tabbed Tables)**

* **Tabs:** Interfaces | DNS | Routes | Connections
* **Table Style:** glossy neon, frosted background, 70% transparency.
* **Controls:** search box (top right), column filters (dropdown per header).
* **Export Button:** cyan glow, click → JSON/CSV/PDF options.
* **Snapshot Button:** pink glow, click → Vault store.

### Neon Theme

* Tables: black/slate acrylic background, neon pink header row, cyan highlight on hover.
* Selected row: neon green border glow.
* Filters: neon dropdowns with soft pulsing glow.
* Exec Mode: switches to plain white/blue data grid with subtle borders.

---

## 6) Policy & Security

* **Role gating:**

  * Normal users can view Interfaces/DNS.
  * Admins required for Routing Table & full Netstat.
* **Policy hooks**:

```toml
[[rules]]
id="deny-raw-netstat-nonadmin"
resource="ghostdash.connections"
action="view"
when={ role!="admin" }
effect="deny"
```

* **Logging:** All exports & snapshots PQ-signed + logged.
* **Sanitization:** PID → process name mapping optional; sensitive apps can be redacted by policy.

---

## 7) Testing & QA

**Unit**

* Netstat parser across platforms.
* Route table normalization.
* DNS server mapping correctness.

**Integration**

* Dashboard updates every 5s → tables update smoothly.
* Search/filter returns instant results.
* Export → PQ signature verified.

**Security**

* Attempt export without role → denied, toast alert.
* Tampered export → signature mismatch flagged.

**Performance**

* Tables handle 10k connections without UI lag (virtualized rows).
* Data refresh <200ms parse time.

---

## 8) Timeline (3–4 weeks)

**Week 1:** ghost\_ipconfig + ghost\_dns collectors; Interfaces & DNS tables.
**Week 2:** ghost\_route + ghost\_netstat parsers; Routes & Connections tables.
**Week 3:** UI build (cards + glossy tabbed tables); search/filter/export.
**Week 4 (buffer):** PQ signing, policy integration, performance QA.

---

## 9) Deliverables

* **GhostDash v1**: system cards, network analytics, tabbed tables.
* **Queryable glossy tables**: Interfaces, DNS, Routes, Connections.
* **Exports & snapshots**: PQ-signed JSON/CSV/PDF.
* **Policy hooks**: control access to sensitive data.
* **Neon UI**: frosted transparency, neon highlights, exec mode toggle.
* **Docs**: dashboard usage guide, schema references, policy templates.

---

## 10) Future Expansion

* GPU-accelerated graph of netstat flows (animated like Topology Visualizer).
* Correlation with PCAP Studio (per-connection deep dive).
* Integration with GhostAI (Phase 13): error hints for failed DNS resolution, routing loops, or half-open sockets.

---
