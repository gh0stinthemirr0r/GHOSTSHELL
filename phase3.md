# GHOSTSHELL — Phase 3 Deep Dive

**Focus:** **SSH Manager** + **Terminal Hardening** (on top of Phase-1 UI shell and Phase-2 security foundations)

---

## 1) Objectives & Success Criteria

**Objectives**

* Ship a **professional-grade SSH Manager** with PQ/hybrid posture, vault-backed keys, per-host policy, and fast, safe connect flows.
* Harden the **Terminal** against escape/clipboard/URL/OSC vectors; wire it to managed PTYs and SSH sessions.
* Provide a crisp, neon **negotiation/health UI** (KEX/SIGN/CIPHER posture: PQ / Hybrid / Classical).
* All actions enforced by **Policy Engine v1** and immutably recorded in **GhostLog**.

**Success Criteria**

* Connect to hosts via **policy-approved algorithms** (PQ preferred/hybrid allowed/classical blocked per policy).
* Keys come **only** from GhostVault; ephemeral on disk; MFA prompts honored.
* Terminal protects clipboard/links/OSC; **inline error hints** appear (Phase-13 AI hooks stubbed now).
* Host key pinning + verification flow; known\_hosts stored in Vault; **every** connect/logoff/forward event logged.

---

## 2) Scope (what ships in Phase 3)

### SSH Manager (v1)

* **Host inventory**: folders/tags/search; latency probe; last success.
* **Connection Sheet**: profile, key, policy preview, **VPN binding** selector, preflight.
* **Key mgmt**: Ed25519, NTRU-hybrid (sntrup761), OQS-OpenSSH keys (optional build); **all stored in Vault**.
* **Host key pinning** & known\_hosts (Vault-backed).
* **Port forwarding UI**: local/remote/Dynamic (SOCKS5) with policy gates.
* **Multiplexing** (optional): ControlMaster/ControlPath for faster re-connects.
* **Per-host policy**: PQ required? VPN required? MFA to use key? StrictHostKeyChecking mode.

### Terminal Hardening

* **PTY sandbox**: managed child processes only (local shell, ssh client).
* **Escape filtering**: dangerous OSCs disabled by default (esp. OSC 52 clipboard), bracketed-paste enforced.
* **Link safety**: OSC-8 links open in **GhostBrowse** only; explicit user confirm.
* **Clipboard guard**: copy subject to auto-clear (Phase-2); paste redaction option.
* **Env hygiene**: scrub PATH/LD\_\*/TMP, restricted TERM overrides.

### Integrations

* **Policy Engine**: `connect`, `forward`, `agent`, `clipboard`, `download`.
* **GhostVault**: keys & secrets; MFA prompts.
* **GhostVPN**: optional per-session binding.
* **GhostLog**: chain-signed events (connect, auth, algs, pinning, forwards, errors).

*Out of scope (later phases): SFTP UI, file sync, session recording/replay, remote command templates (will land in 4/5/9).*

---

## 3) Architecture

```
crates/
  ghost_pty/        # PTY abstraction (portable-pty/conpty), spawn & IO
  ghost_ssh/        # SSH orchestration: profiles, preflight, spawn client, forwards
  ghost_agent/      # Vault-backed SSH agent (optional), per-use approval
  ghost_known/      # known_hosts & host key pinning (Vault storage)
  ghost_preflight/  # alg/cipher policy pre-check, reachability, latency probe

src-tauri/commands/
  ssh.rs       # connect, disconnect, list_hosts, test_policy, forward_start/stop
  agent.rs     # start/stop agent, add/remove key handles
  pty.rs       # spawn_local_shell, write/read, resize
  known.rs     # pin_hostkey, list_pins
```

**Backends**

* **Stable path:** managed **OpenSSH** client as a child process (strict flags), hybrid KEX (e.g., `sntrup761x25519` where available).
* **PQ option:** ship an **OQS-OpenSSH** client binary (opt-in) to negotiate Kyber/Dilithium hybrids; enforced via policy.

**Key handling**

* Keys decrypted from Vault → written to **ephemeral** memfd/secure-temp (0600) → wiped on teardown.
* Agent mode (optional): Vault backs an internal agent; per-use approval/mfa; agent socket is per-session and cleaned up.

---

## 4) Data Models (concise)

**Host**

```json
{
  "id":"host-001","name":"edge-router",
  "addr":"10.0.0.1","port":22,"user":"ops",
  "tags":["prod","router"],
  "policy":{"requirePQ":true,"requireVPN":false,"strictHostKey": "pin"},
  "keyRef":"vault://keys/ops-edge",
  "proxyJump": null,
  "forwardDefaults": {"local":[],"remote":[],"dynamic":false}
}
```

**ConnectionProfile**

```json
{
  "cipherPolicy":{"pq":"prefer","classical":"deny"},
  "vpnProfile": "corp-wg",
  "agentRequired": true,
  "mfaOnKeyUse": true
}
```

**PreflightResult**

```json
{
  "reachability":"ok","latencyMs":12,
  "algs":{"kex":["sntrup761x25519"],"hostkey":["ssh-ed25519"],"cipher":["chacha20-poly1305@openssh.com"]},
  "policy":"allow","notes":["Hybrid KEX meets PQ policy"]
}
```

---

## 5) Connection Flow (end-to-end)

1. User clicks **Connect** → **Connection Sheet** opens (profile/key/policy shown).
2. **Preflight** runs: reachability + algo availability + policy decision (no creds used yet).
3. If policy OK, **Vault** unlock (MFA if needed) → key materialized to ephemeral path or agent loaded.
4. **Spawn client**:

   * Bind to **GhostVPN** if required.
   * Strict flags: `-oStrictHostKeyChecking=yes|accept-new` per policy, `-oIdentitiesOnly=yes`, disable SSH\_ASKPASS, sanitized env.
   * ControlMaster/ControlPath if multiplexing enabled (per policy).
5. **Hostkey check**: if new/mismatch → neon **pinning dialog** with fingerprint + policy guidance; user action → **GhostLog** event.
6. On success: **Terminal pane** attaches; negotiation details banner shows KEX/SIGN/CIPHER posture (**color-coded**: cyan=PQ, purple=hybrid, amber=classical).
7. Throughout session: copy/paste & link opens go through Policy; forwards can be added from the **Forwards** mini-panel.
8. Disconnect → wipe ephemeral keys, close agent socket, log session summary.

---

## 6) Terminal Hardening (details)

* **Escape/OSC policy**

  * **Disable** risky OSC by default: OSC 52 (clipboard), OSC 7 (cwd leak), OSC 9 (notifications) unless allowed by policy.
  * **Bracketed paste** on; sanitize CR/LF; optional “strip ANSI on paste” toggle.
* **Link handling**

  * Convert OSC-8/URL regex into **clickable chips** with confirm; default opener is **GhostBrowse** (policy-aware).
* **Clipboard**

  * Copy subject to Phase-2 **auto-clear timer**; log lengths only; “mask on copy preview” option.
* **PTY limits**

  * Rate-limit writes to avoid UI stalls; backpressure over IPC; resize events debounced.
* **Env**

  * Strict `TERM` list; `LANG/LC_*` sanitized; `SSH_AUTH_SOCK` set only if internal agent on.

---

## 7) UI / UX

### SSH Manager

* **Sidebar**: tags/folders; fuzzy search; host health dots (green/yellow/red).
* **Host cards**: name, addr, **PQ posture badge**, last success, latency spark.
* **Intel Panel**: pinning status, keys, policy diffs, last errors, quick actions (Connect/Test Policy/Open Terminal Here).
* **Connection Sheet**: profile selector, key dropdown (Vault), **VPN binding**, policy preview (pass/warn/block with reasons), **Dry-Run** link.
* **Forwards Drawer**: add/remove local/remote/Dynamic; per-forward policy badges.

### Terminal

* Negotiation banner on connect:

  * `KEX: sntrup761x25519` (purple “Hybrid”), `HOSTKEY: ssh-ed25519`, `CIPHER: chacha20-poly1305`
* **Inline error chips** (stub for Phase-13 AI): e.g., “Permission denied (publickey)” → open **Why?** sheet with likely causes.
* **Context menu**: Split pane, Change Profile, Start Capture (PCAP), Run Layers/Surveyor here.

---

## 8) Policy Hooks (examples)

* `ssh.connect` → conditions: `requirePQ`, `requireVPN`, `role in ["ops","admin"]`, `time window`, `host.tags`.
* `ssh.forward.local` → allow only for certain ports/subnets; MFA required if `db` tag.
* `ssh.agent.use` → per-use approval with reason; max session lifetime.
* `terminal.clipboard.copy` → constraints: `auto_clear_ms`, `mask_preview`.
* `hostkey.pin` → admin-only; “accept-new” allowed for staging envs.

---

## 9) IPC (typed)

**ssh.rs**

* `ssh_list_hosts(filter?) -> [HostMeta]`
* `ssh_test_policy(hostId, profileId) -> PreflightResult`
* `ssh_connect(req) -> {paneId}`
* `ssh_disconnect(paneId) -> Ok`
* `ssh_forward_start(paneId, {type:"L|R|D", bind, host, port}) -> {id}`
* `ssh_forward_stop(paneId, id) -> Ok`

**agent.rs**

* `agent_start() -> {socketPath}`
* `agent_add_key(vaultKeyRef, ttl) -> {fingerprint}`
* `agent_stop() -> Ok`

**known.rs**

* `known_list(hostId?) -> [Pin]`
* `known_pin(hostId, fingerprint, algo) -> Ok`
* `known_remove(hostId) -> Ok`

**pty.rs**

* `pty_spawn_local(profile?) -> {paneId}`
* `pty_write(paneId, bytes)` / `pty_resize(paneId, cols, rows)`

*(All audited by Policy; logs emitted.)*

---

## 10) Security Hardening

* **Child process sandbox**: restricted env, cwd, and PATH; disallow shell expansion in our code paths (structured args only).
* **Key hygiene**: memfd/secure temp; `chmod 600`; wipe on drop; never echo private keys to logs; redacted fingerprints only.
* **Host key pinning**: mismatch → block by default; override requires admin & justification (logged).
* **VPN binding**: route all SSH traffic through a chosen GhostVPN profile (policy).
* **Logging**: do not log plaintext command content; only metadata & decisions.
* **Crypto agility**: allow **hybrid** now; full PQ via OQS client behind policy flag.

---

## 11) Testing & QA

**Unit**

* Preflight policy evaluator (edge cases).
* known\_hosts parser & pin compare; mismatch detection.
* Agent add/remove; TTL expiry.

**Integration**

* Connect success/fail with/without VPN; pin accept-new path; pin mismatch block.
* Forward start/stop & traffic smoke test; policy block tests (restricted ports).
* Clipboard/paste policies in active SSH pane.

**Security**

* Craft malicious OSC sequences → verify filtered.
* Attempt to use external keys / file paths → blocked by policy.
* Simulate MITM (host key changed) → neon warning + block + log.

**Performance**

* Connect → prompt ≤ **1.0 s** on LAN; reconnect with ControlMaster ≤ **200 ms**.
* Terminal sustained I/O 60–120 FPS; low latency echo.

---

## 12) Timeline (4–6 weeks)

**Week 1**

* ghost\_pty crate; spawn local shell; terminal piping stable.
* ghost\_known + Vault storage; pinning flows.

**Week 2**

* ghost\_ssh orchestration (OpenSSH child + strict flags); Preflight engine; policy wiring.
* Connection Sheet UI + negotiation banner.

**Week 3**

* Agent crate + Vault key unlock; per-use approval/MFA; ephemeral key files.
* Port forwarding UI + policy.

**Week 4**

* Terminal hardening (OSC filters, bracketed paste, link confirm); VPN binding option.
* Logging (connect, pinning, forwards, errors).

**Week 5 (buffer)**

* Multiplexing, perf polish, error UX; docs & CI.
* Optional: OQS client integration behind feature flag.

**Week 6 (if needed)**

* Cross-platform quirks (Windows conpty, macOS sandbox), final QA.

---

## 13) Deliverables

* **SSH Manager v1** with vault-backed keys, policy preflight, VPN binding, pinning, forwards.
* **Terminal hardening** complete (escape/clipboard/link policies, PTY sandbox).
* **Negotiation posture UI** (PQ/Hybrid/Classical) + health/latency.
* **Agent (optional)** with per-use approvals.
* **GhostLog** coverage for all SSH/Terminal events.
* Docs: admin policy examples (strict vs hybrid), user connect guide.

---

## 14) Handoff to Phase 4+

* Tools (Layers/Surveyor) can now **run inside SSH panes** or side-by-side.
* Vault/Policy already wired → SFTP UI, file transfer, remote command templates are straightforward next steps.
* OQS-OpenSSH path can be toggled on per-org to raise PQ posture without destabilizing the stable path.

If you want, I can generate **policy presets** (“Strict PQ”, “Hybrid Prod”, “Dev Sandbox”) and the exact **OpenSSH flag sets** we’ll use so your team can copy/paste into implementation.
