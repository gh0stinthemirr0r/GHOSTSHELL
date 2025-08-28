# GHOSTSHELL — Phase 2 Deep Dive

**Focus:** Secure Foundations — **Policy Engine**, **GhostVault (v1)**, **PQ crypto plumbing**, **Clipboard/Filesystem/I/O guards**, and **GhostLog (bootstrap)**. This phase turns the Phase-1 shell into a trustworthy workstation.

---

## 1) Objectives & Success Criteria

**Objectives**

* Establish a **policy-first runtime** that mediates all privileged actions (PTY, SSH, files, network, clipboard, downloads).
* Ship **GhostVault v1** for secrets + encrypted configs (replaces Phase-1 ad-hoc configs).
* Wire **post-quantum cryptography** end-to-end (Kyber KEM, Dilithium signatures, SHA3/Shake) with upgrade paths.
* Bootstrap **GhostLog** for chain-signed audit of sensitive actions.

**Success Criteria**

* Every sensitive operation goes through a **Policy::check()** gate; denial surfaces clear UI/AI guidance.
* Vault stores secrets/configs using **envelope encryption**, sealed with PQ KEM-wrapped master key, MFA-gated access.
* Clipboard is policy-controlled (copy timeouts, redaction, no auto-paste).
* GhostLog records hashes of: policy decisions, vault access, terminal spawn, download/quarantine events.
* All new IPC commands schema-validated on both UI and Rust sides.

---

## 2) Scope (what ships in Phase 2)

* **Policy Engine v1**

  * Declarative policy (TOML/JSON) + evaluator (Rust).
  * Subjects: user, role, MFA state, device posture (TPM/SE present).
  * Resources: **terminal**, **ssh**, **vault**, **vpn**, **browser**, **files**, **clipboard**, **network**.
  * Actions: read/write/exec/connect/download/autofill/copy.
  * Conditions: time, host tags, sensitivity tags, PQ-required, via-VPN, signed-by.
  * Outcomes: allow/deny/allow-with-justification (prompt).
* **GhostVault v1**

  * Secrets: passwords, SSH keys, API tokens, “config profiles” (replaces GhostConfig).
  * Storage: local encrypted store (SQLite + blob), envelope encryption with **AES-256-GCM** or **XChaCha20-Poly1305** under a **Vault Master Key (VMK)**.
  * **VMK sealing**: VMK wrapped with **Kyber** (TPM/SE key if present) + Dilithium signatures for state attest; MFA unlock.
  * CRUD, list, search; sealed export/import; per-entry access history.
* **PQ Crypto Plumbing**

  * Crate `ghost_pq`: Kyber/Dilithium (liboqs), SHA3/Shake, HKDF-SHA3.
  * Key management helpers, signature/verify API, versioned crypto headers.
* **Clipboard, FS & Download Guards**

  * Policy-gated copy; **auto-clear** timer; redact-on-blur option; “no rich text” mode.
  * Download quarantine (hash, size/type policy), optional YARA hook (stub).
* **GhostLog Bootstrap**

  * Append-only log with hash chaining (SHA3-256), Dilithium-signed batches, local storage.
  * Events: policy decisions, vault access, terminal spawn/exit, clipboard copied/cleared, downloads.
* **UI additions**

  * **Security & Policy** page (view/apply policy, dry-run tester).
  * **Vault** page v1 (grid + details + MFA prompt).
  * **Download/Quarantine** drawer.
  * **Clipboard** settings: timeout slider, mask, disallow on high-risk panes.

Out of scope (reserved): SSH connection flows, VPN tunnel, Tools execution (Phases 3–7).

---

## 3) Architecture

```
crates/
  ghost_pq/           # PQ crypto primitives & KMS helpers
  ghost_policy/       # parser + evaluator + PDP/PEP interfaces
  ghost_vault/        # secrets store, envelope enc, MFA gating
  ghost_log/          # append-only hash chain + signed batches

src-tauri/
  commands/
    policy.rs   # evaluate/apply, dry-run, reload
    vault.rs    # list/get/put/delete/export/import
    io.rs       # clipboard, downloads/quarantine, fs (guarded)
    log.rs      # emit/query events
```

**Flow examples**

* **Terminal wants to copy text** → `clipboard_copy(text, tags)` → **Policy::check(clipboard.copy, tags)** → allow + start **auto-clear** timer → **GhostLog** entry.
* **UI imports theme** → `fs_open(file)` → **Policy::check(files.read, mime=theme/json)** → allow → GhostLog.
* **Vault get(secretId)** → **MFA prompt** (if required, policy-driven) → decrypt under VMK → return masked/plain per policy → GhostLog.

---

## 4) Data Models (concise)

### Policy (JSON/TOML)

```json
{
  "version": 1,
  "defaults": { "pq_required": true, "allow_classical": false },
  "rules": [
    { "id":"clipboard-default", "resource":"clipboard", "action":"copy",
      "when": { "pane":"terminal", "sensitivity":"low" },
      "effect":"allow", "constraints": { "auto_clear_ms": 15000 } },
    { "id":"clipboard-high", "resource":"clipboard", "action":"copy",
      "when": { "sensitivity":"secret" },
      "effect":"allow_with_justification",
      "constraints": { "auto_clear_ms": 5000, "mask_preview": true } },
    { "id":"download-quarantine", "resource":"download", "action":"save",
      "when": { "size_mb": { "<=": 100 }, "mime": ["zip","exe","pdf"] },
      "effect":"allow", "constraints": { "quarantine": true } }
  ]
}
```

### Vault storage header (per item)

```
magic=GSV1 | algo=xchacha20poly1305 | salt | nonce | aad(version, type, tags) | ciphertext | tag
```

### Log entry

```
ts | comp | action | subject | resource | decision | hash(prev) | sig(batch)
```

---

## 5) Crypto Details

* **KEM:** Kyber-768 (default), Kyber-1024 (high-security profile).
* **Signatures:** Dilithium-3 (default), Dilithium-2 (perf) — versioned in header.
* **Hash:** SHA3-256; extendable to SHAKE128 for LFS.
* **Symmetric:** AES-256-GCM (if AES-NI) or XChaCha20-Poly1305 (libsodium).
* **Envelope encryption:**

  * `VMK` protected by `wrap(VMK, device_key || user_key)` where `device_key` = TPM/SE; `user_key` = PW-derived (Argon2id) or passkey; plus **Kyber** wrap for offline recovery.
  * On unlock: unseal `VMK` → decrypt entries.
* **Artifacts signed:** policy bundles, log batches, vault exports.

---

## 6) Policy Engine (PDP/PEP)

* **PDP** (Policy Decision Point): pure function `decide(subject, resource, action, context) -> {effect, constraints, reason}`.
* **PEP** (Enforcement): every command calls PDP before doing anything.
* **Just-in-time prompts**: effect `allow_with_justification` opens a sheet requiring a reason/MFA.
* **Dry-run tester**: admins can simulate a decision in UI, see the matched rule & constraints.

---

## 7) UI / UX Additions

### Security & Policy Page

* Left: policy file viewer (read-only in v1), controls: **Reload Policy**, **Dry-Run**.
* Right: **Dry-Run Tester** form — choose resource/action/context → result chip (Allow / Deny / Allow+Prompt) with matched rule.

### Vault v1

* Grid/list of secrets (type icon, name, tags, expiry).
* Details pane: masked value, copy (policy-guarded), “Reveal” after MFA.
* Create/Edit dialog: type-aware fields; **Require MFA** toggle; tags (sensitivity).
* Export/Import: sealed bundle (signed), confirmation sheet.

### Clipboard Settings

* Timeout slider; mask on copy preview; disallow in high-risk contexts.
* “Clear on window blur” toggle.

### Download/Quarantine Drawer

* Shows recent downloads, hashes, quarantine status, “Reveal in folder” (policy-gated).

### GhostLog Peek

* Minimal timeline view (Phase-2 scope): filter by component, last N entries.

---

## 8) IPC (typed, minimal)

**policy.rs**

* `policy_decide(input) -> Decision`
* `policy_reload() -> Ok`

**vault.rs**

* `vault_list(filter?) -> [Meta]`
* `vault_get(id, mode: "masked"|"plain") -> Value` *(policy + MFA)*
* `vault_put(item) -> Id`
* `vault_delete(id) -> Ok`
* `vault_export(ids[]) -> Path` *(signed bundle)*
* `vault_import(path) -> {count}`

**io.rs**

* `clipboard_copy(text, tags) -> {expiresAt}`
* `clipboard_clear() -> Ok`
* `download_save(meta) -> {quarantinedPath}`

**log.rs**

* `log_query(filter, limit) -> [Entry]`

*All inputs validated UI-side (zod) and Rust-side (serde + custom).*

---

## 9) Security Hardening (Phase 2)

* **CSP locked**; no remote origins; IPC allowlist only for above commands.
* **Role-based gating**: admin vs analyst vs auditor on policy reload/export/import.
* **Clipboard**: never log plaintext; only lengths + tags.
* **Vault**: in-memory plaintext zeroized; constant-time compares; anti-keylogging mode (optional on reveal).
* **Policy file**: integrity-checked & signed; modification recorded in **GhostLog**.
* **Downloads**: quarantine directory with no-exec flag (platform-specific).
* **Crypto agility**: all crypto headers carry algo ids + versions; migration routine ready.

---

## 10) Testing & QA

**Unit**

* Policy rule matching (edge cases, precedence, time windows).
* Vault crypto: encrypt/decrypt, VMK seal/unseal, tamper detection.
* Log chain: prev-hash continuity, batch signature verify.

**Integration**

* Clipboard copy → policy decision → auto-clear → log entries.
* Vault get with MFA → mask/plain behavior → audit.
* Import/export theme now stored **via Vault** (config secret) — round-trip.

**Security**

* Attempt unauthorized clipboard/file/download — denied with clear UI.
* Corrupt vault file → refuse & alert.
* Policy reload with invalid signature → block & alert.

**Performance targets**

* Policy decision < **0.5 ms** median.
* Vault get (hot) < **5 ms**, cold decrypt < **25 ms**.
* Log append < **0.5 ms**.

---

## 11) Timeline (5–6 weeks)

**Week 1**

* `ghost_pq` crate; crypto headers; test vectors.
* `ghost_policy` parser + evaluator; minimal rules.

**Week 2**

* `ghost_vault` envelope crypto + VMK sealing (TPM/SE detect, Kyber wrap).
* CRUD APIs; MFA gating (stub OTP/UI).

**Week 3**

* Clipboard/download/FS guards; PEP wiring across commands.
* GhostLog append-only chain + batch signing.

**Week 4**

* UI: Security & Policy page; Vault v1; Clipboard & Download drawers.
* Theme storage moved into Vault (config secrets).

**Week 5**

* QA & perf; role gating; error UX; docs.
* Hardening: zeroization, constant-time ops, policy signing.

**Week 6 (buffer)**

* Cross-platform quirks; final polish; handoff.

---

## 12) Deliverables

* **Policy Engine v1** with dry-run & enforcement across clipboard/files/downloads/vault.
* **GhostVault v1** (PQ-sealed storage, MFA unlock, secrets + configs).
* **GhostLog bootstrap** (hash chain, signed batches, minimal viewer).
* **Clipboard & Download controls** with quarantine.
* UI pages: **Security & Policy**, **Vault**, **Clipboard settings**, **Download drawer**.
* Docs: policy schema, crypto profile, ops guides.

---

## 13) Hand-off to Phase 3

* Terminal/SSH **PEP hooks already present** → Phase 3 will light up SSH Manager & Terminal hardening on top of this foundation.
* Vault now owns **theme/config** secrets → single secure place for app state.
* GhostLog ready to expand with **SSH/VPN/Tools** events next.

If you want, I’ll immediately spin up **policy examples** (strict vs balanced) and a **sample Vault export bundle** so your team can test real-world flows while wiring SSH in Phase 3.
