# GHOSTSHELL — Phase 6 Deep Dive

**Focus:** **GhostVault v2 — Secrets, Passwords, and Configs Management**
*(post-quantum secure storage for secrets, integrated into the neon UI and Policy Engine)*

---

## 1) Objectives & Success Criteria

**Objectives**

* Upgrade Vault from Phase 2’s “config/secret store” into a **full-featured PQ secure password & secrets manager**.
* Provide **CRUD UI** for secrets, passwords, SSH/API keys, configs, and policy-bound access.
* Support **MFA-gated unlock**, **hardware binding** (TPM/SE), and **fine-grained policies** per secret (roles, expiry, reauth).
* Allow **sealed exports/imports** (PQ-encrypted bundles).
* Integrate with **Terminal, SSH Manager, GhostBrowse, VPN** for autofill/credential injection.
* All access logged immutably in **GhostLog**.

**Success Criteria**

* Users can create, store, retrieve, rotate, and delete secrets securely.
* Vault sealed/unsealed only with MFA (and optionally device key).
* Secrets accessible only under policy; denied attempts logged.
* Autofill workflows (SSH keys, web creds in GhostBrowse, VPN configs) use ephemeral injection, never plaintext.
* Exports are PQ-sealed; imports verified and logged.

---

## 2) Scope (Phase 6 Delivery)

### Vault Core (v2)

* Storage: encrypted SQLite with envelope encryption.
* Master key (VMK) sealed with **Kyber KEM** and optionally hardware key (TPM/SE).
* Unlock requires MFA (TOTP/passkey/biometric).
* Per-entry metadata: type, tags, owner, created/modified, last accessed, expiry, rotation interval, policy refs.

### Secrets Types

* **Passwords** (with generator).
* **SSH Keys** (integrated with SSH Manager agent).
* **API Tokens** (OAuth/JWT, with expiry reminders).
* **Config Profiles** (VPN configs, theme/config bundles).
* **Certificates/PKI material** (PEM/PKCS12 sealed).

### Policies (per secret)

* Roles allowed (analyst, ops, admin).
* MFA always required vs. only on first unlock.
* Expiry / rotation required.
* Context restrictions (e.g., SSH key usable only with specific host tag).

### Vault Operations

* Create, read (masked/unmasked), update, delete.
* Export/import sealed bundles.
* Rotation workflow (manual or auto, per policy).
* Search/filter secrets by tags, type, owner.

### Integration

* **SSH Manager**: retrieves key material on connect → injects ephemeral file/agent → wipes on teardown.
* **GhostBrowse**: autofill creds into login forms → ephemeral injection → never exposed to JS.
* **GhostVPN**: loads VPN profiles/secrets into tunnels.
* **Terminal**: `$VAULT:secret_id` expansion resolved via policy.

### Logging

* Every operation (get/put/delete/export/import/rotation) recorded in **GhostLog** with Dilithium signature.
* No plaintext stored in logs; only metadata + hashes.

---

## 3) Architecture

```
crates/
  ghost_vault/      # core crypto + storage
  ghost_secret/     # secret types, generators, rotation
  ghost_export/     # sealed export/import bundles (PQ-encrypted, signed)

src-tauri/commands/vault.rs
  vault_list(filter?) -> [SecretMeta]
  vault_get(id, mode) -> SecretValue (policy + MFA)
  vault_put(item) -> Id
  vault_update(id, fields) -> Ok
  vault_delete(id) -> Ok
  vault_rotate(id) -> Ok
  vault_export(ids[], path) -> BundlePath
  vault_import(path) -> {count}
```

**Crypto model**

* Secrets encrypted with XChaCha20-Poly1305 or AES-256-GCM.
* VMK sealed with:

  * **Kyber768 KEM** (for backup/restore).
  * Optional TPM/SE (device binding).
  * Dilithium signature for integrity.
* Export bundles: PQ-encrypted archive + signed manifest.

---

## 4) Data Models

**SecretMeta**

```json
{
  "id": "sec-001",
  "name": "Prod DB Admin",
  "type": "password",
  "tags": ["db","prod"],
  "created": "2025-08-25T23:45Z",
  "lastAccessed": "2025-08-26T00:10Z",
  "expiry": "2025-09-25T00:00Z",
  "policy": {"roles":["admin"],"mfa":"always","rotationDays":30}
}
```

**SecretValue**

```json
{
  "id": "sec-001",
  "value": "Xk!92ad...masked",
  "format": "password",
  "metadata": {...}
}
```

**Export Bundle Manifest**

```json
{
  "bundleId": "vault-2025-08-26-01",
  "count": 42,
  "ts": "2025-08-26T00:15Z",
  "signature": "dilithium-sig..."
}
```

---

## 5) Policy Hooks

Examples:

```toml
[[rules]]
id = "vault-admin-only"
resource = "vault.secret"
action = "get"
when = { type = "password", tags = ["prod"] }
effect = "allow"
constraints = { mfa = "always" }

[[rules]]
id = "vault-expiry-enforce"
resource = "vault.secret"
action = "use"
when = { expiry < "now" }
effect = "deny"

[[rules]]
id = "vault-ssh-host-bind"
resource = "vault.secret"
action = "use"
when = { type = "ssh-key", hostTag = "db" }
effect = "allow"
```

---

## 6) UI / UX

### Vault Page

* **List/Grid view** of secrets: name, type, tags, expiry badge.
* **Filters**: by type, tag, expiry.
* **Details panel**:

  * Masked value; unmask requires MFA + policy check.
  * Metadata: created, last accessed, expiry, policy.
  * Rotation history.
  * “Copy” (policy-gated, clipboard auto-clear).
* **Create/Edit dialog**: choose type (password, key, API token, config); tags; expiry; policy.
* **Export/Import dialogs**: frosted panel, path selector, PQ signature verify.

### Autofill Integration

* **SSH Manager**: key dropdown → picks from Vault.
* **GhostBrowse**: autofill icon appears in login fields → click to inject from Vault.
* **Terminal**: command expansion `$VAULT:secretId`.

### Neon Aesthetic

* **Secret type icons** glowing by type (pink=pass, cyan=key, green=token).
* Expiry badges neon orange/red.
* MFA prompt modal: frosted overlay, neon keypad/QR.

---

## 7) Security Hardening

* **Zeroization** of decrypted values in memory after use.
* **Clipboard auto-clear** for copied secrets; only masked previews by default.
* **No local plaintext**: secrets always PQ-encrypted on disk.
* **MFA enforcement**: TOTP, FIDO2/WebAuthn, biometric if available.
* **Export bundles**: PQ-encrypted + signed manifest; only imported with valid signature.
* **Access audits**: every operation → GhostLog with signed hash.
* **Rotation enforcement**: expired secrets inaccessible until rotated.

---

## 8) Testing & QA

**Unit**

* Encrypt/decrypt cycle; seal/unseal with Kyber + TPM.
* Secret generator: correct entropy, allowed charsets.
* Policy enforcement on get/put/delete.

**Integration**

* Create → Save → Retrieve (MFA prompt) → Log check.
* Export bundle → Import to new system → Verify PQ sig.
* SSH Manager uses Vault key ephemeral injection.
* GhostBrowse autofill → no plaintext to page JS.

**Security**

* Attempt to bypass MFA → denied.
* Tamper with export bundle → import blocked.
* Copy secret → clipboard auto-clear within timeout.

**Performance**

* Unlock Vault ≤ 1s with MFA.
* Secret retrieval ≤ 10ms hot.
* Export/import ≤ 2s for 100+ secrets.

---

## 9) Timeline (5–6 weeks)

**Week 1**

* ghost\_vault upgrade (types, metadata, policy checks).
* MFA integrations (TOTP first).

**Week 2**

* Export/import bundles (PQ-sealed).
* Vault UI (list, create/edit, details, MFA unmask).

**Week 3**

* Clipboard guards; auto-clear; masked preview.
* Autofill integration: SSH Manager keys.

**Week 4**

* Autofill integration: GhostBrowse, Terminal expansion.
* Rotation workflows + expiry badges.

**Week 5**

* GhostLog integration (all ops signed).
* Policy enforcement matrix complete.

**Week 6 (buffer)**

* Perf tuning, cross-platform tests, docs.

---

## 10) Deliverables

* **GhostVault v2** with full secret management.
* **UI**: Vault list, filters, details, create/edit, MFA prompts, export/import.
* **Policy enforcement** on secret access & use.
* **Integration**: SSH Manager, GhostBrowse autofill, Terminal expansion.
* **Exports**: PQ-encrypted bundles with signature verification.
* **Logs**: all secret ops in GhostLog.
* Docs: admin policy presets, analyst workflows, export/import guide.

---

## 11) Handoff to Phase 7

* Vault now feeds GhostVPN (profiles/keys) directly.
* Policy + Vault integration ready for **per-tool binding** (VPN, SSH, Browser).
* Exports provide portable sealed config → useful for disaster recovery / enterprise rollout.

---

⚡ Want me to also draft a **“default Vault policy set”** (e.g., Prod secrets require MFA, API tokens expire in 30 days, SSH keys bound to host tags) so you have a baseline security profile ready for rollout?
