# GHOSTSHELL — Phase 11 Deep Dive

**Focus:** **Theming Engine v2 — Custom User Themes**
*(extend Phase-1 theming with full user-authored themes, presets, and cyberpunk variants)*

---

## 1) Objectives & Success Criteria

**Objectives**

* Expand theming from Phase-1 (static neon presets + save/export/import) into a **full user-authored theming engine**.
* Provide a **styling menu system** where users can:

  * Pick fonts (Nerd Fonts selector).
  * Adjust transparency, glow, accent colors.
  * Create, save, export, and import custom themes.
* Support multiple modes: **Cyberpunk Neon**, **Dark Academic**, **Retro Green**, **Exec Mode**.
* Persist themes in **GhostVault** (encrypted config secrets).
* Allow quick switching between themes at runtime without restart.

**Success Criteria**

* User can build a theme with font, palette, glow, transparency, and cursor settings.
* Themes can be exported/imported as PQ-signed bundles.
* Theme switch updates all UI instantly (Sidebar, TopBar, Terminal, Tools).
* Default presets included; Vault stores user themes securely.
* All theme changes logged into GhostLog for compliance (optional).

---

## 2) Scope (Phase 11 Delivery)

### Theming Engine Enhancements

* **Theme Schema v2**: expanded tokens (fonts, cursors, glow, borders, noise textures).
* **Theme Manager UI**:

  * Create/edit theme → live preview.
  * Save to Vault.
  * Export as `.ghosttheme.json` (PQ-signed).
  * Import with validation + preview.
* **Preset Library**:

  * Cyberpunk Neon (default).
  * Dark Academic (sepia, serif, muted).
  * Retro Green (80s terminal, amber/green on black).
  * Exec Mode (clean white/blue, corporate).

### Nerd Font System

* Dropdown list (JetBrainsMono, Cascadia Code, Iosevka, Fira Code, Hack).
* Preview line with ANSI colors + glyphs.
* Live swap in Terminal + UI monospace regions.

### Transparency & Effects

* Adjustable slider for acrylic transparency (30–90%).
* Glow intensity (subtle → strong).
* Noise overlay opacity for frosted look.
* Cursor style: block/underline/bar + neon color picker.

### Policy & Security

* Themes stored in Vault as encrypted config secrets.
* Exports PQ-signed with Dilithium.
* Import validation (schema, signature check).
* Optional: restrict corporate deployments to approved presets.

---

## 3) Architecture

```
crates/
  ghost_theme/       # schema, validator, crypto
  ghost_effects/     # UI shader helpers (glow, noise, transparency)

src-tauri/commands/theme.rs
  theme_list() -> [ThemeMeta]
  theme_apply(id) -> Ok
  theme_save(themeJson) -> Id
  theme_export(id) -> Path
  theme_import(path) -> Id
```

**Execution model**

* UI edits theme → sends schema JSON to Rust.
* Rust validates, stores in Vault, updates acrylic tint.
* CSS variables & GPU shaders updated live.

---

## 4) Data Models

**Theme v2 Schema**

```json
{
  "name":"Cyberpunk Custom",
  "version":2,
  "tokens":{
    "bgTint":"rgba(12,15,28,0.70)",
    "fg":"#EAEAEA",
    "slate":"#2B2B2E",
    "accent1":"#FF008C",
    "accent2":"#00FFD1",
    "accent3":"#AFFF00",
    "monoFont":"JetBrainsMono Nerd Font",
    "uiFont":"Inter",
    "cursorStyle":"block",
    "cursorColor":"#AFFF00",
    "cursorGlow":0.8,
    "blurPx":18,
    "glowStrength":0.6,
    "noiseOpacity":0.08,
    "radius":14,
    "border":"rgba(255,255,255,0.10)"
  },
  "signature":"dilithium-sig..."
}
```

---

## 5) Policy Hooks

Examples:

```toml
[[rules]]
id = "theme-restrict-exec"
resource = "theme"
action = "apply"
when = { template = "exec" }
effect = "allow"
constraints = { roles = ["exec","auditor"] }

[[rules]]
id = "theme-import-signature"
resource = "theme"
action = "import"
effect = "allow"
constraints = { requireSignature = true }
```

---

## 6) UI / UX

### Theme Manager Page

* **List of themes** (Vault + presets).
* **Preview panel**: live card showing fonts, colors, cursor style.
* **Create/Edit modal**:

  * Color pickers for accents.
  * Transparency/glow sliders.
  * Font dropdown.
  * Cursor style selector.
* **Actions**: Apply, Save, Export, Import.

### Runtime Switching

* Switching themes instantly changes CSS variables + acrylic tint.
* No restart needed.

### Neon Aesthetic

* Cyberpunk preview: glowing accents, frosted blur, bright block cursor.
* Retro preview: pixel font + amber/green palette.
* Exec preview: clean corporate blue/white.

---

## 7) Security Hardening

* **PQ-signed themes**: exports signed with Dilithium, verified on import.
* **Vault storage**: user themes encrypted at rest.
* **Rollback**: if theme import fails, app reverts to last known good theme.
* **Policy restrictions**: block unauthorized imports or non-approved presets.
* **Audit**: GhostLog records theme apply/import/export.

---

## 8) Testing & QA

**Unit**

* Schema validator rejects malformed JSON.
* PQ signature verification.
* Font preview correctness.

**Integration**

* Create/edit theme → apply live → persists to Vault.
* Export → reimport on another system → identical rendering.
* Policy enforcement blocks unauthorized import.

**Security**

* Tampered theme export → rejected.
* Unsigned theme → denied if policy requires signature.

**Performance**

* Theme switch ≤300 ms.
* UI glow/transparency stable at 60–120 FPS.

---

## 9) Timeline (3–4 weeks)

**Week 1**

* ghost\_theme crate; schema v2; validator.
* Theme Manager UI skeleton.

**Week 2**

* Nerd Fonts dropdown; color pickers; preview.
* Vault integration (save/load).

**Week 3**

* Export/import PQ-signed bundles.
* Runtime switching.

**Week 4 (buffer)**

* Policy integration; UI polish; docs.

---

## 10) Deliverables

* **Theming Engine v2** with custom user themes.
* **UI**: Theme Manager page, create/edit/preview, save/export/import.
* **Presets**: Cyberpunk, Dark Academic, Retro Green, Exec Mode.
* **Vault storage** of themes; PQ-signed exports/imports.
* **Logs**: GhostLog entries for apply/import/export.
* Docs: theme schema reference, preset guide, policy rules.

---

## 11) Handoff to Phase 12

* Themes feed into **Compliance Dashboard** (Exec Mode as default).
* Alerts (Phase 10) adopt theme styling for immersive or professional look.
* AI (Phase 13) can recommend **theme swaps** (e.g., high contrast when anomaly floods).

---

⚡ Do you want me to also prepare a **“Theme Preset Pack” spec** (exact palettes, font sets, transparency/glow settings) so your devs can ship with four polished styles right out of the gate?
