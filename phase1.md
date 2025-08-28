# GHOSTSHELL — Phase 1 Deep Dive

**Focus:** Premium cyberpunk UI shell, theming system (create/save/export/import/switch), Nerd Fonts selector, terminal MVP (neon, transparent, thick block cursor), acrylic/mica window, essential chrome (Sidebar, TopBar, Command Palette, Notifications).

---

## 1) Objectives & Success Criteria

**Objectives**

* Ship a visually stunning, performant shell that sets the tone for all later phases.
* Implement a robust theming engine with live switching and full round-trip (save/export/import).
* Deliver a transparent acrylic/mica window and frosted panels.
* Stand up terminal MVP with WebGL renderer, **thick neon yellow-green block cursor**, truecolor palette, Nerd Fonts.

**Success Criteria**

* App launches to a **70% acrylic** window; panels show frosted glass with neon edges.
* Theme Manager: users can **create → save → export(JSON) → import → preview → switch** themes with rollback.
* Nerd Fonts dropdown applies instantly to terminal + mono UI elements.
* Terminal renders at 60–120 FPS with transparent background and neon palette.
* Accessibility toggles work (Reduce Motion, High Contrast, Transparency slider).
* CI produces signed installers (Win/macOS/Linux).

---

## 2) UX / Visual Spec

**Window & Surfaces**

* Window: acrylic/mica at \~70% transparency (Win: Mica → Acrylic fallback; macOS: Vibrancy; Linux: CSS frost fallback).
* Panels (Sidebar, TopBar, dialogs): frosted (`blur(18px) saturate(140%)`), soft 1px border, subtle inner neon edge.

**Color & Typography (defaults)**

* Base bg tint: `rgba(12,15,28,0.70)`
* Foreground: `#EAEAEA`
* Slate (menus): `#2B2B2E` with **neon pink** text `#FF008C`
* Accents: neon pink `#FF008C`, neon cyan `#00FFD1`, neon yellow-green `#AFFF00`
* UI font: Inter / Geist; Mono font (configurable Nerd Font)

**Terminal**

* **xterm.js + WebGL**; background fully transparent.
* Cursor: **block**, size 100%, color `#AFFF00`, subtle glow.
* ANSI palette tuned for neon over acrylic; ligatures enabled.

**Menus & Overlays**

* Command Palette (⌘/Ctrl-K): frosted sheet, grouped fuzzy results.
* Notifications: neon toasts (info/warn/critical) slide from top-right.
* Theme Manager: left list of presets, right live preview; “Apply / Revert”.

---

## 3) Architecture & Project Layout

```
ghostshell/
├─ src-tauri/                    # Rust host (window effects, secure config, IPC)
│  ├─ main.rs
│  ├─ security.rs                # CSP, protocol allowlist
│  ├─ commands/
│  │   ├─ theme.rs               # set_acrylic_tint, save_theme, list/apply/export/import
│  │   └─ settings.rs
│  └─ tauri.conf.json
├─ app-ui/                       # SvelteKit (or React) UI
│  ├─ src/lib/theme/             # tokens, registry, schema, preview renderer
│  │   ├─ tokens.css
│  │   ├─ schema.ts
│  │   └─ registry.ts
│  ├─ src/routes/settings/theme  # Theme Manager page
│  ├─ src/components/            # GhostCard, Sidebar, TopBar, Toast, Palette, Dropdown
│  ├─ src/features/terminal/     # xterm init, profiles, WebGL renderer
│  └─ src/bridge/tauri.ts        # typed IPC wrappers
└─ shared/                       # types (serde <-> zod), fonts, noise assets
```

---

## 4) Theming Engine (Design & Schema)

**Concept**

* Single source of truth: CSS variables (tokens) + a JSON theme schema.
* Live preview/switch; safe rollback if user cancels or theme invalid.
* Persist themes per user (encrypted config file in Rust).

**Theme Schema (v1)**

```json
{
  "name": "Neon Cyberpunk",
  "version": 1,
  "tokens": {
    "bgTint": "rgba(12,15,28,0.70)",
    "fg": "#EAEAEA",
    "slate": "#2B2B2E",
    "accentPink": "#FF008C",
    "accentCyan": "#00FFD1",
    "accentNeonGreen": "#AFFF00",
    "glowStrength": 0.6,
    "blurPx": 18,
    "noiseOpacity": 0.08,
    "cursorStyle": "block",
    "cursorColor": "#AFFF00",
    "monoFont": "JetBrainsMono Nerd Font",
    "uiFont": "Inter",
    "radius": 14,
    "border": "rgba(255,255,255,0.10)"
  }
}
```

**Tokens → CSS Variables (excerpt)**

```css
:root {
  --bg-tint: rgba(12,15,28,0.70);
  --fg: #EAEAEA;
  --slate: #2B2B2E;
  --accent-pink: #FF008C;
  --accent-cyan: #00FFD1;
  --accent-neon-green: #AFFF00;
  --glow-strength: 0.6;
  --blur-px: 18px;
  --noise-opacity: 0.08;
  --radius: 14px;
  --border: rgba(255,255,255,0.10);
  --mono-font: "JetBrainsMono Nerd Font", "Fira Code", monospace;
  --ui-font: Inter, system-ui, sans-serif;
}
```

**Theme Operations**

* **Create/Save:** UI sends validated theme JSON to Rust; Rust stores signed file (hash + signature for integrity).
* **Export:** UI requests theme JSON; Rust adds checksum; user downloads `.ghosttheme.json`.
* **Import:** UI loads file → validates schema/hash → preview (sandbox) → Apply/Cancel.
* **Switch:** UI swaps CSS vars; Rust updates **Acrylic tint** (`set_acrylic_tint`), persists selection.

---

## 5) Nerd Fonts Selector

**Built-in options**

* JetBrainsMono Nerd Font, Cascadia Code NF, FiraCode Nerd Font, Hack Nerd Font, Iosevka Nerd Font.

**UI Behavior**

* Dropdown with live preview row (ANSI blocks, powerline glyphs).
* Apply instantly to terminal + mono UI regions.
* Optional “Add font” with local `.ttf/.otf` validation; copy to app font dir (user scope).

**Security**

* Restrict to local file system (no remote font downloads).
* Hash & whitelist installed font binaries; store metadata in Rust config.

---

## 6) Terminal MVP (xterm.js + WebGL)

**Init (TypeScript)**

```ts
import { Terminal } from 'xterm';
import { WebglAddon } from 'xterm-addon-webgl';
import { FitAddon } from 'xterm-addon-fit';
import { LigaturesAddon } from 'xterm-addon-ligatures';

const term = new Terminal({
  allowProposedApi: true,
  allowTransparency: true,
  fontFamily: 'var(--mono-font)',
  fontSize: 14,
  letterSpacing: 0.2,
  lineHeight: 1.2,
  theme: {
    background: '#00000000',
    foreground: 'var(--fg)',
    cursor: 'var(--accent-neon-green)',
    cursorAccent: '#0A0F1E',
    selectionBackground: '#00FFD170',
    black: '#0A0F1E', red: '#FF4D4D', green: '#2EE6A6', yellow: '#F5A623',
    blue: '#6FA8FF', magenta: '#FF00FF', cyan: '#00FFD1', white: '#D7E1FF',
    brightBlack: '#1A2037', brightRed: '#FF6B6B', brightGreen: '#49F0B6',
    brightYellow: '#FFC85B', brightBlue: '#9BC2FF', brightMagenta: '#FF66FF',
    brightCyan: '#6FFFF0', brightWhite: '#FFFFFF'
  },
  cursorStyle: 'block',
  cursorBlink: false
});
const fit = new FitAddon();
term.loadAddon(fit);
term.loadAddon(new LigaturesAddon());
term.loadAddon(new WebglAddon());

term.open(document.getElementById('terminal')!);
fit.fit();
```

**Extra “piercing” touch**

```css
/* very subtle, avoid halos */
.xterm .xterm-rows { text-shadow: 0 0 0.6px rgba(175,255,0,0.25); }
```

---

## 7) Acrylic / Mica / Vibrancy (Rust)

**tauri.conf.json (transparent window)**

```json
{ "tauri": { "windows": [{
  "label": "main", "transparent": true, "decorations": false,
  "resizable": true, "backgroundColor": "#00000000"
}]}}
```

**Rust setup**

```rust
#[cfg(target_os = "windows")]
use window_vibrancy::{apply_mica, apply_acrylic};

#[tauri::command]
fn set_acrylic_tint(window: tauri::Window, r: u8, g: u8, b: u8, a: u8) -> Result<(), String> {
  #[cfg(target_os = "windows")]
  window_vibrancy::apply_acrylic(&window, Some((r,g,b,a))).map_err(|e| e.to_string())?;
  Ok(())
}

fn main() {
  tauri::Builder::default()
    .setup(|app| {
      let win = app.get_window("main").unwrap();
      #[cfg(target_os = "windows")]
      if apply_mica(&win).is_err() {
        let tint = (12, 15, 28, 180); // ~70% opacity feel, tweak per theme
        apply_acrylic(&win, Some(tint)).expect("acrylic failed");
      }
      Ok(())
    })
    .invoke_handler(tauri::generate_handler![set_acrylic_tint])
    .run(tauri::generate_context!())
    .expect("run failed");
}
```

**UI → Rust (tint sync on theme switch)**

```ts
import { invoke } from '@tauri-apps/api/tauri';
await invoke('set_acrylic_tint', { r:12, g:15, b:28, a:180 });
```

---

## 8) IPC Contracts (typed, minimal surface)

**Theme**

* `list_themes() -> ThemeMeta[]`
* `save_theme(theme: ThemeV1) -> {id}`
* `apply_theme(id: string) -> ok`
* `export_theme(id: string) -> ThemeV1`
* `import_theme(filePath: string) -> {id}`
* `set_acrylic_tint(r,g,b,a) -> ok`

**Settings**

* `set_accessibility({ reduceMotion, highContrast, transparency }) -> ok`
* `set_fonts({ monoFont, uiFont }) -> ok`

*(All inputs schema-validated UI-side; Rust revalidates.)*

---

## 9) Security Hardening (Phase 1)

* **CSP**: no remote origins; `default-src 'self'`; ban `eval`; inline styles only for Tailwind (nonce or hashed).
* **Protocol**: serve assets via `asset://`; disable `http(s)` in prod.
* **IPC allowlist**: only theme/settings commands enabled.
* **Config storage**: user-scoped, encrypted at rest (basic now; Vault later).
* **Fonts**: user import restricted to local files; hash & record metadata; no auto-execution.

---

## 10) Accessibility, Performance, QA

**Accessibility**

* Reduce Motion: disables panel slide/scale; keeps opacity transitions ≤80ms.
* High Contrast: swap palette to high-contrast Dark Academic; ensure ≥4.5:1 contrast.
* Transparency slider: 0–100%; at 0% all panels/terminal become opaque.

**Performance Budgets**

* App launch ≤ 2s warm.
* Terminal scroll 120 FPS on 5k lines.
* Palette open/close ≤ 120ms.
* Theme switch ≤ 300ms including acrylic tint update.

**QA Matrix**

* Fonts: all built-ins + one imported; ligatures; glyph coverage.
* Themes: create/save/export/import/rollback; bad schema rejection.
* Accessibility toggles live-update UI.
* Win10/11: Acrylic/Mica; macOS: Vibrancy; Linux: fallback frost.
* Perf: terminal FPS; palette open timing; theme swap timing.

---

## 11) Timeline & Tasks (4–5 weeks)

**Week 1**

* Project scaffolding (Tauri + SvelteKit).
* Transparent window + Acrylic/Mica/Vibrancy.
* Base tokens + GhostCard/Sidebar/TopBar/Toast components.

**Week 2**

* Terminal MVP (xterm.js + WebGL + fonts).
* Nerd Fonts dropdown + preview + apply.
* Command Palette shell.

**Week 3**

* Theme schema + validator; Theme Manager UI.
* Save/list/apply/export/import + preview/rollback.

**Week 4**

* Accessibility toggles; Transparency slider wired to Rust tint.
* QA hardening (CSP, allowlist, perf); CI signed installers.

**Week 5 (buffer)**

* Polish visuals (glow curves, noise textures), docs & handoff.

---

## 12) Deliverables

* Executable app with **70% acrylic** window and frosted neon UI.
* Terminal MVP (transparent, truecolor, **neon yellow-green block cursor**).
* **Theme Manager** with create/save/export/import/switch + live preview & rollback.
* **Nerd Fonts** dropdown with live preview + instant apply.
* Command Palette & Notifications (foundational).
* Accessibility toggles (Reduce Motion, High Contrast, Transparency).
* Signed installers (Win/macOS/Linux) + setup docs.

---

## 13) Backlog / Next Phase Handoffs

* Prepare stubs for: PTY (terminal → Rust), SSH manager, Vault config store, Policy engine, GhostLog hooks.
* Define Phase 2 deep dive: security foundations (policy/Vault/PQ plumbing) that snap into this UI shell.

