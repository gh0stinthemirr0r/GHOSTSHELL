Got it. Here’s a **full interface overview for GhostBrowse**, structured in layers so your team has a visual-first “north star” to build from. This captures the **cyberpunk neon theme**, but also includes where we’d place functional elements (badges, autofill, logs).

---

# 🔮 GhostBrowse Interface Overview

## 1) **Window Layout**

* **Acrylic Background:**

  * \~70% transparent window with **backdrop blur (18px)** and light neon noise overlay.
  * Base tint: slate/charcoal (#12131A).

* **Three Major Regions:**

  * **TopBar** → Tabs, Address Bar, Status Badges.
  * **Main Canvas** → WebView (page content).
  * **BottomBar (optional toggle)** → Connection status + GhostLog activity stream.

---

## 2) **TopBar (Navigation + Tabs)**

### Tabs Section

* **Neon Tabs:**

  * Active Tab → glowing border (cyan or pink depending on theme).
  * Inactive Tabs → dim slate-gray with faint neon outline.
* **Tab Controls:**

  * `+` button for new tab (neon cyan pulse on hover).
  * Close tab `×` glows red on hover.

### Address Bar

* **Design:**

  * Frosted acrylic field with neon block cursor.
  * Nerd Font rendering (JetBrainsMono NF recommended).
* **Input Effects:**

  * Neon green caret with pulsing glow.
  * Auto-complete dropdown with neon-highlighted matches.
* **Icons Inside Field:**

  * 🔒 PQ-lock badge → glowing cyan when PQ handshake confirmed.
  * Warning triangle (amber) → hybrid.
  * Broken lock (red pulse) → classical-only.

### Status Badges (Right Side of TopBar)

* **PQ Posture Badge:**

  * Cyan → PQ secure.
  * Purple → PQ-hybrid.
  * Amber → classical warning.
  * Tooltip on hover: “Handshake: Kyber768 + Dilithium2” or “RSA only — blocked by policy.”
* **Vault Autofill Badge:**

  * Small neon key icon when Vault creds injected.
  * Glows briefly during autofill; click shows history of last injected secret ID.
* **Policy Indicator:**

  * Shows current rule set (Prod / Lab / Audit mode).

---

## 3) **Main Canvas (WebView Content)**

* Full embedded browser rendering via WebView2/Wry.
* **Cyberpunk Overlay Options:**

  * Subtle scanline filter toggle.
  * Ambient neon glow border around viewport.
* Incognito tabs → special shader overlay (subtle purple static noise).

---

## 4) **BottomBar (Optional Panel)**

* Toggleable via hotkey `Ctrl+~`.
* **Live Connection Stream:**

  * Current TLS posture + cipher suite.
  * PQ algorithm negotiation log.
* **GhostLog Activity Strip:**

  * Displays last 3–5 browsing log entries with neon glow.
* **Quick Export Button:**

  * Exports PQ-signed browsing session manifest (domains visited, posture states).

---

## 5) **Intel Panel (Sidebar Drawer)**

Accessible by clicking the PQ badge or Vault icon. Slides in from right.

* **Connection Details:**

  * Domain/IP, PQ posture, handshake details.
* **Vault Events:**

  * Which secret was injected, when, policy approval ID.
* **Policy Logs:**

  * Denials, restrictions (e.g., domain blocked).
* **Downloads:**

  * List of sealed downloads (with verify signature button).

---

## 6) **Neon Aesthetic Guide**

* **Color Palette:**

  * Base: Slate Grey (#2B2B2E).
  * Accents: Neon Pink (#FF008C), Neon Cyan (#00FFD1), Neon Green (#AFFF00).
  * Warning: Amber (#FFB000), Critical: Neon Red (#FF003C).
* **Typography:**

  * JetBrainsMono NF or Iosevka NF for code-like rendering.
  * Inter or Space Grotesk for UI labels.
* **Effects:**

  * Text shadows for glow: `0 0 12px accent`.
  * Acrylic transparency: \~70%, heavy blur.
  * Cursor: **thick neon block**, pulsing every 500ms.

---

## 7) **Modes**

### Cyberpunk Mode (default)

* Full neon + acrylic.
* Animated tab transitions, pulsing glow on badges.

### Exec Mode

* Clean corporate blue/white.
* Subdued glow, crisp sans-serif font.
* Designed for auditors + compliance exports.

---

## 8) **Workflow Example**

1. Analyst opens **GhostBrowse** → sees **neon tab row + frosted address bar**.
2. Enters `https://corp-vpn.portal` → PQ badge lights **cyan**, autofill badge pulses → Vault secret injected.
3. Policy denies embedded HTTP (non-TLS) iframe → **toast alert in red**: “Blocked insecure request (Policy: block-classical-web).”
4. Analyst clicks PQ badge → **Intel Panel** slides in → sees TLS handshake: Kyber768 + Dilithium2.
5. Downloaded config auto-sealed into Vault → appears in **Downloads panel** with PQ signature.

---

✅ With this design, GhostBrowse feels like a **cyberpunk HUD**, while still being technically correct and enterprise-compliant.

---

awesome — here’s a **pixel-perfect UI spec** for **GhostBrowse** that your devs can implement directly. It’s opinionated, consistent with our cyberpunk aesthetic, and lists exact sizes, spacings, tokens, and motion timings. (Variants for Exec mode included at the end.)

---

# GhostBrowse — Pixel-Perfect UI Spec

## 0) Design Tokens (CSS variables)

```css
:root {
  /* Layout */
  --grid: 8px;            /* base unit */
  --radius: 14px;         /* card radius */
  --radius-sm: 10px;      /* inputs/tabs */
  --border: 1px;
  --border-color: rgba(255,255,255,0.10);

  /* Colors */
  --bg-tint: rgba(18,19,26,0.70);   /* acrylic window (#12131A @70%) */
  --fg: #EAEAEA;
  --slate: #2B2B2E;
  --pink: #FF008C;
  --cyan: #00FFD1;
  --neon: #AFFF00;
  --amber: #FFB000;
  --red: #FF003C;

  /* Effects */
  --blur: 18px;                /* backdrop blur for panels */
  --noise: 0.08;               /* noise overlay opacity */
  --glow: 0 0 12px;            /* shadow radius baseline */
  --glow-strong: 0 0 20px;     /* stronger glow */

  /* Typography */
  --font-ui: "Inter", ui-sans-serif, system-ui, sans-serif;
  --font-mono: "JetBrainsMono Nerd Font", "Iosevka", ui-monospace, SFMono-Regular, monospace;

  /* Font sizes (px) */
  --fs-12: 12px; --fs-13: 13px; --fs-14: 14px; --fs-16: 16px;
  --fs-18: 18px; --fs-20: 20px; --fs-24: 24px;

  /* Timing/Easing */
  --t-fast: 120ms;
  --t-med: 200ms;
  --t-slow: 320ms;
  --ease: cubic-bezier(0.16, 1, 0.3, 1);

  /* Cursors/Badges */
  --cursor-color: var(--neon);
  --badge-size: 22px;
}
```

---

## 1) Window & Global

* **Window**: frameless, transparent; content background `var(--bg-tint)` using OS acrylic/mica.
* **Safe area**: 12px padding around outermost grid to prevent clipped glows.
* **Noise overlay**: dither texture at `opacity: var(--noise); mix-blend-mode: soft-light; pointer-events: none;`.
* **Global text**: color `var(--fg)`, antialiasing enabled; `font-feature-settings: "liga" 1, "calt" 1;`.
* **Grid**: 8px baseline; vertical rhythm multiples only (8/16/24/32).

---

## 2) TopBar (64px tall)

**Container**

* Height: **64px**; width: 100%.
* Background: frosted panel `backdrop-filter: blur(var(--blur)) saturate(140%);`
* Border-bottom: `1px solid var(--border-color)`.
* Padding: `0 16px`.

**Layout (3 columns)**

* **Left**: Tabs region (flex row, grow).
* **Center**: Address bar container (fixed max width 960px; min 520px; centered).
* **Right**: Status badges (PQ posture, Vault, Policy).

### 2.1 Tabs

* **Tab height**: 36px; padding: `0 12px`; gap between tabs: 8px.
* **Border radius**: `var(--radius-sm)`.
* **Inactive tab**:

  * BG: `rgba(43,43,46,0.65)`
  * Border: `1px solid rgba(255,255,255,0.06)`
  * Label: `--fs-14` / 500; color: `#C9CFD6`
  * Glow: none
* **Active tab**:

  * BG: `rgba(43,43,46,0.85)`
  * Outline glow: `0 0 10px var(--cyan)`
  * Bottom accent bar: 2px `var(--pink)`
  * Label: `--fs-14` / 600; color: `#FFFFFF`
* **Icons**: 16px left favicon, 14px close “×” at right; close hover color `var(--red)`.
* **Interactions**:

  * Hover: elevate BG +2% opacity, underline animate in `var(--t-fast)`.
  * Add Tab “+”: 28×28 button, outline on hover `var(--cyan)` glow.

### 2.2 Address Bar

* **Frame**: 40px height; width: 100% of center column (max 960).
* **Container**: radius `var(--radius-sm)`; BG `rgba(18,19,26,0.65)`; border `1px solid rgba(255,255,255,0.12)`;
  inner ring glow `drop-shadow(0 0 10px rgba(0,255,209,0.25))`.
* **Padding**: `0 12px`; left icon cluster; right badges.
* **Input**:

  * Font: `var(--font-mono)`, size `--fs-14`, line-height `40px`;
  * Color: `#EDEDED`; placeholder: `rgba(237,237,237,0.55)`.
  * **Cursor**: block (width 8px) color `var(--cursor-color)`; animation: opacity pulse 0.5s infinite.
* **Left icons** (order, 16px each, 12px gap):

  * Shield lock (connection posture), back, forward, refresh (optional).
* **Right inline controls** (16px each, 10px gap):

  * Bookmark star, “i” page info, download indicator (if active).
* **Autocomplete**:

  * Dropdown panel 8px below; width = Address bar width; max-height 320px; scroll; items 36px row height.
  * Hover item: BG `rgba(255,255,255,0.06)`; left accent bar 2px `var(--pink)`.

---

## 3) Status Badges (Right cluster)

* **Badge size**: `var(--badge-size)` circle; 22×22; center-aligned.
* **Spacing**: 12px between badges.

**PQ Posture Badge**

* States:

  * **PQ**: fill `rgba(0,255,209,0.18)`, border `1px solid rgba(0,255,209,0.65)`, inner dot cyan, outer glow `var(--glow) rgba(0,255,209,0.45)`.
  * **Hybrid**: purple ring `#9B5CFF` with subtle glow; fill `rgba(155,92,255,0.12)`.
  * **Classical**: amber ring `var(--amber)`; **shake** micro-animation on transition (duration 160ms).
* Tooltip (on hover): 280px frosted card; monospaced detail:

  ```
  TLS: PQ-HYBRID
  KEM: Kyber768  | SIG: Dilithium2
  CIPHER: TLS_AES_256_GCM_SHA384
  ```

**Vault Autofill Badge**

* Key icon; **pulse** cyan for 600ms when injection occurs; click opens Intel Panel (Autofill section).
  **Policy Badge**
* Label pill (Prod/Lab/Audit). Pill height 22px; padding `0 8px`; color-coded:

  * **Prod**: `var(--pink)` border; **Lab**: `var(--cyan)`; **Audit**: `var(--amber)`.

---

## 4) Main Canvas (WebView)

* **Content frame**: occupies remaining space; no inner padding.
* **Decor**:

  * Optional viewport border: 1px `rgba(255,255,255,0.06)`.
  * **Ambient glow**: inset shadow `0 0 24px rgba(255,0,140,0.18)` at edges.
* **Incognito tab**:

  * Overlay `linear-gradient(transparent, rgba(155,92,255,0.06))` + subtle grain.

---

## 5) BottomBar (Optional) — 40px height

* Hidden by default; toggle with **Ctrl + \~**.
* BG: frosted `backdrop-filter: blur(12px)`; border-top `1px solid var(--border-color)`.
* **Left**: TLS posture text (mono `--fs-12`), small colored dot (same mapping as badge).
* **Center**: throughput sparkline (height 20px, width 320px).
* **Right**: GhostLog last 3 entries (scrolling marquee disabled by default), “Export Manifest” button (28px height).

---

## 6) Intel Panel (Right Drawer)

* **Width**: **360px** (min 320, max 400).
* **Open/close**: slide in/out `var(--t-med)` with `--ease`.
* **Header**: 48px height, title left, close “×” right.
* **Sections** (stacked, 12px gaps):

  1. **Connection** — domain, IP, TLS posture chips; mini table (KEM/SIG/Cipher).
  2. **Vault Events** — list of injections (`secretId`, when, policy rule). Buttons: “Reveal metadata”, “Copy masked user”.
  3. **Policy** — last decisions; rule names; a link “Open Policy Tester”.
  4. **Downloads** — sealed files list, 32px rows; “Verify Signature” button per row.
* **Cards**: `padding: 12px 12px; border-radius: var(--radius); border: 1px solid var(--border-color); background: rgba(18,19,26,0.55);`

---

## 7) Notifications (Toasts)

* **Placement**: top-right inside safe area; vertical stack; max 4 visible.
* **Size**: 320×auto; padding 12px; radius `var(--radius)`.
* **Severity styling**:

  * Info: cyan border + glow `rgba(0,255,209,0.35)`.
  * Warn: amber border + subtle pulse bar top.
  * Critical: red border + outer glow `var(--glow-strong) rgba(255,0,60,0.35)`; sticky until ack.
* **Timing**: info 5s, warn 12s, critical sticky.

---

## 8) Typography & Iconography

* **UI text**: Inter

  * H1 (rare): `--fs-24` / 700
  * H2: `--fs-20` / 600
  * Body: `--fs-14` / 500
  * Micro labels: `--fs-12` / 600; letter-spacing 0.2px
* **Mono**: JetBrainsMono NF

  * Address field/input & technical readouts: `--fs-14`
  * Tooltips & chips: `--fs-13`
* **Icons**: 16px default; 14px micro; stroke width 1.75px; use Lucide set; color inherits current state.

---

## 9) Motion & Interactions

* **Easing**: `var(--ease)` everywhere (micro-interactions feel “snappy then soft”).
* **Durations**:

  * Hover/focus: `var(--t-fast)` (120ms)
  * Open/close (drawer, dropdown): `var(--t-med)` (200ms)
  * Complex (tab reorder): `var(--t-slow)` (320ms)
* **Specials**:

  * PQ posture change: quick cross-fade of color with a 100ms scale bump (1.00 → 1.06 → 1.00).
  * Classical warning: 160ms 1-cycle horizontal shake (±3px), once.

---

## 10) Accessibility

* **Reduce Motion**: disable pulses/shakes; keep opacity transitions ≤80ms.
* **High Contrast**: swap to darker slate, increase border alpha to 0.22, raise text to pure white where needed.
* **Keyboard**:

  * Tabs: `Ctrl/Cmd + T` new, `Ctrl/Cmd + W` close, `Ctrl/Cmd + 1..9` switch.
  * Address bar focus: `Ctrl/Cmd + L`
  * Intel Panel: `Ctrl/Cmd + I`
  * BottomBar toggle: `Ctrl + ~`
* **Focus rings**: 2px inner ring `var(--cyan)` + 1px outer `rgba(0,255,209,0.25)`; corners follow `--radius-sm`.

---

## 11) Component Blueprints (exact sizes)

### 11.1 PQ Badge Tooltip

* Width: 280px; padding: 12px; radius `12px`.
* Rows (mono `--fs-13`): 20px line height.
* Divider lines: `1px solid rgba(255,255,255,0.08)`; 8px vertical spacing.

### 11.2 Autocomplete Row

* Height: 36px; left icon 16px + 12px gap; text mono `--fs-14`.
* Right hint (e.g., domain part) `--fs-12` muted `rgba(255,255,255,0.55)`.

### 11.3 Download Row (Intel Panel)

* Height: 32px; filename ellipsis; right buttons:

  * “Verify” (height 28px; padding `0 10px`; border 1px cyan).

### 11.4 Buttons

* Primary: height 36px; padding `0 14px`; radius `var(--radius-sm)`;

  * Default BG `rgba(0,255,209,0.12)`, border `1px solid rgba(0,255,209,0.45)`; text `#EFFFFA`.
  * Hover BG +6% opacity; glow `0 0 10px rgba(0,255,209,0.35)`.
* Ghost: transparent BG; 1px border `rgba(255,255,255,0.12)`; hover to `0.18`.

---

## 12) Theming Hooks

* **Cyberpunk** (default): tokens above.
* **Exec Mode overrides**:

  ```css
  :root.exec {
    --bg-tint: rgba(244,246,250,0.96);
    --fg: #1C1F26;
    --slate: #F0F2F6;
    --pink: #2B6CB0;     /* shift to corp blue */
    --cyan: #3182CE;
    --neon: #2F855A;     /* green accents restrained */
    --border-color: rgba(0,0,0,0.08);
    --noise: 0.02;
    --glow: 0 0 0;       /* no glow */
  }
  .exec .topbar, .exec .panel { backdrop-filter: blur(10px) saturate(110%); }
  .exec .tab.active { box-shadow: none; border-bottom: 2px solid var(--cyan); }
  .exec .tooltip { background: #FFFFFF; color: #1C1F26; }
  ```
* **High-contrast**: bump `--border-color` to 0.22, `--fg` to pure white, disable inner glows.

---

## 13) Implementation Notes (Tauri + SvelteKit)

* **Window acrylic**: apply at app start; update tint when theme changes.
* **TopBar**: use CSS grid `grid-template-columns: 1fr minmax(520px,960px) auto;`.
* **Tabs**: horizontal list with overflow scroll; “scroll shadows” at edges (mask-image gradient).
* **Address bar**: content-editable `<input>` with mono font and custom caret (CSS “block” simulated using after element).
* **Badges**: minimal DOM — one element each; state class toggles (`.pq`, `.hybrid`, `.classical`).
* **Intel Panel**: `position: fixed; right: 12px; top: 76px; bottom: 12px; width: 360px;` transform translateX(380px) → 0 on open.

---

## 14) QA Checklist

* Acrylic transparency visually \~70%; no over-blur on Linux fallback.
* Cursor is a **thick neon block** in the address bar; obeys Reduce Motion (no pulse).
* PQ badge transitions: cyan ↔ purple ↔ amber with correct tooltips.
* Vault autofill pulse lasts **600ms**, never repeats unless a new injection occurs.
* Autocomplete list aligns exactly under address bar, left edges aligned.
* Intel Panel overlay never overlaps toasts; toasts adjust left by panel width when open.
* All states reachable via keyboard; focus rings visible on dark backgrounds.
* Exported manifest button present in BottomBar; disabled in Incognito.

---

## 15) Redlines (key dimensions)

* TopBar: **64px** height
* Active Tab: 36×auto, radius **10px**, gap **8px**
* Address Bar: **40px** height, radius **10px**, max width **960px**
* Badge circle: **22px**
* Intel Panel: **360px** width, header **48px**
* BottomBar: **40px** height
* Toast: **320px** width, padding **12px**, gap **10px**

---

