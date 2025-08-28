GHOSTSHELL — Project Overview
Mission

A post-quantum secure, neon-sleek analyst environment: terminal, SSH/VPN, scanners, PCAP, flows, vault, browser, AI, compliance—designed for speed, beauty, and rigor.

Core Tenets

PQ by default: Kyber/Dilithium everywhere.

Secure by architecture: Rust core owns all privileged ops; UI is sandboxed.

Cyberpunk UI: Acrylic window (~70% transparency), frosted panels, piercing neon, clean spacing.

Observability + governance: Immutable logs → compliance heatmaps → signed reports.

Programmability: Sandbox scripting and AI explainers.

Recommended Stack (visual-first + secure)

App shell: Tauri (Rust) + WebView2 (Win) / WebKit (macOS/Linux)

UI: SvelteKit + Tailwind + Motion One (or React + Framer Motion)

GPU visuals: WebGL/WebGPU (Three.js/Pixi/regl) for topology, heatmaps

Terminal: xterm.js + WebGL addon (truecolor, transparent)

Rust crates: PQ crypto (liboqs), SSH/PTY, PCAP, VPN, Vault, Policy, GhostLog

Feature Catalog (master)
Environment

PQ Terminal (tabs/splits/profiles, transparent neon, thick neon yellow-green block cursor)

SSH Manager (PQ/hybrid, policy enforcement, latency/health)

GhostVPN (Kyber/hybrid, split tunneling, per-tool binding)

GhostBrowse (PQ-secure browser: policy, VPN binding, Vault autofill, audit)

Theming Engine (presets + user themes, Nerd Fonts, export/import/switch)

Tooling

Layers (OSI probe, waterfall)

Surveyor (throughput + ports/services)

PCAP Studio (capture, GPU analysis, anomalies)

Topology Visualizer (interactive neon map; active+passive flows)

Quantum Noise Analyzer (entropy sources & PQ readiness)

Security & Governance

GhostVault (PQ secrets/passwords/configs, MFA, hardware bind, sealed exports)

GhostLog (Merkle chain, PQ signatures, optional blockchain anchor)

Compliance Dashboard (NIST/CIS/ISO mapping, KPIs, executive exports)

GhostAlign (AI posture analysis + policy recommendations)

Intelligence & Productivity

Scripting Console (Rust/Lua/Python-WASM, sandboxed)

AI Error Assistant (terminal/SSH/browser explainers; policy-aware fixes)

Report Templates (signed PDF/HTML/CSV bundles)

Notifications/Alerts (neon toasts + center; exportable incidents)

Command Palette (global fuzzy actions/hosts/tools/reports)

Phased Implementation (high-level)

Phase 1 — UI Shell & Theming (this phase)

Acrylic window, frosted components, neon tokens, Nerd Fonts dropdown, theme save/export/import/switch, terminal MVP (WebGL), Sidebar/TopBar/Palette/Alerts.

Phase 2 — Secure Foundations

Policy engine, Vault (MFA, sealed storage), PQ crypto plumbing, Clipboard policy, GhostLog base.

Phase 3 — SSH Manager & Terminal Hardening

Profiles, PQ/hybrid negotiation, sandbox improvements, AI error hooks.

Phase 4 — Tools: Layers & Surveyor (active probing)

OSI probe, throughput/port enum, exports.

Phase 5 — PCAP Studio (capture + GPU analysis)

Live flows, anomalies, signed bundles.

Phase 6 — GhostVault Deep & Secrets UX

Rotations, access controls, hardware bind, audits.

Phase 7 — GhostVPN

PQ handshake, split tunneling, per-tool binding.

Phase 8 — Topology + NetFlow/sFlow

Neon map, time slider, data fusion.

Phase 9 — Scripting Console & Report Templates

REPLs (WASM), templates, signed exports.

Phase 10 — Notifications & Theming Pro

Rule engine, alert center, advanced theme presets.

Phase 11 — GhostLog Immutable + Anchoring

Merkle batches, blockchain anchors, verification UI.

Phase 12 — Compliance Dashboard

Framework mapping, KPIs, executive mode.

Phase 13 — GhostAI

Error explainers, anomaly clustering, compliance drift forecast.

Phase 14 — GhostBrowse

PQ secure browser with policy/VPN/Vault, Inspector panel.

Phase 1 — UI Shell & Theming (Deep Overview)
Goals

Nail the look/feel: acrylic window (≈70% transparency), frosted panels, neon palette, Nerd Fonts.

Ship a usable shell: terminal MVP (WebGL), sidebar navigation, command palette, notifications.

Build the Theming Engine: create/save/export/import/switch themes; persist per user.

Scope (what ships)

Transparent window + Acrylic/Mica (Win11 pref Mica; fallback Acrylic).

Global design tokens (CSS variables) and Tailwind config.

Theme Manager page + quick selector in TopBar.

Nerd Fonts dropdown (pre-bundled & user-added), applied live to terminal & UI monospace.

Theme save, export (JSON), import, switch with live preview and rollback.

Terminal MVP (xterm.js+WebGL):

Transparent background

Thick block neon yellow-green cursor

Truecolor theme (neon ANSI palette)

Core shell: Sidebar (modules), TopBar (status pills), Command Palette (⌘/Ctrl-K), Notifications toasts.

Accessibility toggles: Reduce Motion, High Contrast, Transparency slider.

UI/UX specifics
Acrylic & Frost

Window: ~70% transparent tint (e.g., rgba(12,15,28,0.70)).

Panels: backdrop-filter: blur(18px) saturate(140%), 1px soft border, subtle inner neon edge.

Color & Layout

Base: slate grey on neon pink menus, cyan/magenta accents, neutral slate for content.

Grid: 8px spacing, 2 elevation layers (acrylic background + glass cards).

Motion: 120ms ease (cubic-bezier(0.16,1,0.3,1)), honors reduce-motion.

Nerd Fonts (dropdown)

Pre-bundled options: JetBrainsMono Nerd Font, Cascadia Code NF, FiraCode Nerd Font, Hack Nerd Font, Iosevka Nerd Font.

Preview row renders sample ANSI colors and powerline glyphs.

Selection applies to terminal + any mono UI elements instantly.

Optional “Add font” (user-provided .ttf/.otf) with validation.

Theme Manager (save/export/import/switch)

Theme schema (v1)