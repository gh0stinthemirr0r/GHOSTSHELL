## 📸 GHOSTSHELL Screenshots

![GhostShell Main](https://github.com/gh0stinthemirr0r/GHOSTSHELL/blob/main/screenshots/ghostshell_ghostshell.png?raw=true)  
![GhostSSH](https://github.com/gh0stinthemirr0r/GHOSTSHELL/blob/main/screenshots/ghostshell_ghostssh.png?raw=true)  
![GhostBrowse](https://github.com/gh0stinthemirr0r/GHOSTSHELL/blob/main/screenshots/ghostshell_ghostbrowse.png?raw=true)  
![GhostVault](https://github.com/gh0stinthemirr0r/GHOSTSHELL/blob/main/screenshots/ghostshell_ghostvault.png?raw=true)  
![Topology View](https://github.com/gh0stinthemirr0r/GHOSTSHELL/blob/main/screenshots/ghostshell_topology.png?raw=true)  
![GhostVPN](https://github.com/gh0stinthemirr0r/GHOSTSHELL/blob/main/screenshots/ghostshell_ghostvpn.png?raw=true)  
![PAN Engine](https://github.com/gh0stinthemirr0r/GHOSTSHELL/blob/main/screenshots/ghostshell_pan_engine.png?raw=true)  
![PAN Evaluator](https://github.com/gh0stinthemirr0r/GHOSTSHELL/blob/main/screenshots/ghostshell_pan_evaluator.png?raw=true)  
![Meraki Engine](https://github.com/gh0stinthemirr0r/GHOSTSHELL/blob/main/screenshots/ghostshell_meraki_engine.png?raw=true)  
![Arista Engine](https://github.com/gh0stinthemirr0r/GHOSTSHELL/blob/main/screenshots/ghostshell_arista_engine.png?raw=true)  
![Forti Engine](https://github.com/gh0stinthemirr0r/GHOSTSHELL/blob/main/screenshots/ghostshell_forti_engine.png?raw=true)  
![Layers UI](https://github.com/gh0stinthemirr0r/GHOSTSHELL/blob/main/screenshots/ghostshell_layers.png?raw=true)  
![Surveyor](https://github.com/gh0stinthemirr0r/GHOSTSHELL/blob/main/screenshots/ghostshell_Surveyor.png?raw=true)  
![PCAP Studio](https://github.com/gh0stinthemirr0r/GHOSTSHELL/blob/main/screenshots/ghostshell_PCAP_Studio.png?raw=true)  
![GhostDash](https://github.com/gh0stinthemirr0r/GHOSTSHELL/blob/main/screenshots/ghostshell_ghostdash.png?raw=true)  
![GhostLog](https://github.com/gh0stinthemirr0r/GHOSTSHELL/blob/main/screenshots/ghostshell_ghostlog.png?raw=true)  
![GhostReport](https://github.com/gh0stinthemirr0r/GHOSTSHELL/blob/main/screenshots/ghostshell_ghostreport.png?raw=true)  
![GhostScript](https://github.com/gh0stinthemirr0r/GHOSTSHELL/blob/main/screenshots/ghostshell_ghostscript.png?raw=true)  
![File Manager](https://github.com/gh0stinthemirr0r/GHOSTSHELL/blob/main/screenshots/ghostshell_filemanager.png?raw=true)  
![Settings](https://github.com/gh0stinthemirr0r/GHOSTSHELL/blob/main/screenshots/ghostshell_settings.png?raw=true)

# GHOSTSHELL

**Post-Quantum Secure Terminal Environment for Cybersecurity Professionals**

[![License: MIT](https://img.shields.io/badge/License-MIT-cyan.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.70+-red.svg)](https://www.rust-lang.org/)
[![Tauri](https://img.shields.io/badge/Tauri-1.4+-blue.svg)](https://tauri.app/)
[![Node.js](https://img.shields.io/badge/Node.js-18+-green.svg)](https://nodejs.org/)

---

## 🔮 Overview

GHOSTSHELL is a **cyberpunk-themed, post-quantum secure terminal environment** designed specifically for cybersecurity engineers and network security professionals. Built with Rust + Tauri backend and SvelteKit frontend, it combines cutting-edge cryptography with a stunning neon aesthetic.

**Lead Developer & Engineer**: Aaron Stovall

### 🎯 Core Mission

- **Post-Quantum Security**: Kyber/Dilithium cryptography by default
- **Professional Tool**: Single-user sidecar for cybersecurity engineers  
- **Real Data Only**: No simulation or mock data - works with actual network traffic and system data
- **Cyberpunk UI**: Acrylic transparency, neon colors, and smooth animations
- **Comprehensive Logging**: Immutable audit trails with PQ signatures

---

## 🚀 Quick Start

### Prerequisites

- **Rust** 1.70+ with Cargo
- **Node.js** 18+ with npm
- **Python** 3.8+ (for launcher script)
- **Windows 10/11** (primary platform), macOS, or Linux

### Installation & Launch

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/ghostshell.git
   cd ghostshell
   ```

2. **Run the launcher** (handles all dependencies and startup):
   ```bash
   python run.py
   ```

   The launcher will:
   - Check and install missing dependencies
   - Kill conflicting processes
   - Start the development server
   - Launch the application with transparency effects

3. **Alternative manual build**:
   ```bash
   npm install
   npm run tauri build
   ```

---

## 🏗️ Architecture

### Frontend Stack
- **SvelteKit**: Reactive UI framework
- **Tailwind CSS**: Utility-first styling  
- **xterm.js**: WebGL terminal rendering
- **Lucide**: Icon system
- **Motion One**: Smooth animations

### Backend Stack
- **Rust**: Systems programming language
- **Tauri**: Cross-platform app framework
- **Post-Quantum Crypto**: liboqs (Kyber768, Dilithium3)
- **SQLite**: Local data storage
- **Tokio**: Async runtime

### Window Effects
- **Windows**: Mica/Acrylic transparency
- **macOS**: Vibrancy effects
- **Linux**: CSS backdrop-filter fallback

---

## 📦 Core Modules

### 🖥️ Terminal & Shell Environment

| Module | Description | Status |
|--------|-------------|--------|
| **Ghostshell Nushell** | Advanced shell environment with Nushell integration | ✅ Active |
| **GhostshellSSH (SSH Manager)** | Post-quantum capable SSH client with comprehensive key management | ✅ Active |
| **File Manager** | Simple integrated file manager built to simplify file operations | ✅ Active |

### 🔐 Security & Cryptography

| Module | Description | Status |
|--------|-------------|--------|
| **GhostBrowse** | Post-quantum secure browser with policy enforcement and vault integration | ✅ Active |
| **GhostVault** | Post-quantum secure password and secrets vault with MFA | ✅ Active |
| **GhostVPN** | Comprehensive VPN solution based on OpenVPN supporting standard and post-quantum secured communications | ✅ Active |

### 🌐 Network Infrastructure Management

| Module | Description | Status |
|--------|-------------|--------|
| **Topo** | Micro MAPR dynamic network topology mapper solution (imported from external project) | ✅ Active |
| **Pan_Engine** | Palo Alto Networks API GUI interface for comprehensive firewall management | ✅ Active |
| **Pan_Evaluator** | Firewall Security Policy audit and assessment agent - analyzes policies, recommends security enhancements, identifies shadowing, suggests merging, reports zero hits | ✅ Active |
| **Meraki_Engine** | Cisco Meraki API GUI interface for cloud-managed networking | ✅ Active |
| **Arista_Engine** | Arista Networks API GUI interface for data center switching | ✅ Active |
| **Forti_Engine** | Comprehensive API GUI interfaces for the broad portfolio of Fortinet/FortiGate APIs | ✅ Active |

### 🔧 Network Testing & Analysis Tools

| Module | Description | Status |
|--------|-------------|--------|
| **Layers** | Automated network testing for OSI Layers 1-7 with comprehensive output reports | ✅ Active |
| **Surveyor** | Endpoint testing and analysis to determine link quality using destination IP addresses - includes port enumeration on destination hosts | ✅ Active |
| **PCAP Studio** | Packet capturing module based on BruteShark methodology (requires WinPcap/Npcap) | ✅ Active |

### 📊 System Monitoring & Analytics

| Module | Description | Status |
|--------|-------------|--------|
| **GhostDash** | Centralized system dashboard displaying system analytics in a single, easy-to-access location | ✅ Active |
| **GhostLog** | Centralized application logging system - each module provides intricate logging to this backend with frontend GUI for easy troubleshooting | ✅ Active |
| **GhostReport** | Automated report generation based on GhostDash or GhostLog data (PDF/XLSX/CSV formats) | ✅ Active |

### 🚀 Automation & Scripting

| Module | Description | Status |
|--------|-------------|--------|
| **GhostScript** | Script execution and management system - run Python, batch files, or PowerShell scripts and manage multiple script folders (requires backend languages to be installed) | ✅ Active |

### 🎨 Customization & Settings

| Module | Description | Status |
|--------|-------------|--------|
| **Settings** | Comprehensive theming and customization interface for personalizing the GHOSTSHELL experience | ✅ Active |

---

## 🎨 UI Features

### Design System
- **Cyberpunk Theme**: Neon pink (#FF008C), cyan (#00FFD1), green (#AFFF00)
- **Typography**: JetBrains Mono NF, Inter, custom font selection
- **Transparency**: ~70% acrylic background with blur effects
- **Animations**: Smooth 120ms transitions with easing

### Interface Components
- **Sidebar Navigation**: Collapsible module launcher
- **Command Palette**: Fuzzy search (Ctrl/Cmd+K)
- **Terminal**: WebGL rendering with thick neon block cursor
- **Modals**: Frosted glass overlay system
- **Notifications**: Neon toast system with severity colors

---

## 🔧 Configuration

### Database Files (./data/)
- `ghostshell_browser.db` - Browser engine data
- `ghostshell_vault.db` - Encrypted secrets storage
- `ghostshell_settings.db` - Application settings
- `ghostshell_theme.db` - Theme definitions

### Log Files (./logs/)
- `ghostshell-debug.log.*` - Detailed application logs
- `ghostlog/` - Structured audit trail with PQ signatures

### Fonts (./src-tauri/fonts/)
- 298 embedded font files (TTF/OTF)
- Comprehensive Nerd Font collection
- Live font switching support

---

## 🔒 Security Features

### Post-Quantum Cryptography
- **Key Exchange**: Kyber768 (NIST Level 3)
- **Digital Signatures**: Dilithium3 (NIST Level 2)  
- **Hybrid Mode**: PQ + Classical for compatibility
- **Hardware Security**: TPM integration for key binding

### Audit & Compliance
- **Immutable Logs**: Merkle tree structure with PQ signatures
- **Policy Enforcement**: Configurable security policies
- **Quarantine System**: Automatic file isolation
- **Clipboard Security**: Policy-aware clipboard management

### Network Security
- **VPN Integration**: PQ-enhanced tunneling
- **SSH Hardening**: Post-quantum key exchange
- **TLS Enhancement**: Custom PQ-capable stack
- **Certificate Management**: Automated cert lifecycle

---

## 📈 Real-World Capabilities

### Network Analysis
- **Live Packet Capture**: Real network traffic analysis
- **Protocol Dissection**: Deep packet inspection
- **Anomaly Detection**: Behavioral baseline comparison
- **Topology Mapping**: Automated network discovery

### Security Assessment
- **Policy Analysis**: Firewall rule evaluation
- **Vulnerability Scanning**: Network and host assessment
- **Threat Modeling**: Attack path analysis
- **Risk Scoring**: Quantitative security metrics

### Incident Response
- **Evidence Collection**: Forensic data gathering
- **Timeline Analysis**: Event correlation and sequencing
- **Report Generation**: Professional incident documentation
- **Playbook Execution**: Automated response procedures

---

## 🛠️ Development

### Project Structure
```
GHOSTSHELL/
├── src/                    # SvelteKit frontend
│   ├── lib/components/     # UI components
│   ├── lib/stores/         # State management
│   └── routes/             # Application pages
├── src-tauri/              # Rust backend
│   ├── src/               # Main application logic
│   └── Cargo.toml         # Rust dependencies
├── crates/                 # Ghost modules (27 total)
│   ├── ghost_pq/          # Post-quantum crypto
│   ├── ghost_vault/       # Secure storage
│   ├── ghost_dash/        # System dashboard
│   └── ...                # Additional modules
└── data/                   # SQLite databases
```

### Build Commands
```bash
# Development server
npm run tauri:dev

# Production build  
npm run tauri:build

# Component development
npm run dev

# Dependency check
cargo check --workspace
```

### Testing
```bash
# Rust tests
cargo test --workspace

# Frontend tests  
npm test

# Integration tests
cargo test --test integration
```

---

## 📄 Documentation

### Key Files
- `Overview.md` - Project vision and roadmap
- `Interface.md` - Detailed UI specifications
- `WindowControlSolution.md` - Window management approach

### API Reference
- Tauri commands for frontend-backend communication
- Ghost module APIs for security operations
- Database schemas for data persistence

---

## 🤝 Contributing

### Development Workflow
1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** changes (`git commit -m 'Add amazing feature'`)
4. **Push** to branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Code Standards
- **Rust**: Follow `cargo fmt` and `cargo clippy`
- **TypeScript**: Use Prettier formatting
- **Commits**: Conventional commit format
- **Documentation**: Update README for significant changes

---

## 📋 System Requirements

### Minimum Requirements
- **OS**: Windows 10 (1903+), macOS 10.15+, Linux (glibc 2.18+)
- **Memory**: 4GB RAM
- **Storage**: 2GB available space
- **Graphics**: DirectX 11 or OpenGL 3.3

### Recommended
- **OS**: Windows 11 (for Mica effects)
- **Memory**: 8GB RAM
- **Storage**: 4GB available space (for packet capture)
- **Graphics**: Dedicated GPU for WebGL acceleration

---

## 🐛 Troubleshooting

### Common Issues

**Port Conflicts**: Run `python run.py` which automatically kills conflicting processes

**Missing Dependencies**: The launcher script handles most dependency installation

**Transparency Effects**: Ensure compositor is enabled on Linux, Windows Aero on Windows

**Font Rendering**: Verify Nerd Fonts are properly installed in system

### Debug Information
- Check `logs/ghostshell-debug.log.*` for detailed error information
- Enable debug mode: `RUST_LOG=debug npm run tauri:dev`
- Component loading errors appear in browser developer tools

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Credits

**Lead Developer & Engineer**: Aaron Stovall

## 🌟 Acknowledgments

- **BruteShark** - Inspiration for network analysis capabilities
- **Palo Alto Networks** - Policy analysis methodologies  
- **NIST** - Post-quantum cryptography standards
- **Tauri Team** - Cross-platform framework
- **Svelte Team** - Reactive UI framework

---

## 📞 Support

- **Issues**: GitHub Issues for bug reports
- **Discussions**: GitHub Discussions for questions
- **Security**: Report security issues privately via email

---

*Built with ❤️ and quantum-safe cryptography for the cybersecurity community*
