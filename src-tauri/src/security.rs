// Security module for CSP and protocol allowlists
// Phase 1: Basic security hardening
// Phase 2: Policy Engine integration

pub mod pep;

pub use pep::{PolicyEnforcementPoint, PepState, PepDecision, PolicyStats, DryRunResult, initialize_pep};

pub fn get_csp() -> &'static str {
    "default-src 'self'; \
     img-src 'self' asset: https://asset.localhost; \
     style-src 'self' 'unsafe-inline'; \
     font-src 'self' asset: https://asset.localhost; \
     script-src 'self'; \
     connect-src 'self' ws://localhost:* ws://127.0.0.1:*"
}

pub fn validate_protocol(url: &str) -> bool {
    // Only allow asset:// and localhost for development
    url.starts_with("asset://") || 
    url.starts_with("http://localhost:") ||
    url.starts_with("http://127.0.0.1:") ||
    url.starts_with("ws://localhost:") ||
    url.starts_with("ws://127.0.0.1:")
}

// Phase 2: Policy Engine integration complete
// TODO Phase 2: Add IPC command allowlisting
// TODO Phase 2: Add file system access controls
