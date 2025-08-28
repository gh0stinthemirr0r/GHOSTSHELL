use anyhow::Result;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, client::TlsStream};
use tracing::{debug, info, warn, error};

use crate::{GhostTLSConfig, PQPosture, TLSConnectionInfo, CertificateInfo};
use ghost_log::AuditLogger;
use ghost_pq::signatures::DilithiumSigner;

/// GhostTLS client for post-quantum secure connections
pub struct GhostTLSClient {
    config: GhostTLSConfig,
    connector: TlsConnector,
    logger: Arc<AuditLogger>,
    signer: Arc<DilithiumSigner>,
}

impl GhostTLSClient {
    /// Create a new GhostTLS client
    pub async fn new(
        config: GhostTLSConfig,
        logger: Arc<AuditLogger>,
        signer: Arc<DilithiumSigner>,
    ) -> Result<Self> {
        // Create TLS connector with custom configuration
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_trust_anchors(
            webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
                rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            })
        );

        let tls_config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(tls_config));

        Ok(Self {
            config,
            connector,
            logger,
            signer,
        })
    }

    /// Connect to a host with PQ-aware TLS
    pub async fn connect(&self, hostname: &str, port: u16) -> Result<GhostTLSConnection> {
        debug!("Attempting GhostTLS connection to {}:{}", hostname, port);

        // Establish TCP connection
        let tcp_stream = TcpStream::connect((hostname, port)).await?;
        
        // Perform TLS handshake
        let server_name = hostname.try_into()?;
        let tls_stream = self.connector.connect(server_name, tcp_stream).await?;

        // Analyze the connection for PQ posture
        let posture = self.analyze_connection_posture(&tls_stream).await?;
        
        // Check policy compliance
        if !posture.is_compliant(self.config.allow_classical, self.config.allow_hybrid) {
            let error_msg = format!(
                "Connection to {}:{} blocked by policy. Posture: {:?}, Config: classical={}, hybrid={}",
                hostname, port, posture, self.config.allow_classical, self.config.allow_hybrid
            );
            error!("{}", error_msg);
            return Err(anyhow::anyhow!(error_msg));
        }

        // Create connection info
        let connection_info = TLSConnectionInfo {
            hostname: hostname.to_string(),
            port,
            posture: posture.clone(),
            cipher_suite: self.get_cipher_suite(&tls_stream),
            protocol_version: self.get_protocol_version(&tls_stream),
            certificate_info: self.get_certificate_info(&tls_stream).await?,
            established_at: chrono::Utc::now(),
        };

        // Log the connection
        self.log_connection(&connection_info).await?;

        info!(
            "GhostTLS connection established to {}:{} with posture: {}",
            hostname, port, posture.display_name()
        );

        Ok(GhostTLSConnection {
            stream: tls_stream,
            info: connection_info,
        })
    }

    /// Analyze the PQ posture of a TLS connection
    async fn analyze_connection_posture(&self, _stream: &TlsStream<TcpStream>) -> Result<PQPosture> {
        // TODO: Implement actual PQ posture detection
        // For now, simulate based on configuration
        if self.config.pq_only {
            Ok(PQPosture::PurePostQuantum)
        } else if self.config.allow_hybrid {
            Ok(PQPosture::Hybrid)
        } else {
            Ok(PQPosture::Classical)
        }
    }

    /// Get cipher suite information
    fn get_cipher_suite(&self, _stream: &TlsStream<TcpStream>) -> Option<String> {
        // TODO: Extract actual cipher suite from rustls
        Some("TLS_AES_256_GCM_SHA384".to_string())
    }

    /// Get protocol version
    fn get_protocol_version(&self, _stream: &TlsStream<TcpStream>) -> Option<String> {
        // TODO: Extract actual protocol version
        Some("TLSv1.3".to_string())
    }

    /// Get certificate information
    async fn get_certificate_info(&self, _stream: &TlsStream<TcpStream>) -> Result<Option<CertificateInfo>> {
        // TODO: Extract actual certificate information
        Ok(Some(CertificateInfo {
            subject: "CN=example.com".to_string(),
            issuer: "CN=Example CA".to_string(),
            valid_from: chrono::Utc::now() - chrono::Duration::days(30),
            valid_to: chrono::Utc::now() + chrono::Duration::days(365),
            signature_algorithm: "dilithium3".to_string(),
            is_pq_signed: true,
        }))
    }

    /// Log the TLS connection
    async fn log_connection(&self, info: &TLSConnectionInfo) -> Result<()> {
        let log_entry = serde_json::json!({
            "event_type": "tls_connection",
            "hostname": info.hostname,
            "port": info.port,
            "posture": info.posture,
            "cipher_suite": info.cipher_suite,
            "protocol_version": info.protocol_version,
            "established_at": info.established_at,
        });

        let actor = ghost_log::Actor {
            actor_type: ghost_log::ActorType::System,
            id: "ghost_tls".to_string(),
            name: None,
            session_id: None,
            ip_address: None,
            user_agent: None,
        };

        let resource = ghost_log::Resource {
            resource_type: ghost_log::ResourceType::Network,
            id: Some(info.hostname.clone()),
            name: None,
            path: None,
            attributes: std::collections::HashMap::new(),
        };

        self.logger.log_event().await
            .event_type(ghost_log::EventType::NetworkAccess)
            .severity(ghost_log::Severity::Info)
            .actor(actor)
            .resource(resource)
            .action(ghost_log::Action::Connect)
            .outcome(ghost_log::Outcome::Success)
            .message("TLS connection established".to_string())
            .submit()
            .await?;
        Ok(())
    }
}

/// A GhostTLS connection wrapper
pub struct GhostTLSConnection {
    pub stream: TlsStream<TcpStream>,
    pub info: TLSConnectionInfo,
}

impl GhostTLSConnection {
    /// Get connection information
    pub fn info(&self) -> &TLSConnectionInfo {
        &self.info
    }

    /// Get the PQ posture
    pub fn posture(&self) -> &PQPosture {
        &self.info.posture
    }
}
