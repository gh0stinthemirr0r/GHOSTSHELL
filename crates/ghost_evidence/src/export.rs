use crate::{EvidenceBundle, EvidenceResult, EvidenceError};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::fs;
use std::io::Write;
use chrono::Utc;

/// Export format options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExportFormat {
    JSON,
    PDF,
    ZIP,
    OSCAL,
    CSV,
}

/// Export configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportConfig {
    pub format: ExportFormat,
    pub include_artifacts: bool,
    pub include_signatures: bool,
    pub include_metadata: bool,
    pub output_path: PathBuf,
    pub compress: bool,
}

/// Export result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportResult {
    pub export_id: String,
    pub format: ExportFormat,
    pub output_path: PathBuf,
    pub file_size_bytes: u64,
    pub export_timestamp: chrono::DateTime<Utc>,
    pub bundle_count: usize,
    pub artifact_count: usize,
    pub checksum: String,
}

/// Evidence bundle exporter
pub struct BundleExporter;

impl BundleExporter {
    pub async fn export_bundle(
        bundle: &EvidenceBundle,
        config: &ExportConfig,
    ) -> EvidenceResult<ExportResult> {
        match config.format {
            ExportFormat::JSON => Self::export_json(bundle, config).await,
            ExportFormat::PDF => Self::export_pdf(bundle, config).await,
            ExportFormat::ZIP => Self::export_zip(bundle, config).await,
            ExportFormat::OSCAL => Self::export_oscal(bundle, config).await,
            ExportFormat::CSV => Self::export_csv(bundle, config).await,
        }
    }

    pub async fn export_multiple_bundles(
        bundles: &[EvidenceBundle],
        config: &ExportConfig,
    ) -> EvidenceResult<ExportResult> {
        match config.format {
            ExportFormat::ZIP => Self::export_multiple_zip(bundles, config).await,
            ExportFormat::JSON => Self::export_multiple_json(bundles, config).await,
            _ => {
                // For other formats, create a combined bundle
                let combined_bundle = Self::combine_bundles(bundles)?;
                Self::export_bundle(&combined_bundle, config).await
            }
        }
    }

    async fn export_json(
        bundle: &EvidenceBundle,
        config: &ExportConfig,
    ) -> EvidenceResult<ExportResult> {
        let export_data = if config.include_artifacts {
            serde_json::to_string_pretty(bundle)?
        } else {
            // Create a lightweight version without artifact content
            let lightweight = LightweightBundle {
                bundle_id: bundle.bundle_id,
                name: bundle.name.clone(),
                description: bundle.description.clone(),
                framework_id: bundle.framework_id.clone(),
                control_ids: bundle.control_ids.clone(),
                artifact_count: bundle.artifacts.len(),
                created_at: bundle.created_at,
                created_by: bundle.created_by.clone(),
                verification_manifest: bundle.verification_manifest.clone(),
            };
            serde_json::to_string_pretty(&lightweight)?
        };

        fs::write(&config.output_path, &export_data)?;
        
        let metadata = fs::metadata(&config.output_path)?;
        let checksum = Self::calculate_checksum(&export_data);

        Ok(ExportResult {
            export_id: bundle.bundle_id.to_string(),
            format: ExportFormat::JSON,
            output_path: config.output_path.clone(),
            file_size_bytes: metadata.len(),
            export_timestamp: Utc::now(),
            bundle_count: 1,
            artifact_count: bundle.artifacts.len(),
            checksum,
        })
    }

    async fn export_pdf(
        bundle: &EvidenceBundle,
        config: &ExportConfig,
    ) -> EvidenceResult<ExportResult> {
        // For now, create a simple text-based report
        // In a real implementation, this would use a PDF library
        let report = Self::generate_text_report(bundle, config);
        
        // Write as text file with .pdf extension (placeholder)
        fs::write(&config.output_path, &report)?;
        
        let metadata = fs::metadata(&config.output_path)?;
        let checksum = Self::calculate_checksum(&report);

        Ok(ExportResult {
            export_id: bundle.bundle_id.to_string(),
            format: ExportFormat::PDF,
            output_path: config.output_path.clone(),
            file_size_bytes: metadata.len(),
            export_timestamp: Utc::now(),
            bundle_count: 1,
            artifact_count: bundle.artifacts.len(),
            checksum,
        })
    }

    async fn export_zip(
        bundle: &EvidenceBundle,
        config: &ExportConfig,
    ) -> EvidenceResult<ExportResult> {
        use std::fs::File;
        use zip::write::{FileOptions, ZipWriter};

        let file = File::create(&config.output_path)?;
        let mut zip = ZipWriter::new(file);
        let options = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

        // Add bundle manifest
        zip.start_file("manifest.json", options)?;
        let manifest_json = serde_json::to_string_pretty(bundle)?;
        zip.write_all(manifest_json.as_bytes())?;

        // Add verification manifest
        zip.start_file("verification.json", options)?;
        let verification_json = serde_json::to_string_pretty(&bundle.verification_manifest)?;
        zip.write_all(verification_json.as_bytes())?;

        // Add text report
        zip.start_file("report.txt", options)?;
        let report = Self::generate_text_report(bundle, config);
        zip.write_all(report.as_bytes())?;

        // Add individual artifact metadata (not content for security)
        if config.include_metadata {
            for (i, artifact) in bundle.artifacts.iter().enumerate() {
                let filename = format!("artifacts/artifact_{:03}_metadata.json", i + 1);
                zip.start_file(&filename, options)?;
                let artifact_json = serde_json::to_string_pretty(artifact)?;
                zip.write_all(artifact_json.as_bytes())?;
            }
        }

        zip.finish()?;
        
        let metadata = fs::metadata(&config.output_path)?;
        let checksum = Self::calculate_file_checksum(&config.output_path)?;

        Ok(ExportResult {
            export_id: bundle.bundle_id.to_string(),
            format: ExportFormat::ZIP,
            output_path: config.output_path.clone(),
            file_size_bytes: metadata.len(),
            export_timestamp: Utc::now(),
            bundle_count: 1,
            artifact_count: bundle.artifacts.len(),
            checksum,
        })
    }

    async fn export_oscal(
        bundle: &EvidenceBundle,
        config: &ExportConfig,
    ) -> EvidenceResult<ExportResult> {
        // OSCAL (Open Security Controls Assessment Language) export
        // This is a simplified version - real OSCAL would be more complex
        let oscal_data = OSCALBundle {
            uuid: bundle.bundle_id.to_string(),
            metadata: OSCALMetadata {
                title: bundle.name.clone(),
                published: bundle.created_at,
                last_modified: bundle.created_at,
                version: "1.0".to_string(),
            },
            assessment_results: OSCALAssessmentResults {
                uuid: bundle.bundle_id.to_string(),
                title: format!("{} Assessment Results", bundle.name),
                description: bundle.description.clone(),
                start: bundle.created_at,
                end: bundle.created_at,
                findings: bundle.artifacts.iter().map(|artifact| OSCALFinding {
                    uuid: artifact.artifact_id.to_string(),
                    title: artifact.name.clone(),
                    description: artifact.description.clone(),
                    implementation_statement_uuid: None,
                    related_observations: vec![],
                }).collect(),
            },
        };

        let oscal_json = serde_json::to_string_pretty(&oscal_data)?;
        fs::write(&config.output_path, &oscal_json)?;
        
        let metadata = fs::metadata(&config.output_path)?;
        let checksum = Self::calculate_checksum(&oscal_json);

        Ok(ExportResult {
            export_id: bundle.bundle_id.to_string(),
            format: ExportFormat::OSCAL,
            output_path: config.output_path.clone(),
            file_size_bytes: metadata.len(),
            export_timestamp: Utc::now(),
            bundle_count: 1,
            artifact_count: bundle.artifacts.len(),
            checksum,
        })
    }

    async fn export_csv(
        bundle: &EvidenceBundle,
        config: &ExportConfig,
    ) -> EvidenceResult<ExportResult> {
        let mut csv_content = String::new();
        
        // CSV header
        csv_content.push_str("Artifact ID,Name,Type,Source,Timestamp,Controls,Hash,Signed\n");
        
        // CSV rows
        for artifact in &bundle.artifacts {
            csv_content.push_str(&format!(
                "{},{},{:?},{},{},{},{},{}\n",
                artifact.artifact_id,
                artifact.name.replace(',', ";"), // Escape commas
                artifact.artifact_type,
                artifact.source,
                artifact.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
                artifact.related_controls.join(";"),
                artifact.content_hash,
                artifact.signature.is_some()
            ));
        }

        fs::write(&config.output_path, &csv_content)?;
        
        let metadata = fs::metadata(&config.output_path)?;
        let checksum = Self::calculate_checksum(&csv_content);

        Ok(ExportResult {
            export_id: bundle.bundle_id.to_string(),
            format: ExportFormat::CSV,
            output_path: config.output_path.clone(),
            file_size_bytes: metadata.len(),
            export_timestamp: Utc::now(),
            bundle_count: 1,
            artifact_count: bundle.artifacts.len(),
            checksum,
        })
    }

    async fn export_multiple_json(
        bundles: &[EvidenceBundle],
        config: &ExportConfig,
    ) -> EvidenceResult<ExportResult> {
        let export_data = serde_json::to_string_pretty(bundles)?;
        fs::write(&config.output_path, &export_data)?;
        
        let metadata = fs::metadata(&config.output_path)?;
        let checksum = Self::calculate_checksum(&export_data);
        let total_artifacts: usize = bundles.iter().map(|b| b.artifacts.len()).sum();

        Ok(ExportResult {
            export_id: format!("multi-bundle-{}", Utc::now().timestamp()),
            format: ExportFormat::JSON,
            output_path: config.output_path.clone(),
            file_size_bytes: metadata.len(),
            export_timestamp: Utc::now(),
            bundle_count: bundles.len(),
            artifact_count: total_artifacts,
            checksum,
        })
    }

    async fn export_multiple_zip(
        bundles: &[EvidenceBundle],
        config: &ExportConfig,
    ) -> EvidenceResult<ExportResult> {
        use std::fs::File;
        use zip::write::{FileOptions, ZipWriter};

        let file = File::create(&config.output_path)?;
        let mut zip = ZipWriter::new(file);
        let options = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

        // Add each bundle as a separate directory
        for (i, bundle) in bundles.iter().enumerate() {
            let bundle_dir = format!("bundle_{:03}_{}/", i + 1, bundle.bundle_id);
            
            // Bundle manifest
            zip.start_file(&format!("{}manifest.json", bundle_dir), options)?;
            let manifest_json = serde_json::to_string_pretty(bundle)?;
            zip.write_all(manifest_json.as_bytes())?;
            
            // Bundle report
            zip.start_file(&format!("{}report.txt", bundle_dir), options)?;
            let report = Self::generate_text_report(bundle, config);
            zip.write_all(report.as_bytes())?;
        }

        // Add combined index
        zip.start_file("index.json", options)?;
        let index = bundles.iter().map(|b| {
            serde_json::json!({
                "bundle_id": b.bundle_id,
                "name": b.name,
                "framework_id": b.framework_id,
                "control_count": b.control_ids.len(),
                "artifact_count": b.artifacts.len(),
                "created_at": b.created_at
            })
        }).collect::<Vec<_>>();
        zip.write_all(serde_json::to_string_pretty(&index)?.as_bytes())?;

        zip.finish()?;
        
        let metadata = fs::metadata(&config.output_path)?;
        let checksum = Self::calculate_file_checksum(&config.output_path)?;
        let total_artifacts: usize = bundles.iter().map(|b| b.artifacts.len()).sum();

        Ok(ExportResult {
            export_id: format!("multi-bundle-{}", Utc::now().timestamp()),
            format: ExportFormat::ZIP,
            output_path: config.output_path.clone(),
            file_size_bytes: metadata.len(),
            export_timestamp: Utc::now(),
            bundle_count: bundles.len(),
            artifact_count: total_artifacts,
            checksum,
        })
    }

    fn combine_bundles(bundles: &[EvidenceBundle]) -> EvidenceResult<EvidenceBundle> {
        if bundles.is_empty() {
            return Err(EvidenceError::BundleCreation("No bundles to combine".to_string()));
        }

        let first_bundle = &bundles[0];
        let mut combined_artifacts = Vec::new();
        let mut combined_control_ids = std::collections::HashSet::new();

        for bundle in bundles {
            combined_artifacts.extend(bundle.artifacts.clone());
            combined_control_ids.extend(bundle.control_ids.iter().cloned());
        }

        Ok(EvidenceBundle {
            bundle_id: uuid::Uuid::new_v4(),
            name: format!("Combined Bundle ({} bundles)", bundles.len()),
            description: "Combined evidence bundle from multiple sources".to_string(),
            framework_id: first_bundle.framework_id.clone(),
            snapshot_id: None,
            control_ids: combined_control_ids.into_iter().collect(),
            artifacts: combined_artifacts,
            created_at: Utc::now(),
            created_by: "system".to_string(),
            signature: None,
            verification_manifest: crate::VerificationManifest {
                manifest_version: "1.0".to_string(),
                bundle_hash: "combined".to_string(),
                artifact_hashes: std::collections::HashMap::new(),
                signatures: std::collections::HashMap::new(),
                verification_timestamp: Utc::now(),
                signing_key_id: None,
            },
        })
    }

    fn generate_text_report(bundle: &EvidenceBundle, _config: &ExportConfig) -> String {
        let mut report = String::new();
        
        report.push_str("GHOSTSHELL COMPLIANCE EVIDENCE REPORT\n");
        report.push_str("=====================================\n\n");
        
        report.push_str(&format!("Bundle ID: {}\n", bundle.bundle_id));
        report.push_str(&format!("Name: {}\n", bundle.name));
        report.push_str(&format!("Framework: {}\n", bundle.framework_id));
        report.push_str(&format!("Created: {}\n", bundle.created_at.format("%Y-%m-%d %H:%M:%S UTC")));
        report.push_str(&format!("Created By: {}\n", bundle.created_by));
        report.push_str(&format!("Description: {}\n\n", bundle.description));
        
        report.push_str("CONTROLS COVERED\n");
        report.push_str("================\n");
        for control_id in &bundle.control_ids {
            report.push_str(&format!("- {}\n", control_id));
        }
        report.push_str("\n");
        
        report.push_str("EVIDENCE ARTIFACTS\n");
        report.push_str("==================\n");
        for (i, artifact) in bundle.artifacts.iter().enumerate() {
            report.push_str(&format!("{}. {}\n", i + 1, artifact.name));
            report.push_str(&format!("   Type: {:?}\n", artifact.artifact_type));
            report.push_str(&format!("   Source: {}\n", artifact.source));
            report.push_str(&format!("   Timestamp: {}\n", artifact.timestamp.format("%Y-%m-%d %H:%M:%S UTC")));
            report.push_str(&format!("   Hash: {}\n", artifact.content_hash));
            report.push_str(&format!("   Signed: {}\n", artifact.signature.is_some()));
            report.push_str(&format!("   Controls: {}\n", artifact.related_controls.join(", ")));
            report.push_str("\n");
        }
        
        if bundle.signature.is_some() {
            report.push_str("DIGITAL SIGNATURE\n");
            report.push_str("=================\n");
            report.push_str("This bundle is digitally signed with post-quantum cryptography.\n");
            report.push_str(&format!("Signature Algorithm: Dilithium\n"));
            report.push_str(&format!("Verification Timestamp: {}\n", bundle.verification_manifest.verification_timestamp.format("%Y-%m-%d %H:%M:%S UTC")));
            report.push_str("\n");
        }
        
        report
    }

    fn calculate_checksum(data: &str) -> String {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(data.as_bytes());
        format!("sha3-256:{}", hex::encode(hasher.finalize()))
    }

    fn calculate_file_checksum(path: &PathBuf) -> EvidenceResult<String> {
        use sha3::{Digest, Sha3_256};
        let data = fs::read(path)?;
        let mut hasher = Sha3_256::new();
        hasher.update(&data);
        Ok(format!("sha3-256:{}", hex::encode(hasher.finalize())))
    }
}

// Supporting structures for exports

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LightweightBundle {
    bundle_id: uuid::Uuid,
    name: String,
    description: String,
    framework_id: String,
    control_ids: Vec<String>,
    artifact_count: usize,
    created_at: chrono::DateTime<Utc>,
    created_by: String,
    verification_manifest: crate::VerificationManifest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OSCALBundle {
    uuid: String,
    metadata: OSCALMetadata,
    assessment_results: OSCALAssessmentResults,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OSCALMetadata {
    title: String,
    published: chrono::DateTime<Utc>,
    last_modified: chrono::DateTime<Utc>,
    version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OSCALAssessmentResults {
    uuid: String,
    title: String,
    description: String,
    start: chrono::DateTime<Utc>,
    end: chrono::DateTime<Utc>,
    findings: Vec<OSCALFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OSCALFinding {
    uuid: String,
    title: String,
    description: String,
    implementation_statement_uuid: Option<String>,
    related_observations: Vec<String>,
}
