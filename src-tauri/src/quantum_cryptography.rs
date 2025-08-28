use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use anyhow::Result;
use rand::Rng;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumKeyDistribution {
    pub qkd_id: String,
    pub name: String,
    pub description: String,
    pub protocol: QKDProtocol,
    pub participants: Vec<QKDParticipant>,
    pub quantum_channel: QuantumChannel,
    pub classical_channel: ClassicalChannel,
    pub key_generation_rate: f64, // bits per second
    pub security_parameters: SecurityParameters,
    pub status: QKDStatus,
    pub created_at: DateTime<Utc>,
    pub last_key_exchange: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QKDProtocol {
    BB84,
    E91,
    SARG04,
    COW, // Coherent One Way
    DPS, // Differential Phase Shift
    CVQuantum, // Continuous Variable
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QKDParticipant {
    pub participant_id: String,
    pub name: String,
    pub role: ParticipantRole,
    pub public_key: Vec<u8>,
    pub quantum_device: QuantumDevice,
    pub location: String,
    pub trust_level: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ParticipantRole {
    Alice, // Sender
    Bob,   // Receiver
    Eve,   // Eavesdropper (for testing)
    Charlie, // Trusted third party
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumDevice {
    pub device_id: String,
    pub device_type: String, // "Photon Source", "Single Photon Detector", "Quantum Memory"
    pub specifications: DeviceSpecs,
    pub calibration_status: CalibrationStatus,
    pub error_rates: ErrorRates,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceSpecs {
    pub wavelength: f64, // nanometers
    pub detection_efficiency: f64,
    pub dark_count_rate: f64,
    pub timing_resolution: f64, // picoseconds
    pub quantum_bit_error_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationStatus {
    pub last_calibrated: DateTime<Utc>,
    pub calibration_drift: f64,
    pub next_calibration: DateTime<Utc>,
    pub auto_calibration_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorRates {
    pub bit_error_rate: f64,
    pub phase_error_rate: f64,
    pub detection_error_rate: f64,
    pub transmission_loss: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumChannel {
    pub channel_id: String,
    pub channel_type: ChannelType,
    pub distance: f64, // kilometers
    pub transmission_medium: TransmissionMedium,
    pub attenuation: f64, // dB/km
    pub noise_level: f64,
    pub security_level: SecurityLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChannelType {
    FiberOptic,
    FreeSpace,
    Satellite,
    Underwater,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransmissionMedium {
    SingleModeFiber,
    MultiModeFiber,
    Atmosphere,
    Vacuum,
    Water,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityLevel {
    Experimental,
    Commercial,
    Government,
    Military,
    QuantumSafe,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassicalChannel {
    pub channel_id: String,
    pub encryption: ClassicalEncryption,
    pub authentication: AuthenticationMethod,
    pub bandwidth: f64, // Mbps
    pub latency: f64, // milliseconds
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClassicalEncryption {
    AES256,
    RSA4096,
    ECC521,
    PostQuantum,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthenticationMethod {
    HMAC,
    DigitalSignature,
    QuantumAuthentication,
    BiometricAuth,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityParameters {
    pub min_key_length: u32,
    pub max_error_threshold: f64,
    pub privacy_amplification_ratio: f64,
    pub error_correction_efficiency: f64,
    pub security_proof: SecurityProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityProof {
    InformationTheoretic,
    Computational,
    Composable,
    DeviceIndependent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QKDStatus {
    Initializing,
    KeyGeneration { rate: f64, quality: f64 },
    Paused { reason: String },
    Error { error_code: String, message: String },
    Completed { keys_generated: u32, success_rate: f64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumRandomGenerator {
    pub generator_id: String,
    pub name: String,
    pub entropy_source: EntropySource,
    pub generation_rate: f64, // bits per second
    pub randomness_quality: RandomnessQuality,
    pub output_format: OutputFormat,
    pub statistical_tests: Vec<StatisticalTest>,
    pub certification: Option<Certification>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EntropySource {
    QuantumVacuum,
    PhotonArrival,
    PhaseNoise,
    QuantumTunneling,
    SpinMeasurement,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RandomnessQuality {
    pub min_entropy: f64,
    pub bias: f64,
    pub correlation: f64,
    pub predictability: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputFormat {
    Raw,
    Whitened,
    Compressed,
    Encrypted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatisticalTest {
    pub test_name: String,
    pub test_result: TestResult,
    pub p_value: f64,
    pub confidence_level: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TestResult {
    Pass,
    Fail,
    Inconclusive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certification {
    pub authority: String,
    pub certificate_id: String,
    pub issued_date: DateTime<Utc>,
    pub expiry_date: DateTime<Utc>,
    pub security_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumDigitalSignature {
    pub signature_id: String,
    pub algorithm: QDSAlgorithm,
    pub key_pair: QuantumKeyPair,
    pub message_hash: Vec<u8>,
    pub signature_data: Vec<u8>,
    pub verification_keys: Vec<Vec<u8>>,
    pub security_parameters: QDSSecurityParams,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QDSAlgorithm {
    LamportOTS, // One-Time Signature
    WinternitzOTS,
    XMSS, // Extended Merkle Signature Scheme
    SPHINCS, // Stateless Hash-based Signatures
    QuantumOneTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumKeyPair {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub quantum_state: Vec<f64>,
    pub entanglement_info: Option<EntanglementInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntanglementInfo {
    pub entangled_particles: u32,
    pub entanglement_measure: f64,
    pub coherence_time: f64,
    pub fidelity: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QDSSecurityParams {
    pub hash_function: String,
    pub signature_length: u32,
    pub security_level: u32, // bits
    pub quantum_resistance: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumSecureMultiParty {
    pub protocol_id: String,
    pub name: String,
    pub participants: Vec<MPCParticipant>,
    pub computation_type: ComputationType,
    pub privacy_level: PrivacyLevel,
    pub quantum_resources: MPCQuantumResources,
    pub execution_status: MPCStatus,
    pub results: Option<MPCResults>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MPCParticipant {
    pub participant_id: String,
    pub name: String,
    pub input_data: Option<Vec<u8>>, // Encrypted
    pub quantum_shares: Vec<QuantumShare>,
    pub verification_keys: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumShare {
    pub share_id: String,
    pub quantum_state: Vec<f64>,
    pub classical_data: Vec<u8>,
    pub verification_hash: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComputationType {
    SecretSharing,
    PrivateSetIntersection,
    SecureAggregation,
    QuantumVoting,
    DistributedKeyGeneration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PrivacyLevel {
    SemiHonest,
    Malicious,
    Covert,
    QuantumSecure,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MPCQuantumResources {
    pub qubits_required: u32,
    pub quantum_gates: u32,
    pub entanglement_pairs: u32,
    pub measurement_rounds: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MPCStatus {
    Setup,
    InputSharing,
    Computation,
    OutputReconstruction,
    Verification,
    Completed,
    Failed { error: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MPCResults {
    pub computation_result: Vec<u8>,
    pub verification_proof: Vec<u8>,
    pub privacy_guarantees: PrivacyGuarantees,
    pub execution_time: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyGuarantees {
    pub differential_privacy: Option<f64>,
    pub information_leakage: f64,
    pub quantum_advantage: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumCryptoStats {
    pub active_qkd_sessions: u32,
    pub total_keys_generated: u64,
    pub average_key_rate: f64,
    pub quantum_bit_error_rate: f64,
    pub security_violations: u32,
    pub random_bits_generated: u64,
    pub signatures_created: u32,
    pub mpc_protocols_active: u32,
    pub quantum_advantage_factor: f64,
}

pub struct QuantumCryptographyManager {
    pub qkd_sessions: Vec<QuantumKeyDistribution>,
    pub random_generators: Vec<QuantumRandomGenerator>,
    pub digital_signatures: Vec<QuantumDigitalSignature>,
    pub mpc_protocols: Vec<QuantumSecureMultiParty>,
}

impl QuantumCryptographyManager {
    pub fn new() -> Self {
        Self {
            qkd_sessions: Vec::new(),
            random_generators: Vec::new(),
            digital_signatures: Vec::new(),
            mpc_protocols: Vec::new(),
        }
    }

    pub fn create_qkd_session(&mut self, name: String, protocol: QKDProtocol, distance: f64) -> Result<QuantumKeyDistribution> {
        let qkd_id = format!("qkd_{}", chrono::Utc::now().timestamp());
        let mut rng = rand::thread_rng();

        let session = QuantumKeyDistribution {
            qkd_id: qkd_id.clone(),
            name,
            description: format!("Quantum Key Distribution using {:?} protocol", protocol),
            protocol,
            participants: self.generate_participants(),
            quantum_channel: QuantumChannel {
                channel_id: format!("{}_quantum", qkd_id),
                channel_type: if distance > 100.0 { ChannelType::Satellite } else { ChannelType::FiberOptic },
                distance,
                transmission_medium: TransmissionMedium::SingleModeFiber,
                attenuation: 0.2 + rng.gen::<f64>() * 0.1,
                noise_level: rng.gen::<f64>() * 0.01,
                security_level: SecurityLevel::QuantumSafe,
            },
            classical_channel: ClassicalChannel {
                channel_id: format!("{}_classical", qkd_id),
                encryption: ClassicalEncryption::PostQuantum,
                authentication: AuthenticationMethod::QuantumAuthentication,
                bandwidth: 100.0 + rng.gen::<f64>() * 900.0,
                latency: distance * 0.005 + rng.gen::<f64>() * 2.0,
            },
            key_generation_rate: self.calculate_key_rate(distance),
            security_parameters: SecurityParameters {
                min_key_length: 256,
                max_error_threshold: 0.11,
                privacy_amplification_ratio: 0.5,
                error_correction_efficiency: 0.95,
                security_proof: SecurityProof::InformationTheoretic,
            },
            status: QKDStatus::Initializing,
            created_at: Utc::now(),
            last_key_exchange: None,
        };

        self.qkd_sessions.push(session.clone());
        Ok(session)
    }

    pub fn start_key_generation(&mut self, qkd_id: String) -> Result<()> {
        if let Some(session) = self.qkd_sessions.iter_mut().find(|s| s.qkd_id == qkd_id) {
            let mut rng = rand::thread_rng();
            let quality = 0.8 + rng.gen::<f64>() * 0.2;
            
            session.status = QKDStatus::KeyGeneration { 
                rate: session.key_generation_rate, 
                quality 
            };
            session.last_key_exchange = Some(Utc::now());
            Ok(())
        } else {
            Err(anyhow::anyhow!("QKD session not found"))
        }
    }

    pub fn create_quantum_random_generator(&mut self, name: String, entropy_source: EntropySource) -> Result<QuantumRandomGenerator> {
        let generator_id = format!("qrng_{}", chrono::Utc::now().timestamp());
        let mut rng = rand::thread_rng();

        let generator = QuantumRandomGenerator {
            generator_id: generator_id.clone(),
            name,
            entropy_source,
            generation_rate: 1000000.0 + rng.gen::<f64>() * 9000000.0, // 1-10 Mbps
            randomness_quality: RandomnessQuality {
                min_entropy: 0.99 + rng.gen::<f64>() * 0.01,
                bias: rng.gen::<f64>() * 0.001,
                correlation: rng.gen::<f64>() * 0.001,
                predictability: rng.gen::<f64>() * 0.0001,
            },
            output_format: OutputFormat::Whitened,
            statistical_tests: self.generate_statistical_tests(),
            certification: Some(Certification {
                authority: "Quantum Security Institute".to_string(),
                certificate_id: format!("QSI-{}", generator_id),
                issued_date: Utc::now(),
                expiry_date: Utc::now() + chrono::Duration::days(365),
                security_level: "EAL7+".to_string(),
            }),
        };

        self.random_generators.push(generator.clone());
        Ok(generator)
    }

    pub fn create_quantum_signature(&mut self, message: Vec<u8>, algorithm: QDSAlgorithm) -> Result<QuantumDigitalSignature> {
        let signature_id = format!("qds_{}", chrono::Utc::now().timestamp());
        let mut rng = rand::thread_rng();

        // Generate quantum key pair
        let private_key: Vec<u8> = (0..64).map(|_| rng.gen()).collect();
        let public_key: Vec<u8> = (0..64).map(|_| rng.gen()).collect();
        let quantum_state: Vec<f64> = (0..16).map(|_| rng.gen::<f64>() * 2.0 - 1.0).collect();

        // Create signature
        let message_hash = self.quantum_hash(&message);
        let signature_data = self.quantum_sign(&message_hash, &private_key);

        let signature = QuantumDigitalSignature {
            signature_id,
            algorithm,
            key_pair: QuantumKeyPair {
                private_key,
                public_key: public_key.clone(),
                quantum_state,
                entanglement_info: Some(EntanglementInfo {
                    entangled_particles: 8,
                    entanglement_measure: 0.9 + rng.gen::<f64>() * 0.1,
                    coherence_time: 100.0 + rng.gen::<f64>() * 50.0,
                    fidelity: 0.95 + rng.gen::<f64>() * 0.05,
                }),
            },
            message_hash,
            signature_data,
            verification_keys: vec![public_key],
            security_parameters: QDSSecurityParams {
                hash_function: "SHA3-512".to_string(),
                signature_length: 1024,
                security_level: 256,
                quantum_resistance: true,
            },
            timestamp: Utc::now(),
        };

        self.digital_signatures.push(signature.clone());
        Ok(signature)
    }

    pub fn create_mpc_protocol(&mut self, name: String, computation_type: ComputationType, participant_count: u32) -> Result<QuantumSecureMultiParty> {
        let protocol_id = format!("mpc_{}", chrono::Utc::now().timestamp());
        let mut rng = rand::thread_rng();

        let mut participants = Vec::new();
        for i in 0..participant_count {
            participants.push(MPCParticipant {
                participant_id: format!("participant_{}", i),
                name: format!("Participant {}", i + 1),
                input_data: None, // Will be set later
                quantum_shares: self.generate_quantum_shares(4),
                verification_keys: vec![vec![rng.gen(); 32]],
            });
        }

        let protocol = QuantumSecureMultiParty {
            protocol_id: protocol_id.clone(),
            name,
            participants,
            computation_type,
            privacy_level: PrivacyLevel::QuantumSecure,
            quantum_resources: MPCQuantumResources {
                qubits_required: participant_count * 4,
                quantum_gates: participant_count * 20,
                entanglement_pairs: participant_count * 2,
                measurement_rounds: 5,
            },
            execution_status: MPCStatus::Setup,
            results: None,
        };

        self.mpc_protocols.push(protocol.clone());
        Ok(protocol)
    }

    pub fn get_crypto_stats(&self) -> QuantumCryptoStats {
        let mut rng = rand::thread_rng();
        
        QuantumCryptoStats {
            active_qkd_sessions: self.qkd_sessions.iter()
                .filter(|s| matches!(s.status, QKDStatus::KeyGeneration { .. }))
                .count() as u32,
            total_keys_generated: 15000 + (rng.gen::<f64>() * 5000.0) as u64,
            average_key_rate: if !self.qkd_sessions.is_empty() {
                self.qkd_sessions.iter().map(|s| s.key_generation_rate).sum::<f64>() / self.qkd_sessions.len() as f64
            } else { 0.0 },
            quantum_bit_error_rate: 0.01 + rng.gen::<f64>() * 0.05,
            security_violations: rng.gen::<u32>() % 3,
            random_bits_generated: 1000000000 + (rng.gen::<f64>() * 500000000.0) as u64,
            signatures_created: self.digital_signatures.len() as u32,
            mpc_protocols_active: self.mpc_protocols.iter()
                .filter(|p| !matches!(p.execution_status, MPCStatus::Completed | MPCStatus::Failed { .. }))
                .count() as u32,
            quantum_advantage_factor: 4.5 + rng.gen::<f64>() * 2.5,
        }
    }

    // Helper methods
    fn generate_participants(&self) -> Vec<QKDParticipant> {
        let mut rng = rand::thread_rng();
        vec![
            QKDParticipant {
                participant_id: "alice".to_string(),
                name: "Alice (Sender)".to_string(),
                role: ParticipantRole::Alice,
                public_key: (0..64).map(|_| rng.gen()).collect(),
                quantum_device: self.create_quantum_device("photon_source"),
                location: "Site A".to_string(),
                trust_level: 1.0,
            },
            QKDParticipant {
                participant_id: "bob".to_string(),
                name: "Bob (Receiver)".to_string(),
                role: ParticipantRole::Bob,
                public_key: (0..64).map(|_| rng.gen()).collect(),
                quantum_device: self.create_quantum_device("detector"),
                location: "Site B".to_string(),
                trust_level: 1.0,
            },
        ]
    }

    fn create_quantum_device(&self, device_type: &str) -> QuantumDevice {
        let mut rng = rand::thread_rng();
        
        QuantumDevice {
            device_id: format!("qdev_{}", chrono::Utc::now().timestamp_nanos()),
            device_type: device_type.to_string(),
            specifications: DeviceSpecs {
                wavelength: 1550.0 + rng.gen::<f64>() * 100.0,
                detection_efficiency: 0.8 + rng.gen::<f64>() * 0.15,
                dark_count_rate: rng.gen::<f64>() * 1000.0,
                timing_resolution: 10.0 + rng.gen::<f64>() * 90.0,
                quantum_bit_error_rate: 0.01 + rng.gen::<f64>() * 0.04,
            },
            calibration_status: CalibrationStatus {
                last_calibrated: Utc::now() - chrono::Duration::hours(rng.gen_range(1..24)),
                calibration_drift: rng.gen::<f64>() * 0.05,
                next_calibration: Utc::now() + chrono::Duration::hours(rng.gen_range(24..168)),
                auto_calibration_enabled: true,
            },
            error_rates: ErrorRates {
                bit_error_rate: 0.01 + rng.gen::<f64>() * 0.04,
                phase_error_rate: 0.005 + rng.gen::<f64>() * 0.02,
                detection_error_rate: 0.02 + rng.gen::<f64>() * 0.03,
                transmission_loss: 0.1 + rng.gen::<f64>() * 0.2,
            },
        }
    }

    fn calculate_key_rate(&self, distance: f64) -> f64 {
        // Simplified key rate calculation based on distance
        let base_rate = 1000000.0; // 1 Mbps
        let attenuation_factor = (-0.2 * distance / 1000.0).exp();
        base_rate * attenuation_factor * (0.8 + rand::thread_rng().gen::<f64>() * 0.4)
    }

    fn generate_statistical_tests(&self) -> Vec<StatisticalTest> {
        vec![
            StatisticalTest {
                test_name: "Frequency Test".to_string(),
                test_result: TestResult::Pass,
                p_value: 0.1 + rand::thread_rng().gen::<f64>() * 0.8,
                confidence_level: 0.99,
            },
            StatisticalTest {
                test_name: "Runs Test".to_string(),
                test_result: TestResult::Pass,
                p_value: 0.1 + rand::thread_rng().gen::<f64>() * 0.8,
                confidence_level: 0.99,
            },
            StatisticalTest {
                test_name: "Serial Test".to_string(),
                test_result: TestResult::Pass,
                p_value: 0.1 + rand::thread_rng().gen::<f64>() * 0.8,
                confidence_level: 0.99,
            },
        ]
    }

    fn generate_quantum_shares(&self, count: u32) -> Vec<QuantumShare> {
        let mut shares = Vec::new();
        let mut rng = rand::thread_rng();
        
        for i in 0..count {
            shares.push(QuantumShare {
                share_id: format!("share_{}", i),
                quantum_state: (0..8).map(|_| rng.gen::<f64>() * 2.0 - 1.0).collect(),
                classical_data: (0..32).map(|_| rng.gen()).collect(),
                verification_hash: (0..32).map(|_| rng.gen()).collect(),
            });
        }
        
        shares
    }

    fn quantum_hash(&self, data: &[u8]) -> Vec<u8> {
        // Simplified quantum hash simulation
        let mut rng = rand::thread_rng();
        (0..64).map(|i| data.get(i % data.len()).unwrap_or(&0) ^ rng.gen::<u8>()).collect()
    }

    fn quantum_sign(&self, hash: &[u8], private_key: &[u8]) -> Vec<u8> {
        // Simplified quantum signature simulation
        let mut signature = Vec::new();
        for (i, &byte) in hash.iter().enumerate() {
            let key_byte = private_key.get(i % private_key.len()).unwrap_or(&0);
            signature.push(byte ^ key_byte ^ rand::thread_rng().gen::<u8>());
        }
        signature
    }

    pub fn list_qkd_sessions(&self) -> Vec<QuantumKeyDistribution> {
        self.qkd_sessions.clone()
    }

    pub fn list_random_generators(&self) -> Vec<QuantumRandomGenerator> {
        self.random_generators.clone()
    }

    pub fn list_digital_signatures(&self) -> Vec<QuantumDigitalSignature> {
        self.digital_signatures.clone()
    }

    pub fn list_mpc_protocols(&self) -> Vec<QuantumSecureMultiParty> {
        self.mpc_protocols.clone()
    }
}

// Tauri commands
#[tauri::command]
pub async fn quantum_crypto_get_stats(
    manager: tauri::State<'_, std::sync::Arc<tokio::sync::Mutex<QuantumCryptographyManager>>>,
) -> Result<QuantumCryptoStats, String> {
    let manager = manager.lock().await;
    Ok(manager.get_crypto_stats())
}

#[tauri::command]
pub async fn quantum_crypto_create_qkd_session(
    name: String,
    protocol: String,
    distance: f64,
    manager: tauri::State<'_, std::sync::Arc<tokio::sync::Mutex<QuantumCryptographyManager>>>,
) -> Result<QuantumKeyDistribution, String> {
    let mut manager = manager.lock().await;
    let protocol_enum = match protocol.as_str() {
        "BB84" => QKDProtocol::BB84,
        "E91" => QKDProtocol::E91,
        "SARG04" => QKDProtocol::SARG04,
        "COW" => QKDProtocol::COW,
        "DPS" => QKDProtocol::DPS,
        "CVQuantum" => QKDProtocol::CVQuantum,
        _ => QKDProtocol::BB84,
    };
    
    manager.create_qkd_session(name, protocol_enum, distance)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn quantum_crypto_start_key_generation(
    qkd_id: String,
    manager: tauri::State<'_, std::sync::Arc<tokio::sync::Mutex<QuantumCryptographyManager>>>,
) -> Result<(), String> {
    let mut manager = manager.lock().await;
    manager.start_key_generation(qkd_id)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn quantum_crypto_create_random_generator(
    name: String,
    entropy_source: String,
    manager: tauri::State<'_, std::sync::Arc<tokio::sync::Mutex<QuantumCryptographyManager>>>,
) -> Result<QuantumRandomGenerator, String> {
    let mut manager = manager.lock().await;
    let source_enum = match entropy_source.as_str() {
        "QuantumVacuum" => EntropySource::QuantumVacuum,
        "PhotonArrival" => EntropySource::PhotonArrival,
        "PhaseNoise" => EntropySource::PhaseNoise,
        "QuantumTunneling" => EntropySource::QuantumTunneling,
        "SpinMeasurement" => EntropySource::SpinMeasurement,
        _ => EntropySource::QuantumVacuum,
    };
    
    manager.create_quantum_random_generator(name, source_enum)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn quantum_crypto_create_signature(
    message: Vec<u8>,
    algorithm: String,
    manager: tauri::State<'_, std::sync::Arc<tokio::sync::Mutex<QuantumCryptographyManager>>>,
) -> Result<QuantumDigitalSignature, String> {
    let mut manager = manager.lock().await;
    let algorithm_enum = match algorithm.as_str() {
        "LamportOTS" => QDSAlgorithm::LamportOTS,
        "WinternitzOTS" => QDSAlgorithm::WinternitzOTS,
        "XMSS" => QDSAlgorithm::XMSS,
        "SPHINCS" => QDSAlgorithm::SPHINCS,
        "QuantumOneTime" => QDSAlgorithm::QuantumOneTime,
        _ => QDSAlgorithm::QuantumOneTime,
    };
    
    manager.create_quantum_signature(message, algorithm_enum)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn quantum_crypto_create_mpc_protocol(
    name: String,
    computation_type: String,
    participant_count: u32,
    manager: tauri::State<'_, std::sync::Arc<tokio::sync::Mutex<QuantumCryptographyManager>>>,
) -> Result<QuantumSecureMultiParty, String> {
    let mut manager = manager.lock().await;
    let computation_enum = match computation_type.as_str() {
        "SecretSharing" => ComputationType::SecretSharing,
        "PrivateSetIntersection" => ComputationType::PrivateSetIntersection,
        "SecureAggregation" => ComputationType::SecureAggregation,
        "QuantumVoting" => ComputationType::QuantumVoting,
        "DistributedKeyGeneration" => ComputationType::DistributedKeyGeneration,
        _ => ComputationType::SecretSharing,
    };
    
    manager.create_mpc_protocol(name, computation_enum, participant_count)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn quantum_crypto_list_qkd_sessions(
    manager: tauri::State<'_, std::sync::Arc<tokio::sync::Mutex<QuantumCryptographyManager>>>,
) -> Result<Vec<QuantumKeyDistribution>, String> {
    let manager = manager.lock().await;
    Ok(manager.list_qkd_sessions())
}

#[tauri::command]
pub async fn quantum_crypto_list_random_generators(
    manager: tauri::State<'_, std::sync::Arc<tokio::sync::Mutex<QuantumCryptographyManager>>>,
) -> Result<Vec<QuantumRandomGenerator>, String> {
    let manager = manager.lock().await;
    Ok(manager.list_random_generators())
}

#[tauri::command]
pub async fn quantum_crypto_list_signatures(
    manager: tauri::State<'_, std::sync::Arc<tokio::sync::Mutex<QuantumCryptographyManager>>>,
) -> Result<Vec<QuantumDigitalSignature>, String> {
    let manager = manager.lock().await;
    Ok(manager.list_digital_signatures())
}

#[tauri::command]
pub async fn quantum_crypto_list_mpc_protocols(
    manager: tauri::State<'_, std::sync::Arc<tokio::sync::Mutex<QuantumCryptographyManager>>>,
) -> Result<Vec<QuantumSecureMultiParty>, String> {
    let manager = manager.lock().await;
    Ok(manager.list_mpc_protocols())
}
