use crate::{EvidenceArtifact, ArtifactType, EvidenceResult};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Evidence graph node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceNode {
    pub node_id: Uuid,
    pub artifact: EvidenceArtifact,
    pub relationships: Vec<EvidenceRelationship>,
    pub trust_score: f64,
    pub provenance_chain: Vec<ProvenanceEntry>,
}

/// Relationship between evidence artifacts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRelationship {
    pub relationship_id: Uuid,
    pub target_node_id: Uuid,
    pub relationship_type: RelationshipType,
    pub strength: f64,
    pub description: String,
    pub created_at: DateTime<Utc>,
}

/// Types of relationships between evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RelationshipType {
    DerivedFrom,    // Target derived from source
    References,     // Source references target
    Supports,       // Source supports target's claims
    Contradicts,    // Source contradicts target
    Supersedes,     // Source supersedes target
    Correlates,     // Source correlates with target
    Validates,      // Source validates target
}

/// Provenance entry for audit trail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceEntry {
    pub entry_id: Uuid,
    pub action: ProvenanceAction,
    pub actor: String,
    pub timestamp: DateTime<Utc>,
    pub details: HashMap<String, String>,
    pub signature: Option<String>,
}

/// Provenance actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProvenanceAction {
    Created,
    Modified,
    Accessed,
    Copied,
    Moved,
    Deleted,
    Verified,
    Signed,
}

/// Evidence graph for managing relationships and provenance
pub struct EvidenceGraph {
    nodes: HashMap<Uuid, EvidenceNode>,
    control_index: HashMap<String, HashSet<Uuid>>,
    type_index: HashMap<ArtifactType, HashSet<Uuid>>,
    source_index: HashMap<String, HashSet<Uuid>>,
}

impl EvidenceGraph {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            control_index: HashMap::new(),
            type_index: HashMap::new(),
            source_index: HashMap::new(),
        }
    }

    pub fn add_artifact(&mut self, artifact: EvidenceArtifact) -> Uuid {
        let node_id = artifact.artifact_id;
        
        // Create provenance entry for creation
        let creation_entry = ProvenanceEntry {
            entry_id: Uuid::new_v4(),
            action: ProvenanceAction::Created,
            actor: artifact.source.clone(),
            timestamp: artifact.timestamp,
            details: HashMap::new(),
            signature: artifact.signature.clone(),
        };

        let node = EvidenceNode {
            node_id,
            artifact: artifact.clone(),
            relationships: Vec::new(),
            trust_score: 1.0, // Default trust score
            provenance_chain: vec![creation_entry],
        };

        // Update indexes
        for control_id in &artifact.related_controls {
            self.control_index
                .entry(control_id.clone())
                .or_insert_with(HashSet::new)
                .insert(node_id);
        }

        self.type_index
            .entry(artifact.artifact_type.clone())
            .or_insert_with(HashSet::new)
            .insert(node_id);

        self.source_index
            .entry(artifact.source.clone())
            .or_insert_with(HashSet::new)
            .insert(node_id);

        self.nodes.insert(node_id, node);
        node_id
    }

    pub fn add_relationship(
        &mut self,
        source_id: Uuid,
        target_id: Uuid,
        relationship_type: RelationshipType,
        strength: f64,
        description: String,
    ) -> EvidenceResult<Uuid> {
        let relationship_id = Uuid::new_v4();
        
        let relationship = EvidenceRelationship {
            relationship_id,
            target_node_id: target_id,
            relationship_type,
            strength,
            description,
            created_at: Utc::now(),
        };

        if let Some(source_node) = self.nodes.get_mut(&source_id) {
            source_node.relationships.push(relationship);
            Ok(relationship_id)
        } else {
            Err(crate::EvidenceError::ArtifactNotFound(source_id.to_string()))
        }
    }

    pub fn get_artifact(&self, node_id: &Uuid) -> Option<&EvidenceArtifact> {
        self.nodes.get(node_id).map(|node| &node.artifact)
    }

    pub fn get_node(&self, node_id: &Uuid) -> Option<&EvidenceNode> {
        self.nodes.get(node_id)
    }

    pub fn find_artifacts_for_control(&self, control_id: &str) -> Vec<&EvidenceArtifact> {
        if let Some(node_ids) = self.control_index.get(control_id) {
            node_ids
                .iter()
                .filter_map(|id| self.nodes.get(id))
                .map(|node| &node.artifact)
                .collect()
        } else {
            Vec::new()
        }
    }

    pub fn find_artifacts_by_type(&self, artifact_type: &ArtifactType) -> Vec<&EvidenceArtifact> {
        if let Some(node_ids) = self.type_index.get(artifact_type) {
            node_ids
                .iter()
                .filter_map(|id| self.nodes.get(id))
                .map(|node| &node.artifact)
                .collect()
        } else {
            Vec::new()
        }
    }

    pub fn find_artifacts_by_source(&self, source: &str) -> Vec<&EvidenceArtifact> {
        if let Some(node_ids) = self.source_index.get(source) {
            node_ids
                .iter()
                .filter_map(|id| self.nodes.get(id))
                .map(|node| &node.artifact)
                .collect()
        } else {
            Vec::new()
        }
    }

    pub fn get_related_artifacts(&self, node_id: &Uuid) -> Vec<(&EvidenceRelationship, &EvidenceArtifact)> {
        if let Some(node) = self.nodes.get(node_id) {
            node.relationships
                .iter()
                .filter_map(|rel| {
                    self.nodes
                        .get(&rel.target_node_id)
                        .map(|target_node| (rel, &target_node.artifact))
                })
                .collect()
        } else {
            Vec::new()
        }
    }

    pub fn calculate_trust_score(&mut self, node_id: &Uuid) -> f64 {
        if let Some(node) = self.nodes.get(node_id) {
            let mut score = 1.0;

            // Factor in source reliability (simplified)
            match node.artifact.source.as_str() {
                "ghost_log" => score *= 1.0,      // Highest trust
                "ghost_vault" => score *= 0.95,   // Very high trust
                "pcap_studio" => score *= 0.9,    // High trust
                "manual" => score *= 0.7,         // Lower trust
                _ => score *= 0.8,                 // Default trust
            }

            // Factor in signature presence
            if node.artifact.signature.is_some() {
                score *= 1.1; // Boost for signed artifacts
            }

            // Factor in age (newer is generally more trusted)
            let age_hours = (Utc::now() - node.artifact.timestamp).num_hours();
            if age_hours < 24 {
                score *= 1.05; // Recent artifacts get slight boost
            } else if age_hours > 24 * 30 {
                score *= 0.95; // Old artifacts get slight penalty
            }

            // Factor in relationships
            let supporting_relationships = node.relationships
                .iter()
                .filter(|rel| matches!(rel.relationship_type, RelationshipType::Supports | RelationshipType::Validates))
                .count();
            
            let contradicting_relationships = node.relationships
                .iter()
                .filter(|rel| matches!(rel.relationship_type, RelationshipType::Contradicts))
                .count();

            if supporting_relationships > 0 {
                score *= 1.0 + (supporting_relationships as f64 * 0.05);
            }
            
            if contradicting_relationships > 0 {
                score *= 1.0 - (contradicting_relationships as f64 * 0.1);
            }

            // Clamp score between 0.0 and 1.0
            score = score.max(0.0).min(1.0);

            // Update the stored trust score
            if let Some(node_mut) = self.nodes.get_mut(node_id) {
                node_mut.trust_score = score;
            }

            score
        } else {
            0.0
        }
    }

    pub fn add_provenance_entry(&mut self, node_id: &Uuid, entry: ProvenanceEntry) -> EvidenceResult<()> {
        if let Some(node) = self.nodes.get_mut(node_id) {
            node.provenance_chain.push(entry);
            Ok(())
        } else {
            Err(crate::EvidenceError::ArtifactNotFound(node_id.to_string()))
        }
    }

    pub fn get_provenance_chain(&self, node_id: &Uuid) -> Option<&Vec<ProvenanceEntry>> {
        self.nodes.get(node_id).map(|node| &node.provenance_chain)
    }

    pub fn list_all_artifacts(&self) -> Vec<&EvidenceArtifact> {
        self.nodes.values().map(|node| &node.artifact).collect()
    }

    pub fn get_statistics(&self) -> GraphStatistics {
        let total_artifacts = self.nodes.len();
        let total_relationships: usize = self.nodes.values().map(|node| node.relationships.len()).sum();
        
        let mut type_counts = HashMap::new();
        let mut source_counts = HashMap::new();
        let mut signed_count = 0;

        for node in self.nodes.values() {
            *type_counts.entry(format!("{:?}", node.artifact.artifact_type)).or_insert(0) += 1;
            *source_counts.entry(node.artifact.source.clone()).or_insert(0) += 1;
            
            if node.artifact.signature.is_some() {
                signed_count += 1;
            }
        }

        GraphStatistics {
            total_artifacts,
            total_relationships,
            signed_artifacts: signed_count,
            type_distribution: type_counts,
            source_distribution: source_counts,
        }
    }
}

impl Default for EvidenceGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about the evidence graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphStatistics {
    pub total_artifacts: usize,
    pub total_relationships: usize,
    pub signed_artifacts: usize,
    pub type_distribution: HashMap<String, usize>,
    pub source_distribution: HashMap<String, usize>,
}
