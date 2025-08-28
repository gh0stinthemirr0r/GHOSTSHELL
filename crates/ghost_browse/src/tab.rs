use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

use ghost_tls::PQPosture;

/// Browser tab state
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TabState {
    Loading,
    Active,
    Inactive,
    Error,
    Closed,
}

/// Browser tab metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TabMeta {
    pub id: String,
    pub url: String,
    pub title: Option<String>,
    pub pq_posture: Option<PQPosture>,
    pub vault_used: Vec<String>,
    pub state: TabState,
    pub created_at: DateTime<Utc>,
    pub last_accessed: DateTime<Utc>,
    pub is_incognito: bool,
}

impl TabMeta {
    /// Create a new tab
    pub fn new(url: String, is_incognito: bool) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            url,
            title: None,
            pq_posture: None,
            vault_used: vec![],
            state: TabState::Loading,
            created_at: now,
            last_accessed: now,
            is_incognito,
        }
    }

    /// Update the tab's PQ posture
    pub fn set_posture(&mut self, posture: PQPosture) {
        self.pq_posture = Some(posture);
        self.last_accessed = Utc::now();
    }

    /// Add a vault secret usage
    pub fn add_vault_usage(&mut self, secret_id: String) {
        if !self.vault_used.contains(&secret_id) {
            self.vault_used.push(secret_id);
        }
        self.last_accessed = Utc::now();
    }

    /// Update tab state
    pub fn set_state(&mut self, state: TabState) {
        self.state = state;
        self.last_accessed = Utc::now();
    }

    /// Set the page title
    pub fn set_title(&mut self, title: String) {
        self.title = Some(title);
        self.last_accessed = Utc::now();
    }

    /// Check if tab is active
    pub fn is_active(&self) -> bool {
        matches!(self.state, TabState::Active)
    }

    /// Get display title (URL if no title set)
    pub fn display_title(&self) -> &str {
        self.title.as_deref().unwrap_or(&self.url)
    }
}

/// Browser tab history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TabHistoryEntry {
    pub url: String,
    pub title: Option<String>,
    pub visited_at: DateTime<Utc>,
    pub pq_posture: Option<PQPosture>,
    pub vault_used: Vec<String>,
}

/// Browser tab with history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserTab {
    pub meta: TabMeta,
    pub history: Vec<TabHistoryEntry>,
    pub current_index: usize,
}

impl BrowserTab {
    /// Create a new browser tab
    pub fn new(url: String, is_incognito: bool) -> Self {
        let meta = TabMeta::new(url.clone(), is_incognito);
        let history = vec![TabHistoryEntry {
            url,
            title: None,
            visited_at: Utc::now(),
            pq_posture: None,
            vault_used: vec![],
        }];

        Self {
            meta,
            history,
            current_index: 0,
        }
    }

    /// Navigate to a new URL
    pub fn navigate(&mut self, url: String) {
        // Add new history entry
        let entry = TabHistoryEntry {
            url: url.clone(),
            title: None,
            visited_at: Utc::now(),
            pq_posture: None,
            vault_used: vec![],
        };

        // Remove any forward history
        self.history.truncate(self.current_index + 1);
        
        // Add new entry
        self.history.push(entry);
        self.current_index = self.history.len() - 1;

        // Update meta
        self.meta.url = url;
        self.meta.title = None;
        self.meta.pq_posture = None;
        self.meta.vault_used.clear();
        self.meta.set_state(TabState::Loading);
    }

    /// Go back in history
    pub fn go_back(&mut self) -> Option<&str> {
        if self.current_index > 0 {
            self.current_index -= 1;
            let entry = &self.history[self.current_index];
            self.meta.url = entry.url.clone();
            self.meta.title = entry.title.clone();
            self.meta.pq_posture = entry.pq_posture.clone();
            Some(&entry.url)
        } else {
            None
        }
    }

    /// Go forward in history
    pub fn go_forward(&mut self) -> Option<&str> {
        if self.current_index < self.history.len() - 1 {
            self.current_index += 1;
            let entry = &self.history[self.current_index];
            self.meta.url = entry.url.clone();
            self.meta.title = entry.title.clone();
            self.meta.pq_posture = entry.pq_posture.clone();
            Some(&entry.url)
        } else {
            None
        }
    }

    /// Can go back
    pub fn can_go_back(&self) -> bool {
        self.current_index > 0
    }

    /// Can go forward
    pub fn can_go_forward(&self) -> bool {
        self.current_index < self.history.len() - 1
    }

    /// Update current page info
    pub fn update_current_page(&mut self, title: Option<String>, posture: Option<PQPosture>) {
        if let Some(entry) = self.history.get_mut(self.current_index) {
            if let Some(title) = &title {
                entry.title = Some(title.clone());
                self.meta.title = Some(title.clone());
            }
            if let Some(posture) = &posture {
                entry.pq_posture = Some(posture.clone());
                self.meta.pq_posture = Some(posture.clone());
            }
        }
    }
}
