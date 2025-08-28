use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Credentials for autofill
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutofillCredentials {
    pub username: String,
    pub password: String,
    pub additional_fields: HashMap<String, String>,
}

impl AutofillCredentials {
    /// Create new credentials
    pub fn new(username: String, password: String) -> Self {
        Self {
            username,
            password,
            additional_fields: HashMap::new(),
        }
    }

    /// Add additional field
    pub fn add_field(&mut self, key: String, value: String) {
        self.additional_fields.insert(key, value);
    }

    /// Get field value
    pub fn get_field(&self, key: &str) -> Option<&String> {
        self.additional_fields.get(key)
    }

    /// Clear sensitive data
    pub fn clear(&mut self) {
        self.username.clear();
        self.password.clear();
        self.additional_fields.clear();
    }
}

/// Autofill field type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FieldType {
    Username,
    Password,
    Email,
    Phone,
    CreditCard,
    SecurityCode,
    Custom(String),
}

/// Autofill field mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldMapping {
    pub field_type: FieldType,
    pub selector: String,
    pub value: String,
}

impl FieldMapping {
    /// Create a new field mapping
    pub fn new(field_type: FieldType, selector: String, value: String) -> Self {
        Self {
            field_type,
            selector,
            value,
        }
    }
}
