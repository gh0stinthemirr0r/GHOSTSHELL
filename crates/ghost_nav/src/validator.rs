use crate::{LayoutV2, NavGroup, NavModule};
use anyhow::{anyhow, Result};
use std::collections::{HashMap, HashSet};

/// Validator for navigation layouts
pub struct LayoutValidator {
    max_groups: usize,
    max_modules: usize,
    max_name_length: usize,
}

impl LayoutValidator {
    pub fn new() -> Self {
        Self {
            max_groups: 20,
            max_modules: 50,
            max_name_length: 100,
        }
    }

    pub fn with_limits(max_groups: usize, max_modules: usize, max_name_length: usize) -> Self {
        Self {
            max_groups,
            max_modules,
            max_name_length,
        }
    }

    /// Validate a complete layout
    pub fn validate(&self, layout: &LayoutV2) -> Result<()> {
        self.validate_basic_structure(layout)?;
        self.validate_groups(&layout.groups)?;
        self.validate_modules(&layout.modules)?;
        self.validate_group_module_references(layout)?;
        self.validate_ordering(layout)?;
        Ok(())
    }

    fn validate_basic_structure(&self, layout: &LayoutV2) -> Result<()> {
        if layout.version != 2 {
            return Err(anyhow!("Unsupported layout version: {}", layout.version));
        }

        if layout.workspace.is_empty() {
            return Err(anyhow!("Workspace name cannot be empty"));
        }

        if layout.workspace.len() > self.max_name_length {
            return Err(anyhow!(
                "Workspace name too long: {} > {}",
                layout.workspace.len(),
                self.max_name_length
            ));
        }

        if layout.groups.len() > self.max_groups {
            return Err(anyhow!(
                "Too many groups: {} > {}",
                layout.groups.len(),
                self.max_groups
            ));
        }

        if layout.modules.len() > self.max_modules {
            return Err(anyhow!(
                "Too many modules: {} > {}",
                layout.modules.len(),
                self.max_modules
            ));
        }

        Ok(())
    }

    fn validate_groups(&self, groups: &[NavGroup]) -> Result<()> {
        let mut group_ids = HashSet::new();
        let mut group_orders = HashSet::new();

        for group in groups {
            // Check for duplicate IDs
            if !group_ids.insert(&group.id) {
                return Err(anyhow!("Duplicate group ID: {}", group.id));
            }

            // Check for duplicate orders
            if !group_orders.insert(group.order) {
                return Err(anyhow!("Duplicate group order: {}", group.order));
            }

            // Validate group structure
            self.validate_group(group)?;
        }

        Ok(())
    }

    fn validate_group(&self, group: &NavGroup) -> Result<()> {
        if group.id.is_empty() {
            return Err(anyhow!("Group ID cannot be empty"));
        }

        if group.name.is_empty() {
            return Err(anyhow!("Group name cannot be empty"));
        }

        if group.name.len() > self.max_name_length {
            return Err(anyhow!(
                "Group name too long: {} > {}",
                group.name.len(),
                self.max_name_length
            ));
        }

        // Validate ID format (alphanumeric + hyphens/underscores)
        if !group.id.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
            return Err(anyhow!(
                "Invalid group ID format: {}. Use alphanumeric, hyphens, or underscores only",
                group.id
            ));
        }

        Ok(())
    }

    fn validate_modules(&self, modules: &[NavModule]) -> Result<()> {
        let mut module_ids = HashSet::new();
        let mut module_orders_by_group: HashMap<String, HashSet<u32>> = HashMap::new();

        for module in modules {
            // Check for duplicate IDs
            if !module_ids.insert(&module.id) {
                return Err(anyhow!("Duplicate module ID: {}", module.id));
            }

            // Check for duplicate orders within the same group
            let group_orders = module_orders_by_group
                .entry(module.group_id.clone())
                .or_insert_with(HashSet::new);

            if !group_orders.insert(module.order) {
                return Err(anyhow!(
                    "Duplicate module order {} in group {}",
                    module.order,
                    module.group_id
                ));
            }

            // Validate module structure
            self.validate_module(module)?;
        }

        Ok(())
    }

    fn validate_module(&self, module: &NavModule) -> Result<()> {
        if module.id.is_empty() {
            return Err(anyhow!("Module ID cannot be empty"));
        }

        if module.group_id.is_empty() {
            return Err(anyhow!("Module group_id cannot be empty"));
        }

        // Validate ID format
        if !module.id.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
            return Err(anyhow!(
                "Invalid module ID format: {}. Use alphanumeric, hyphens, or underscores only",
                module.id
            ));
        }

        // Validate lock reason if locked
        if module.locked && module.lock_reason.is_none() {
            return Err(anyhow!(
                "Locked module {} must have a lock_reason",
                module.id
            ));
        }

        // Validate icon variant if present
        if let Some(ref variant) = module.icon_variant {
            if !["neon", "exec", "minimal"].contains(&variant.as_str()) {
                return Err(anyhow!(
                    "Invalid icon variant: {}. Must be one of: neon, exec, minimal",
                    variant
                ));
            }
        }

        Ok(())
    }

    fn validate_group_module_references(&self, layout: &LayoutV2) -> Result<()> {
        let group_ids: HashSet<&String> = layout.groups.iter().map(|g| &g.id).collect();

        for module in &layout.modules {
            if !group_ids.contains(&module.group_id) {
                return Err(anyhow!(
                    "Module {} references non-existent group: {}",
                    module.id,
                    module.group_id
                ));
            }
        }

        Ok(())
    }

    fn validate_ordering(&self, layout: &LayoutV2) -> Result<()> {
        // Check that group orders are sequential starting from 0
        let mut group_orders: Vec<u32> = layout.groups.iter().map(|g| g.order).collect();
        group_orders.sort();

        for (i, &order) in group_orders.iter().enumerate() {
            if order != i as u32 {
                return Err(anyhow!(
                    "Group orders must be sequential starting from 0. Expected {}, found {}",
                    i,
                    order
                ));
            }
        }

        // Check that module orders within each group are sequential starting from 0
        let mut modules_by_group: HashMap<&String, Vec<&NavModule>> = HashMap::new();
        for module in &layout.modules {
            modules_by_group
                .entry(&module.group_id)
                .or_insert_with(Vec::new)
                .push(module);
        }

        for (group_id, modules) in modules_by_group {
            let mut module_orders: Vec<u32> = modules.iter().map(|m| m.order).collect();
            module_orders.sort();

            for (i, &order) in module_orders.iter().enumerate() {
                if order != i as u32 {
                    return Err(anyhow!(
                        "Module orders in group {} must be sequential starting from 0. Expected {}, found {}",
                        group_id,
                        i,
                        order
                    ));
                }
            }
        }

        Ok(())
    }
}

/// Validation result with warnings
#[derive(Debug)]
pub struct ValidationResult {
    pub is_valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl ValidationResult {
    pub fn valid() -> Self {
        Self {
            is_valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    pub fn invalid(errors: Vec<String>) -> Self {
        Self {
            is_valid: false,
            errors,
            warnings: Vec::new(),
        }
    }

    pub fn with_warnings(mut self, warnings: Vec<String>) -> Self {
        self.warnings = warnings;
        self
    }
}

/// Extended validator that can provide warnings
pub struct ExtendedLayoutValidator {
    validator: LayoutValidator,
}

impl ExtendedLayoutValidator {
    pub fn new() -> Self {
        Self {
            validator: LayoutValidator::new(),
        }
    }

    /// Validate with detailed results including warnings
    pub fn validate_detailed(&self, layout: &LayoutV2) -> ValidationResult {
        let mut warnings = Vec::new();

        // Run basic validation
        match self.validator.validate(layout) {
            Ok(()) => {
                // Check for warnings
                self.check_warnings(layout, &mut warnings);
                ValidationResult::valid().with_warnings(warnings)
            }
            Err(e) => ValidationResult::invalid(vec![e.to_string()]),
        }
    }

    fn check_warnings(&self, layout: &LayoutV2, warnings: &mut Vec<String>) {
        // Check for empty groups
        let modules_by_group = layout.get_grouped_modules();
        for group in &layout.groups {
            if !modules_by_group.contains_key(&group.id) {
                warnings.push(format!("Group '{}' has no visible modules", group.name));
            }
        }

        // Check for too many pinned modules
        let pinned_count = layout.modules.iter().filter(|m| m.pinned && m.visible).count();
        if pinned_count > 5 {
            warnings.push(format!(
                "Too many pinned modules ({}). Consider unpinning some for better UX",
                pinned_count
            ));
        }

        // Check for modules without groups
        let group_ids: HashSet<&String> = layout.groups.iter().map(|g| &g.id).collect();
        for module in &layout.modules {
            if !group_ids.contains(&module.group_id) {
                warnings.push(format!(
                    "Module '{}' references non-existent group '{}'",
                    module.id, module.group_id
                ));
            }
        }
    }
}
