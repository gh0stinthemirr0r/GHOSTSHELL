#!/usr/bin/env python3
"""
GHOSTSHELL Complete Database Setup Script
=========================================

This script creates and initializes ALL database files needed by GHOSTSHELL:
- Audit logging database (SQLite) - For tamper-evident logging
- Vault database (SQLite) - For secure secret storage
- Policy enforcement database (SQLite) - For policy tracking
- Settings database (SQLite) - For user preferences and configuration
- Quarantine database (SQLite) - For file quarantine management
- Clipboard database (SQLite) - For persistent clipboard history
- Theme database (SQLite) - For theme management and customization

Usage: python setup_complete_databases.py
"""

import sqlite3
import os
import sys
from pathlib import Path

def create_audit_database(db_path):
    """Create the audit logging database with all required tables"""
    print(f"Creating audit database: {db_path}")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create log entries table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS log_entries (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            sequence_number INTEGER NOT NULL UNIQUE,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            actor_id TEXT NOT NULL,
            actor_type TEXT NOT NULL,
            actor_session_id TEXT,
            actor_ip TEXT,
            resource_type TEXT NOT NULL,
            resource_id TEXT,
            resource_name TEXT,
            resource_path TEXT,
            action TEXT NOT NULL,
            outcome TEXT NOT NULL,
            message TEXT NOT NULL,
            details TEXT,
            previous_hash TEXT,
            entry_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create log batches table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS log_batches (
            id TEXT PRIMARY KEY,
            chain_id TEXT NOT NULL,
            batch_number INTEGER NOT NULL,
            start_sequence INTEGER NOT NULL,
            end_sequence INTEGER NOT NULL,
            entry_count INTEGER NOT NULL,
            batch_hash TEXT NOT NULL,
            signature TEXT,
            previous_batch_hash TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create chain metadata table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS chain_metadata (
            chain_id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            last_sequence INTEGER NOT NULL DEFAULT 0,
            verification_key TEXT NOT NULL,
            algorithm TEXT NOT NULL DEFAULT 'dilithium',
            status TEXT NOT NULL DEFAULT 'active'
        )
    ''')
    
    # Create checkpoints table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS checkpoints (
            id TEXT PRIMARY KEY,
            chain_id TEXT NOT NULL,
            sequence_number INTEGER NOT NULL,
            checkpoint_hash TEXT NOT NULL,
            signature TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (chain_id) REFERENCES chain_metadata (chain_id)
        )
    ''')
    
    # Create indexes for performance
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_log_entries_timestamp ON log_entries(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_log_entries_sequence ON log_entries(sequence_number)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_log_entries_actor ON log_entries(actor_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_log_batches_chain ON log_batches(chain_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_checkpoints_chain ON checkpoints(chain_id)')
    
    conn.commit()
    conn.close()
    print(f"✅ Audit database created successfully")

def create_vault_database(db_path):
    """Create the vault database with all required tables"""
    print(f"Creating vault database: {db_path}")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create secrets table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS secrets (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            secret_type TEXT NOT NULL,
            encrypted_data BLOB NOT NULL,
            metadata TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at TEXT,
            access_count INTEGER DEFAULT 0,
            last_accessed TEXT
        )
    ''')
    
    # Create vault metadata table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vault_metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create MFA sessions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS mfa_sessions (
            session_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            challenge_type TEXT NOT NULL,
            challenge_data TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at TEXT NOT NULL,
            verified BOOLEAN DEFAULT FALSE
        )
    ''')
    
    # Create access logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS access_logs (
            id TEXT PRIMARY KEY,
            secret_id TEXT NOT NULL,
            user_id TEXT,
            action TEXT NOT NULL,
            timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            user_agent TEXT,
            success BOOLEAN NOT NULL,
            FOREIGN KEY (secret_id) REFERENCES secrets (id)
        )
    ''')
    
    # Create indexes
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_secrets_name ON secrets(name)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_secrets_type ON secrets(secret_type)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_secrets_expires ON secrets(expires_at)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_access_logs_secret ON access_logs(secret_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_access_logs_timestamp ON access_logs(timestamp)')
    
    conn.commit()
    conn.close()
    print(f"✅ Vault database created successfully")

def create_policy_database(db_path):
    """Create the policy enforcement database"""
    print(f"Creating policy database: {db_path}")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create policies table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS policies (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            version TEXT NOT NULL,
            policy_data TEXT NOT NULL,
            active BOOLEAN DEFAULT TRUE,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create policy evaluations table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS policy_evaluations (
            id TEXT PRIMARY KEY,
            policy_id TEXT NOT NULL,
            resource TEXT NOT NULL,
            action TEXT NOT NULL,
            context TEXT,
            decision TEXT NOT NULL,
            reason TEXT,
            timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (policy_id) REFERENCES policies (id)
        )
    ''')
    
    # Create enforcement logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS enforcement_logs (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            resource TEXT NOT NULL,
            action TEXT NOT NULL,
            decision TEXT NOT NULL,
            policy_version TEXT,
            timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            details TEXT
        )
    ''')
    
    # Create indexes
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_policies_active ON policies(active)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_evaluations_timestamp ON policy_evaluations(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_enforcement_timestamp ON enforcement_logs(timestamp)')
    
    conn.commit()
    conn.close()
    print(f"✅ Policy database created successfully")

def create_settings_database(db_path):
    """Create the settings/configuration database"""
    print(f"Creating settings database: {db_path}")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create user settings table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_settings (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            category TEXT NOT NULL,
            key TEXT NOT NULL,
            value TEXT NOT NULL,
            value_type TEXT NOT NULL DEFAULT 'string',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, category, key)
        )
    ''')
    
    # Create application settings table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            value_type TEXT NOT NULL DEFAULT 'string',
            description TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create settings history table (for tracking changes)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings_history (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            setting_key TEXT NOT NULL,
            old_value TEXT,
            new_value TEXT NOT NULL,
            changed_by TEXT,
            timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Insert default settings
    default_settings = [
        ('theme', 'cyberpunk-neon', 'string', 'Default application theme'),
        ('font_family', 'JetBrainsMono Nerd Font', 'string', 'Default monospace font'),
        ('font_size', '14', 'number', 'Default font size'),
        ('reduce_motion', 'false', 'boolean', 'Reduce animations for accessibility'),
        ('high_contrast', 'false', 'boolean', 'High contrast mode'),
        ('transparency', '0.7', 'number', 'Window transparency level'),
        ('cursor_style', 'block', 'string', 'Terminal cursor style'),
        ('cursor_blink', 'true', 'boolean', 'Terminal cursor blinking'),
        ('font_ligatures', 'true', 'boolean', 'Enable font ligatures'),
    ]
    
    cursor.executemany('''
        INSERT OR IGNORE INTO app_settings (key, value, value_type, description)
        VALUES (?, ?, ?, ?)
    ''', default_settings)
    
    # Create indexes
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_settings_user ON user_settings(user_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_settings_category ON user_settings(category)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_settings_history_timestamp ON settings_history(timestamp)')
    
    conn.commit()
    conn.close()
    print(f"✅ Settings database created successfully")

def create_quarantine_database(db_path):
    """Create the quarantine management database"""
    print(f"Creating quarantine database: {db_path}")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create quarantined files table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS quarantined_files (
            id TEXT PRIMARY KEY,
            original_name TEXT NOT NULL,
            original_path TEXT NOT NULL,
            quarantine_path TEXT NOT NULL,
            file_hash TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            mime_type TEXT,
            quarantined_at INTEGER NOT NULL,
            source_url TEXT,
            source_window TEXT,
            risk_level TEXT NOT NULL,
            policy_rule_id TEXT,
            auto_release_at INTEGER,
            user_approved BOOLEAN DEFAULT FALSE,
            admin_approved BOOLEAN DEFAULT FALSE,
            status TEXT NOT NULL DEFAULT 'quarantined'
        )
    ''')
    
    # Create scan results table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_results (
            id TEXT PRIMARY KEY,
            file_id TEXT NOT NULL,
            scanner TEXT NOT NULL,
            result_type TEXT NOT NULL,
            details TEXT,
            scanned_at INTEGER NOT NULL,
            FOREIGN KEY (file_id) REFERENCES quarantined_files (id)
        )
    ''')
    
    # Create quarantine actions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS quarantine_actions (
            id TEXT PRIMARY KEY,
            file_id TEXT NOT NULL,
            action TEXT NOT NULL,
            performed_by TEXT,
            timestamp INTEGER NOT NULL,
            reason TEXT,
            FOREIGN KEY (file_id) REFERENCES quarantined_files (id)
        )
    ''')
    
    # Create quarantine rules table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS quarantine_rules (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            rule_type TEXT NOT NULL,
            pattern TEXT,
            risk_level TEXT NOT NULL,
            action TEXT NOT NULL,
            active BOOLEAN DEFAULT TRUE,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Insert default quarantine rules
    default_rules = [
        ('exe-files', 'exe-files', 'extension', '.exe', 'high', 'quarantine', True),
        ('script-files', 'script-files', 'extension', '.bat,.cmd,.ps1,.sh', 'medium', 'scan', True),
        ('archive-files', 'archive-files', 'extension', '.zip,.rar,.7z', 'medium', 'scan', True),
        ('suspicious-urls', 'suspicious-urls', 'url_pattern', '.*\\.tk$|.*\\.ml$', 'high', 'quarantine', True),
    ]
    
    cursor.executemany('''
        INSERT OR IGNORE INTO quarantine_rules (id, name, rule_type, pattern, risk_level, action, active)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', default_rules)
    
    # Create indexes
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_quarantined_files_hash ON quarantined_files(file_hash)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_quarantined_files_timestamp ON quarantined_files(quarantined_at)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_quarantined_files_risk ON quarantined_files(risk_level)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_results_file ON scan_results(file_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_quarantine_actions_file ON quarantine_actions(file_id)')
    
    conn.commit()
    conn.close()
    print(f"✅ Quarantine database created successfully")

def create_clipboard_database(db_path):
    """Create the clipboard history database"""
    print(f"Creating clipboard database: {db_path}")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create clipboard entries table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS clipboard_entries (
            id TEXT PRIMARY KEY,
            content TEXT NOT NULL,
            masked_preview TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT,
            source_window TEXT,
            content_type TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            policy_rule_id TEXT,
            encrypted BOOLEAN DEFAULT FALSE,
            access_count INTEGER DEFAULT 0,
            last_accessed TEXT
        )
    ''')
    
    # Create clipboard redaction patterns table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS redaction_patterns (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            pattern TEXT NOT NULL,
            replacement TEXT NOT NULL,
            content_type TEXT NOT NULL,
            active BOOLEAN DEFAULT TRUE,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create clipboard access logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS clipboard_access_logs (
            id TEXT PRIMARY KEY,
            entry_id TEXT NOT NULL,
            action TEXT NOT NULL,
            timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            source_window TEXT,
            user_id TEXT,
            FOREIGN KEY (entry_id) REFERENCES clipboard_entries (id)
        )
    ''')
    
    # Insert default redaction patterns
    default_patterns = [
        ('credit-cards', 'Credit Cards', r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', '[CREDIT CARD]', 'CreditCard', True),
        ('ssn', 'Social Security Numbers', r'\b\d{3}-\d{2}-\d{4}\b', '[SSN]', 'Text', True),
        ('phone', 'Phone Numbers', r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', '[PHONE]', 'Text', True),
        ('email', 'Email Addresses', r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL]', 'Email', True),
        ('api-keys', 'API Keys', r'\b[A-Za-z0-9]{32,}\b', '[API KEY]', 'ApiToken', True),
    ]
    
    cursor.executemany('''
        INSERT OR IGNORE INTO redaction_patterns (id, name, pattern, replacement, content_type, active)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', default_patterns)
    
    # Create indexes
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_clipboard_entries_timestamp ON clipboard_entries(created_at)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_clipboard_entries_type ON clipboard_entries(content_type)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_clipboard_entries_expires ON clipboard_entries(expires_at)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_clipboard_access_logs_entry ON clipboard_access_logs(entry_id)')
    
    conn.commit()
    conn.close()
    print(f"✅ Clipboard database created successfully")

def create_theme_database(db_path):
    """Create the theme management database"""
    print(f"Creating theme database: {db_path}")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create themes table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS themes (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            version TEXT NOT NULL DEFAULT '1.0',
            theme_data TEXT NOT NULL,
            is_default BOOLEAN DEFAULT FALSE,
            is_custom BOOLEAN DEFAULT FALSE,
            created_by TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create theme usage history table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS theme_usage (
            id TEXT PRIMARY KEY,
            theme_id TEXT NOT NULL,
            user_id TEXT,
            applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            duration_seconds INTEGER,
            FOREIGN KEY (theme_id) REFERENCES themes (id)
        )
    ''')
    
    # Create user theme preferences table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_theme_preferences (
            user_id TEXT PRIMARY KEY,
            current_theme_id TEXT NOT NULL,
            auto_switch BOOLEAN DEFAULT FALSE,
            dark_theme_id TEXT,
            light_theme_id TEXT,
            switch_time_dark TEXT,
            switch_time_light TEXT,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (current_theme_id) REFERENCES themes (id),
            FOREIGN KEY (dark_theme_id) REFERENCES themes (id),
            FOREIGN KEY (light_theme_id) REFERENCES themes (id)
        )
    ''')
    
    # Create theme components table (for modular themes)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS theme_components (
            id TEXT PRIMARY KEY,
            theme_id TEXT NOT NULL,
            component_type TEXT NOT NULL,
            component_data TEXT NOT NULL,
            FOREIGN KEY (theme_id) REFERENCES themes (id)
        )
    ''')
    
    # Create indexes
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_themes_name ON themes(name)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_themes_default ON themes(is_default)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_theme_usage_theme ON theme_usage(theme_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_theme_usage_timestamp ON theme_usage(applied_at)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_theme_components_theme ON theme_components(theme_id)')
    
    conn.commit()
    conn.close()
    print(f"✅ Theme database created successfully")

def setup_database_permissions(db_path):
    """Set appropriate permissions on database file"""
    try:
        # On Windows, we'll just ensure the file is readable/writable
        os.chmod(db_path, 0o666)
        print(f"✅ Set permissions for {db_path}")
    except Exception as e:
        print(f"⚠️  Warning: Could not set permissions for {db_path}: {e}")

def main():
    """Main setup function"""
    print("🚀 GHOSTSHELL Complete Database Setup")
    print("=" * 60)
    
    # Create data directory if it doesn't exist
    data_dir = Path("data")
    data_dir.mkdir(exist_ok=True)
    
    # Database file paths
    databases = {
        "audit": data_dir / "ghostshell_audit.db",
        "vault": data_dir / "ghostshell_vault.db", 
        "policy": data_dir / "ghostshell_policy.db",
        "settings": data_dir / "ghostshell_settings.db",
        "quarantine": data_dir / "ghostshell_quarantine.db",
        "clipboard": data_dir / "ghostshell_clipboard.db",
        "theme": data_dir / "ghostshell_theme.db"
    }
    
    try:
        # Create each database
        create_audit_database(databases["audit"])
        create_vault_database(databases["vault"])
        create_policy_database(databases["policy"])
        create_settings_database(databases["settings"])
        create_quarantine_database(databases["quarantine"])
        create_clipboard_database(databases["clipboard"])
        create_theme_database(databases["theme"])
        
        # Set permissions
        for db_name, db_path in databases.items():
            setup_database_permissions(db_path)
        
        print(f"\n🎉 Complete database setup finished successfully!")
        print(f"📁 Database files created in: {data_dir.absolute()}")
        print(f"\nCreated {len(databases)} databases:")
        for db_name, db_path in databases.items():
            size = db_path.stat().st_size if db_path.exists() else 0
            print(f"  • {db_name}: {db_path.name} ({size:,} bytes)")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Database setup failed: {e}")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
