#!/usr/bin/env python3
"""
GHOSTSHELL Database Setup Script
===============================

This script creates and initializes all the database files needed by GHOSTSHELL:
- Audit logging database (SQLite)
- Vault database (SQLite) 
- Policy enforcement database (SQLite)

Usage: python setup_databases.py
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
    print("🚀 GHOSTSHELL Database Setup")
    print("=" * 50)
    
    # Create data directory if it doesn't exist
    data_dir = Path("data")
    data_dir.mkdir(exist_ok=True)
    
    # Database file paths
    databases = {
        "audit": data_dir / "ghostshell_audit.db",
        "vault": data_dir / "ghostshell_vault.db", 
        "policy": data_dir / "ghostshell_policy.db"
    }
    
    try:
        # Create each database
        create_audit_database(databases["audit"])
        create_vault_database(databases["vault"])
        create_policy_database(databases["policy"])
        
        # Set permissions
        for db_name, db_path in databases.items():
            setup_database_permissions(db_path)
        
        print("\n🎉 Database setup completed successfully!")
        print(f"📁 Database files created in: {data_dir.absolute()}")
        print("\nCreated databases:")
        for db_name, db_path in databases.items():
            size = db_path.stat().st_size if db_path.exists() else 0
            print(f"  • {db_name}: {db_path.name} ({size} bytes)")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Database setup failed: {e}")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
