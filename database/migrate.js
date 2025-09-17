#!/usr/bin/env node

/**
 * VINaris Database Migration Script
 * Usage: node database/migrate.js [up|down|reset|status]
 */

const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const path = require('path');

const DB_PATH = path.join(__dirname, 'vinaris.db');
const MIGRATIONS_DIR = path.join(__dirname, 'migrations');

// Ensure migrations table exists
function ensureMigrationsTable(db) {
    return new Promise((resolve, reject) => {
        db.run(`
            CREATE TABLE IF NOT EXISTS migrations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT UNIQUE NOT NULL,
                applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `, (err) => {
            if (err) reject(err);
            else resolve();
        });
    });
}

// Get applied migrations
function getAppliedMigrations(db) {
    return new Promise((resolve, reject) => {
        db.all('SELECT filename FROM migrations ORDER BY applied_at', (err, rows) => {
            if (err) reject(err);
            else resolve(rows.map(row => row.filename));
        });
    });
}

// Apply migration
function applyMigration(db, filename) {
    return new Promise((resolve, reject) => {
        const filePath = path.join(MIGRATIONS_DIR, filename);
        const sql = fs.readFileSync(filePath, 'utf8');
        
        db.exec(sql, (err) => {
            if (err) {
                reject(err);
                return;
            }
            
            db.run('INSERT INTO migrations (filename) VALUES (?)', [filename], (err) => {
                if (err) reject(err);
                else resolve();
            });
        });
    });
}

// Main migration function
async function migrate(action = 'up') {
    const db = new sqlite3.Database(DB_PATH);
    
    try {
        await ensureMigrationsTable(db);
        
        switch (action) {
            case 'up':
                await migrateUp(db);
                break;
            case 'status':
                await migrationStatus(db);
                break;
            case 'reset':
                await resetDatabase(db);
                break;
            default:
                console.log('Usage: node migrate.js [up|status|reset]');
        }
        
    } catch (error) {
        console.error('Migration error:', error);
    } finally {
        db.close();
    }
}

async function migrateUp(db) {
    const applied = await getAppliedMigrations(db);
    const migrationFiles = fs.readdirSync(MIGRATIONS_DIR)
        .filter(file => file.endsWith('.sql'))
        .sort();
    
    const pending = migrationFiles.filter(file => !applied.includes(file));
    
    if (pending.length === 0) {
        console.log('✅ No pending migrations');
        return;
    }
    
    console.log(`📦 Applying ${pending.length} migration(s)...`);
    
    for (const filename of pending) {
        try {
            await applyMigration(db, filename);
            console.log(`✅ Applied: ${filename}`);
        } catch (error) {
            console.error(`❌ Failed to apply ${filename}:`, error);
            break;
        }
    }
}

async function migrationStatus(db) {
    const applied = await getAppliedMigrations(db);
    const allMigrations = fs.readdirSync(MIGRATIONS_DIR)
        .filter(file => file.endsWith('.sql'))
        .sort();
    
    console.log('\n📊 Migration Status:');
    console.log('==================');
    
    allMigrations.forEach(migration => {
        const status = applied.includes(migration) ? '✅ Applied' : '⏳ Pending';
        console.log(`${status} ${migration}`);
    });
    
    console.log(`\nTotal: ${allMigrations.length}, Applied: ${applied.length}, Pending: ${allMigrations.length - applied.length}`);
}

async function resetDatabase(db) {
    console.log('🔄 Resetting database...');
    
    // Read and execute schema
    const schemaPath = path.join(__dirname, 'schema.sql');
    const schema = fs.readFileSync(schemaPath, 'utf8');
    
    return new Promise((resolve, reject) => {
        db.exec('DROP TABLE IF EXISTS migrations; DROP TABLE IF EXISTS users; DROP TABLE IF EXISTS vin_requests; DROP TABLE IF EXISTS credit_transactions; DROP TABLE IF EXISTS user_activities; DROP TABLE IF EXISTS admin_settings; DROP TABLE IF EXISTS vin_data_cache; DROP TABLE IF EXISTS payments; DROP TABLE IF EXISTS api_usage;', (err) => {
            if (err) {
                reject(err);
                return;
            }
            
            db.exec(schema, (err) => {
                if (err) reject(err);
                else {
                    console.log('✅ Database reset complete');
                    resolve();
                }
            });
        });
    });
}

// Run if called directly
if (require.main === module) {
    const action = process.argv[2] || 'up';
    migrate(action);
}

module.exports = { migrate };
