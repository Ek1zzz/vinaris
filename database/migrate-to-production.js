/**
 * VINaris Database Migration Script for Production
 * Migrates from SQLite to PostgreSQL
 */

const fs = require('fs');
const path = require('path');
const { Client } = require('pg');

// Configuration
const config = {
    development: {
        sqlite: path.join(__dirname, 'vinaris.db')
    },
    production: {
        host: process.env.DB_HOST || 'localhost',
        port: process.env.DB_PORT || 5432,
        database: process.env.DB_NAME || 'vinaris_production',
        user: process.env.DB_USER || 'vinaris_prod_user',
        password: process.env.DB_PASS || '',
        ssl: process.env.DB_SSL === 'true'
    }
};

async function migrateToProduction() {
    console.log('🚀 Starting VINaris Database Migration to Production...');
    
    try {
        // Step 1: Export SQLite data
        console.log('📤 Step 1: Exporting SQLite data...');
        const sqliteData = await exportSQLiteData();
        
        // Step 2: Create PostgreSQL database
        console.log('🗄️ Step 2: Creating PostgreSQL database...');
        await createPostgreSQLDatabase();
        
        // Step 3: Import data to PostgreSQL
        console.log('📥 Step 3: Importing data to PostgreSQL...');
        await importToPostgreSQL(sqliteData);
        
        // Step 4: Verify migration
        console.log('✅ Step 4: Verifying migration...');
        await verifyMigration();
        
        console.log('🎉 Migration completed successfully!');
        
    } catch (error) {
        console.error('❌ Migration failed:', error);
        process.exit(1);
    }
}

async function exportSQLiteData() {
    const sqlite3 = require('sqlite3').verbose();
    const db = new sqlite3.Database(config.development.sqlite);
    
    const tables = [
        'users', 'vin_requests', 'credit_transactions', 
        'user_activities', 'admin_settings', 'vin_data_cache',
        'payments', 'api_usage', 'payment_requests'
    ];
    
    const data = {};
    
    for (const table of tables) {
        data[table] = await new Promise((resolve, reject) => {
            db.all(`SELECT * FROM ${table}`, (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        });
        console.log(`  ✓ Exported ${data[table].length} rows from ${table}`);
    }
    
    db.close();
    return data;
}

async function createPostgreSQLDatabase() {
    const client = new Client(config.production);
    
    try {
        await client.connect();
        
        // Create tables using existing schema
        const schema = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
        
        // Convert SQLite schema to PostgreSQL
        const postgresSchema = schema
            .replace(/INTEGER PRIMARY KEY AUTOINCREMENT/g, 'SERIAL PRIMARY KEY')
            .replace(/AUTOINCREMENT/g, '')
            .replace(/DATETIME DEFAULT CURRENT_TIMESTAMP/g, 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP')
            .replace(/BOOLEAN/g, 'BOOLEAN')
            .replace(/PRAGMA foreign_keys = ON;/g, '');
        
        await client.query(postgresSchema);
        console.log('  ✓ PostgreSQL database schema created');
        
    } catch (error) {
        console.error('Error creating PostgreSQL database:', error);
        throw error;
    } finally {
        await client.end();
    }
}

async function importToPostgreSQL(data) {
    const client = new Client(config.production);
    
    try {
        await client.connect();
        
        for (const [tableName, rows] of Object.entries(data)) {
            if (rows.length === 0) continue;
            
            const columns = Object.keys(rows[0]);
            const placeholders = columns.map((_, i) => `$${i + 1}`).join(', ');
            const query = `INSERT INTO ${tableName} (${columns.join(', ')}) VALUES (${placeholders})`;
            
            for (const row of rows) {
                const values = columns.map(col => row[col]);
                await client.query(query, values);
            }
            
            console.log(`  ✓ Imported ${rows.length} rows to ${tableName}`);
        }
        
    } catch (error) {
        console.error('Error importing to PostgreSQL:', error);
        throw error;
    } finally {
        await client.end();
    }
}

async function verifyMigration() {
    const client = new Client(config.production);
    
    try {
        await client.connect();
        
        const tables = ['users', 'vin_requests', 'credit_transactions'];
        
        for (const table of tables) {
            const result = await client.query(`SELECT COUNT(*) FROM ${table}`);
            console.log(`  ✓ ${table}: ${result.rows[0].count} rows`);
        }
        
    } catch (error) {
        console.error('Error verifying migration:', error);
        throw error;
    } finally {
        await client.end();
    }
}

// Run migration if called directly
if (require.main === module) {
    migrateToProduction();
}

module.exports = { migrateToProduction };
