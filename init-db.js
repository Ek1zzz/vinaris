const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

console.log('🔄 Initializing database...');

try {
    // Create database file
    const dbPath = path.join(__dirname, 'database', 'vinaris.db');
    const db = new Database(dbPath);

    // Read schema file
    const schemaPath = path.join(__dirname, 'database', 'schema.sql');
    
    if (fs.existsSync(schemaPath)) {
        const schema = fs.readFileSync(schemaPath, 'utf8');
        
        // Execute schema
        db.exec(schema);
        
        console.log('✅ Database tables created successfully!');
        
        // Check if admin user exists, if not create one
        const adminCheck = db.prepare('SELECT COUNT(*) as count FROM users WHERE email = ?').get('admin@vinaris.ge');
        
        if (adminCheck.count === 0) {
            // Create admin user
            const bcrypt = require('bcrypt');
            const adminPassword = await bcrypt.hash('admin123', 12);
            
            db.prepare(`
                INSERT INTO users (unique_id, name, email, password_hash, user_type, credits, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
            `).run('VIN_ADMIN_001', 'Administrator', 'admin@vinaris.ge', adminPassword, 'admin', 1000, 'active');
            
            console.log('✅ Admin user created successfully!');
        }
        
    } else {
        console.log('❌ Schema file not found, creating basic tables...');
        
        // Basic table creation
        db.exec(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                unique_id TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                user_type TEXT DEFAULT 'user',
                credits INTEGER DEFAULT 3,
                status TEXT DEFAULT 'active',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log('✅ Basic tables created!');
    }
    
    db.close();
    console.log('✅ Database initialization complete!');
    
} catch (error) {
    console.error('❌ Database initialization failed:', error);
    process.exit(1);
}
