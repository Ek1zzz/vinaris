const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

// Create database and run schema
const dbPath = path.join(__dirname, 'database', 'vinaris.db');
const db = new Database(dbPath);

// Read and execute schema
const schemaPath = path.join(__dirname, 'database', 'schema.sql');
const schema = fs.readFileSync(schemaPath, 'utf8');

// Split and execute each statement
const statements = schema.split(';').filter(stmt => stmt.trim());
statements.forEach(statement => {
    if (statement.trim()) {
        db.exec(statement + ';');
    }
});

console.log('Database initialized successfully!');
db.close();
