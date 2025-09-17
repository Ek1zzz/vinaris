# VINaris Database Setup

## 🗄️ Database Architecture

Your VINaris project now has a complete database setup with the following components:

### 📁 File Structure
```
database/
├── vinaris.db              # SQLite database file
├── schema.sql              # Database schema definition
├── config.js               # Database configuration
├── db-helper.js            # Database utility class
├── migrate.js              # Migration system
├── backup.sh               # Backup script
├── backups/                # Backup storage directory
├── migrations/             # Schema migration files
│   └── 001_initial_data.sql
└── seeds/                  # Test data files
    └── test_data.sql
```

### 🏗️ Database Tables

#### 1. **users** - User accounts and profiles
- Stores user information, credentials, credits, and statistics
- Supports both regular users and admins
- Tracks login activity and preferences

#### 2. **vin_requests** - VIN check requests
- Manages all VIN checking requests
- Tracks status (pending → processing → processed)
- Links to users and stores metadata

#### 3. **credit_transactions** - Credit purchase/usage history
- Complete audit trail of all credit operations
- Supports multiple payment methods
- Tracks balance changes

#### 4. **user_activities** - Activity audit log
- Logs all user actions for security and analytics
- Stores IP addresses and user agents
- Supports metadata storage

#### 5. **admin_settings** - System configuration
- Stores system-wide settings
- Configurable by admins
- Version controlled changes

#### 6. **vin_data_cache** - API response caching
- Caches expensive API calls
- Reduces costs and improves performance
- Automatic expiration

#### 7. **payments** - Payment records
- Tracks payment processing
- Links to credit transactions
- Supports multiple payment providers

#### 8. **api_usage** - API call tracking
- Monitors external API usage
- Tracks costs and performance
- Helps optimize API usage

## 🚀 Quick Start

### 1. Test Database Connection
```bash
# From project root
sqlite3 database/vinaris.db "SELECT COUNT(*) as total_users FROM users;"
```

### 2. View Sample Data
```bash
# Check users
sqlite3 database/vinaris.db "SELECT id, name, email, credits FROM users;"

# Check VIN requests
sqlite3 database/vinaris.db "SELECT request_id, vin, status FROM vin_requests;"
```

### 3. Backup Database
```bash
cd database
./backup.sh
```

## 🔧 Management Commands

### Database Operations
```bash
# Connect to database
sqlite3 database/vinaris.db

# View all tables
.tables

# Describe table structure
.schema users

# Export data
.dump > backup.sql

# Import data
.read backup.sql
```

### Using the Helper Scripts
```bash
# Test database operations
node database/db-helper.js test

# List all users
node database/db-helper.js users

# List all requests
node database/db-helper.js requests
```

## 📊 Sample Queries

### User Management
```sql
-- Get user statistics
SELECT 
    name, 
    email, 
    credits, 
    total_vin_checked, 
    DATE(created_at) as joined_date
FROM users 
WHERE user_type = 'user'
ORDER BY created_at DESC;

-- Find users with low credits
SELECT name, email, credits 
FROM users 
WHERE credits < 3 AND user_type = 'user';
```

### VIN Request Analysis
```sql
-- Request status breakdown
SELECT 
    status, 
    COUNT(*) as count,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM vin_requests), 2) as percentage
FROM vin_requests 
GROUP BY status;

-- Average processing time
SELECT 
    AVG((julianday(processed_at) - julianday(created_at)) * 24 * 60) as avg_minutes
FROM vin_requests 
WHERE status = 'processed' AND processed_at IS NOT NULL;
```

### Credit Analytics
```sql
-- Total credits flow
SELECT 
    SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END) as credits_added,
    SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END) as credits_spent,
    COUNT(*) as total_transactions
FROM credit_transactions;

-- Daily credit usage
SELECT 
    DATE(created_at) as date,
    SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END) as credits_used
FROM credit_transactions
WHERE DATE(created_at) >= DATE('now', '-30 days')
GROUP BY DATE(created_at)
ORDER BY date DESC;
```

## 🔄 Migration to PostgreSQL

When ready for production, migrate to PostgreSQL:

### 1. Install PostgreSQL
```bash
# Install PostgreSQL
brew install postgresql
brew services start postgresql

# Create database
createdb vinaris_prod
```

### 2. Convert Schema
The schema is already compatible with PostgreSQL. Just update:
- `INTEGER PRIMARY KEY AUTOINCREMENT` → `SERIAL PRIMARY KEY`
- `DATETIME` → `TIMESTAMP`
- `BOOLEAN` → `BOOLEAN`

### 3. Update Configuration
```javascript
// Set environment variables
process.env.NODE_ENV = 'production';
process.env.DB_HOST = 'localhost';
process.env.DB_NAME = 'vinaris_prod';
process.env.DB_USER = 'vinaris_user';
process.env.DB_PASS = 'secure_password';
```

## 🔒 Security Considerations

### Current Status (Development)
- ✅ Database structure ready
- ❌ Passwords stored in plain text
- ❌ No connection encryption
- ❌ No access controls

### Production Requirements
- 🔧 **Password Hashing**: Use bcrypt for password security
- 🔧 **Connection Encryption**: SSL/TLS for database connections
- 🔧 **Access Controls**: Database user permissions
- 🔧 **Data Encryption**: Encrypt sensitive fields
- 🔧 **Audit Logging**: Enhanced activity tracking

## 📈 Performance Optimization

### Indexes Created
- User email and unique_id lookup
- VIN request filtering and sorting
- Credit transaction history
- Activity log queries

### Caching Strategy
- VIN data cached for 24 hours
- API responses stored for reuse
- User session caching

### Backup Strategy
- Automated daily backups
- Compressed storage
- 30-day retention (development)
- 90-day retention (production)

## 🧪 Testing

### Test Database
```bash
# Create test database
NODE_ENV=test node database/migrate.js reset

# Run with test data
NODE_ENV=test node database/db-helper.js test
```

### Sample Test Accounts
- **Admin**: admin@vinaris.ge / admin123
- **Test User**: test@example.com / password123
- **Dealer**: dealer@example.com / dealer123
- **Customer**: jane@example.com / customer123

## 🔗 Integration with Frontend

Your existing frontend localStorage system can gradually migrate to the database:

1. **Phase 1**: Keep localStorage, add database sync
2. **Phase 2**: Move read operations to database
3. **Phase 3**: Move write operations to database
4. **Phase 4**: Remove localStorage dependency

## 📞 Support & Maintenance

### Regular Maintenance Tasks
```bash
# Daily backup
cd database && ./backup.sh

# Check database integrity
sqlite3 vinaris.db "PRAGMA integrity_check;"

# Vacuum database (optimize)
sqlite3 vinaris.db "VACUUM;"

# Analyze query performance
sqlite3 vinaris.db "ANALYZE;"
```

### Monitoring Queries
```sql
-- Database size
SELECT page_count * page_size as size FROM pragma_page_count(), pragma_page_size();

-- Table sizes
SELECT name, COUNT(*) as rows FROM sqlite_master m, pragma_table_info(m.name) WHERE m.type='table' GROUP BY name;

-- Recent activity
SELECT * FROM user_activities ORDER BY created_at DESC LIMIT 20;
```

---

## ✅ Database Setup Complete!

Your database is now ready for development. Next steps:
1. **Create a backend API** (Node.js + Express recommended)
2. **Integrate real VIN checking APIs**
3. **Add payment processing**
4. **Deploy to production**

The database structure supports all your current features and is designed to scale as your business grows.
