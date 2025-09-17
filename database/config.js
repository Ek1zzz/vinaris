/**
 * VINaris Database Configuration
 * Supports both SQLite (development) and PostgreSQL (production)
 */

const path = require('path');

const config = {
    development: {
        type: 'sqlite',
        database: path.join(__dirname, 'vinaris.db'),
        logging: true,
        backup: {
            enabled: true,
            schedule: '0 2 * * *', // Daily at 2 AM
            retention: 30 // Keep 30 days of backups
        }
    },
    
    production: {
        type: 'postgresql',
        host: process.env.DB_HOST || 'localhost',
        port: process.env.DB_PORT || 5432,
        database: process.env.DB_NAME || 'vinaris_prod',
        username: process.env.DB_USER || 'vinaris_user',
        password: process.env.DB_PASS || '',
        ssl: process.env.DB_SSL === 'true',
        logging: false,
        backup: {
            enabled: true,
            schedule: '0 1 * * *', // Daily at 1 AM
            retention: 90 // Keep 90 days of backups
        }
    },
    
    test: {
        type: 'sqlite',
        database: ':memory:', // In-memory database for tests
        logging: false
    }
};

// Database connection settings
const dbConfig = {
    // Pool settings for production PostgreSQL
    pool: {
        min: 2,
        max: 10,
        idle: 30000,
        acquire: 60000
    },
    
    // Migration settings
    migrations: {
        directory: path.join(__dirname, 'migrations'),
        tableName: 'migrations'
    },
    
    // Seed settings
    seeds: {
        directory: path.join(__dirname, 'seeds')
    }
};

// Get current environment config
function getConfig() {
    const env = process.env.NODE_ENV || 'development';
    return {
        ...config[env],
        ...dbConfig
    };
}

// Database URLs for easy connection
function getDatabaseUrl(env = null) {
    const currentEnv = env || process.env.NODE_ENV || 'development';
    const cfg = config[currentEnv];
    
    if (cfg.type === 'sqlite') {
        return `sqlite:${cfg.database}`;
    }
    
    if (cfg.type === 'postgresql') {
        return `postgresql://${cfg.username}:${cfg.password}@${cfg.host}:${cfg.port}/${cfg.database}`;
    }
    
    throw new Error(`Unsupported database type: ${cfg.type}`);
}

// Environment-specific configurations
const environments = {
    development: {
        name: 'Development',
        debug: true,
        seedData: true,
        autoMigrate: true
    },
    
    production: {
        name: 'Production',
        debug: false,
        seedData: false,
        autoMigrate: false,
        backup: {
            s3Bucket: process.env.BACKUP_S3_BUCKET,
            retention: '90 days'
        }
    },
    
    test: {
        name: 'Test',
        debug: false,
        seedData: false,
        autoMigrate: true,
        cleanup: true
    }
};

module.exports = {
    config,
    dbConfig,
    getConfig,
    getDatabaseUrl,
    environments,
    
    // Helper functions
    isProduction: () => process.env.NODE_ENV === 'production',
    isDevelopment: () => process.env.NODE_ENV !== 'production',
    
    // Constants
    TABLES: {
        USERS: 'users',
        VIN_REQUESTS: 'vin_requests',
        CREDIT_TRANSACTIONS: 'credit_transactions',
        USER_ACTIVITIES: 'user_activities',
        ADMIN_SETTINGS: 'admin_settings',
        VIN_DATA_CACHE: 'vin_data_cache',
        PAYMENTS: 'payments',
        API_USAGE: 'api_usage'
    },
    
    // Default values
    DEFAULTS: {
        USER_CREDITS: 3,
        SESSION_TIMEOUT: 60, // minutes
        RATE_LIMIT: 100, // requests per minute
        CACHE_EXPIRY: 24 // hours
    }
};
