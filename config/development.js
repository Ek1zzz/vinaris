/**
 * Development Configuration for VINaris
 * This file contains development-specific settings
 */

module.exports = {
    // Application Environment
    NODE_ENV: 'development',
    PORT: 3001,
    HOST: 'localhost',

    // Database Configuration
    DB_TYPE: 'sqlite',
    DB_HOST: 'localhost',
    DB_PORT: 5432,
    DB_NAME: 'vinaris_prod',
    DB_USER: 'vinaris_user',
    DB_PASS: 'your_secure_password_here',
    DB_SSL: false,

    // JWT Security
    JWT_SECRET: 'your_super_secure_jwt_secret_key_here_minimum_32_characters_development_key_12345',
    JWT_EXPIRES_IN: '24h',
    JWT_REFRESH_EXPIRES_IN: '7d',

    // Password Security (relaxed for development)
    BCRYPT_ROUNDS: 12,
    PASSWORD_MIN_LENGTH: 8,
    PASSWORD_REQUIRE_SPECIAL: false,
    PASSWORD_REQUIRE_UPPERCASE: false,
    PASSWORD_REQUIRE_LOWERCASE: false,
    PASSWORD_REQUIRE_NUMBERS: false,

    // Rate Limiting (relaxed for development)
    RATE_LIMIT_WINDOW_MS: 900000,
    RATE_LIMIT_MAX_REQUESTS: 1000,
    RATE_LIMIT_AUTH_MAX: 50,
    RATE_LIMIT_API_MAX: 100,

    // File Upload Security
    MAX_FILE_SIZE: 10485760,
    ALLOWED_FILE_TYPES: 'application/pdf',
    UPLOAD_QUARANTINE_PATH: './uploads/quarantine/',
    ENABLE_MALWARE_SCAN: false,

    // CORS Configuration
    ENABLE_CORS: true,
    ALLOWED_ORIGINS: 'http://localhost:3000,http://localhost:3001,http://localhost:8080,http://localhost',

    // Security Features (disabled for initial testing)
    ENABLE_2FA: false,
    ENABLE_ACCOUNT_LOCKOUT: false,
    ENABLE_IP_WHITELIST: false,
    ENABLE_DEVICE_FINGERPRINTING: false,

    // Encryption
    ENCRYPTION_KEY: 'your_32_character_encryption_key_here_12345678901234567890123456789012',
    DATA_ENCRYPTION_ENABLED: false,

    // Monitoring & Logging
    LOG_LEVEL: 'info',
    LOG_RETENTION_DAYS: 30,
    ENABLE_SECURITY_LOGGING: false,
    ENABLE_AUDIT_LOGGING: false,

    // Debug Mode
    DEBUG_MODE: true
};
