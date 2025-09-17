#!/usr/bin/env node

/**
 * VINaris Security Check Script
 * Performs automated security checks on the application
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Security check configuration
const securityChecks = {
    environment: {
        required: ['JWT_SECRET', 'BCRYPT_ROUNDS', 'NODE_ENV'],
        sensitive: ['JWT_SECRET', 'SESSION_SECRET', 'ENCRYPTION_KEY'],
        minLength: {
            'JWT_SECRET': 32,
            'SESSION_SECRET': 32,
            'ENCRYPTION_KEY': 32
        }
    },
    files: {
        required: [
            '.env',
            'config/security.js',
            'middleware/auth.js',
            'middleware/validation.js',
            'middleware/fileUpload.js'
        ],
        sensitive: [
            '.env',
            'database/vinaris.db'
        ]
    },
    permissions: {
        directories: {
            'uploads': 0o755,
            'database': 0o755,
            'config': 0o755
        },
        files: {
            '.env': 0o600,
            'database/vinaris.db': 0o640
        }
    }
};

// Color codes for console output
const colors = {
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    reset: '\x1b[0m',
    bold: '\x1b[1m'
};

// Logging functions
function logSuccess(message) {
    console.log(`${colors.green}✓${colors.reset} ${message}`);
}

function logError(message) {
    console.log(`${colors.red}✗${colors.reset} ${message}`);
}

function logWarning(message) {
    console.log(`${colors.yellow}⚠${colors.reset} ${message}`);
}

function logInfo(message) {
    console.log(`${colors.blue}ℹ${colors.reset} ${message}`);
}

// Check environment variables
function checkEnvironment() {
    console.log('\n🔍 Checking environment configuration...');
    
    const envPath = path.join(__dirname, '..', '.env');
    if (!fs.existsSync(envPath)) {
        logError('.env file not found');
        return false;
    }
    
    // Load environment variables
    const envContent = fs.readFileSync(envPath, 'utf8');
    const envVars = {};
    envContent.split('\n').forEach(line => {
        const [key, value] = line.split('=');
        if (key && value) {
            envVars[key.trim()] = value.trim();
        }
    });
    
    let allGood = true;
    
    // Check required variables
    securityChecks.environment.required.forEach(varName => {
        if (!envVars[varName]) {
            logError(`Required environment variable ${varName} is missing`);
            allGood = false;
        } else {
            logSuccess(`Environment variable ${varName} is set`);
        }
    });
    
    // Check sensitive variable lengths
    securityChecks.environment.sensitive.forEach(varName => {
        if (envVars[varName]) {
            const minLength = securityChecks.environment.minLength[varName] || 16;
            if (envVars[varName].length < minLength) {
                logError(`Environment variable ${varName} is too short (minimum ${minLength} characters)`);
                allGood = false;
            } else {
                logSuccess(`Environment variable ${varName} has sufficient length`);
            }
        }
    });
    
    // Check for default/weak values
    if (envVars.JWT_SECRET && envVars.JWT_SECRET.includes('change-this')) {
        logWarning('JWT_SECRET contains default value - change before production');
        allGood = false;
    }
    
    if (envVars.NODE_ENV === 'development') {
        logWarning('NODE_ENV is set to development - change to production for deployment');
    }
    
    return allGood;
}

// Check file permissions
function checkPermissions() {
    console.log('\n🔒 Checking file permissions...');
    
    let allGood = true;
    
    // Check directory permissions
    Object.entries(securityChecks.permissions.directories).forEach(([dir, expectedPerm]) => {
        const dirPath = path.join(__dirname, '..', dir);
        if (fs.existsSync(dirPath)) {
            const stats = fs.statSync(dirPath);
            const actualPerm = stats.mode & parseInt('777', 8);
            if (actualPerm === expectedPerm) {
                logSuccess(`Directory ${dir} has correct permissions (${expectedPerm.toString(8)})`);
            } else {
                logError(`Directory ${dir} has incorrect permissions (${actualPerm.toString(8)}, expected ${expectedPerm.toString(8)})`);
                allGood = false;
            }
        }
    });
    
    // Check file permissions
    Object.entries(securityChecks.permissions.files).forEach(([file, expectedPerm]) => {
        const filePath = path.join(__dirname, '..', file);
        if (fs.existsSync(filePath)) {
            const stats = fs.statSync(filePath);
            const actualPerm = stats.mode & parseInt('777', 8);
            if (actualPerm === expectedPerm) {
                logSuccess(`File ${file} has correct permissions (${expectedPerm.toString(8)})`);
            } else {
                logError(`File ${file} has incorrect permissions (${actualPerm.toString(8)}, expected ${expectedPerm.toString(8)})`);
                allGood = false;
            }
        }
    });
    
    return allGood;
}

// Check required files
function checkRequiredFiles() {
    console.log('\n📁 Checking required security files...');
    
    let allGood = true;
    
    securityChecks.files.required.forEach(file => {
        const filePath = path.join(__dirname, '..', file);
        if (fs.existsSync(filePath)) {
            logSuccess(`Required file ${file} exists`);
        } else {
            logError(`Required file ${file} is missing`);
            allGood = false;
        }
    });
    
    return allGood;
}

// Check for security vulnerabilities in dependencies
function checkDependencies() {
    console.log('\n📦 Checking dependencies for vulnerabilities...');
    
    const packageJsonPath = path.join(__dirname, '..', 'package.json');
    if (!fs.existsSync(packageJsonPath)) {
        logError('package.json not found');
        return false;
    }
    
    const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
    const dependencies = { ...packageJson.dependencies, ...packageJson.devDependencies };
    
    // Check for known vulnerable packages
    const vulnerablePackages = [
        'express@4.16.0', // Old version with vulnerabilities
        'lodash@4.17.10', // Old version with vulnerabilities
        'moment@2.19.0' // Old version with vulnerabilities
    ];
    
    let allGood = true;
    
    Object.entries(dependencies).forEach(([name, version]) => {
        const fullName = `${name}@${version}`;
        if (vulnerablePackages.includes(fullName)) {
            logError(`Vulnerable package detected: ${fullName}`);
            allGood = false;
        } else {
            logSuccess(`Package ${fullName} appears safe`);
        }
    });
    
    return allGood;
}

// Check for hardcoded secrets
function checkHardcodedSecrets() {
    console.log('\n🔐 Checking for hardcoded secrets...');
    
    const sensitivePatterns = [
        /password\s*=\s*['"][^'"]{8,}['"]/gi,
        /secret\s*=\s*['"][^'"]{8,}['"]/gi,
        /key\s*=\s*['"][^'"]{8,}['"]/gi,
        /token\s*=\s*['"][^'"]{8,}['"]/gi,
        /api[_-]?key\s*=\s*['"][^'"]{8,}['"]/gi
    ];
    
    const filesToCheck = [
        'server.js',
        'api.php',
        'middleware/auth.js',
        'routes/auth.js',
        'config/security.js'
    ];
    
    let allGood = true;
    
    filesToCheck.forEach(file => {
        const filePath = path.join(__dirname, '..', file);
        if (fs.existsSync(filePath)) {
            const content = fs.readFileSync(filePath, 'utf8');
            sensitivePatterns.forEach(pattern => {
                const matches = content.match(pattern);
                if (matches) {
                matches.forEach(match => {
                    if (!match.includes('process.env') && !match.includes('$_ENV') && 
                        !match.includes('login_attempts_') && !match.includes('hash(')) {
                        logWarning(`Potential hardcoded secret in ${file}: ${match.substring(0, 50)}...`);
                        allGood = false;
                    }
                });
                }
            });
        }
    });
    
    if (allGood) {
        logSuccess('No hardcoded secrets detected');
    }
    
    return allGood;
}

// Check database security
function checkDatabaseSecurity() {
    console.log('\n🗄️ Checking database security...');
    
    const dbPath = path.join(__dirname, '..', 'database', 'vinaris.db');
    let allGood = true;
    
    if (fs.existsSync(dbPath)) {
        logSuccess('Database file exists');
        
        // Check if database is readable
        try {
            const stats = fs.statSync(dbPath);
            if (stats.mode & 0o004) { // Check if world-readable
                logWarning('Database file is world-readable');
                allGood = false;
            } else {
                logSuccess('Database file has appropriate permissions');
            }
        } catch (error) {
            logError(`Error checking database permissions: ${error.message}`);
            allGood = false;
        }
    } else {
        logWarning('Database file not found (may be created on first run)');
    }
    
    return allGood;
}

// Main security check function
async function runSecurityCheck() {
    console.log(`${colors.bold}${colors.blue}VINaris Security Check${colors.reset}`);
    console.log('=====================================');
    
    const checks = [
        { name: 'Environment Configuration', fn: checkEnvironment },
        { name: 'File Permissions', fn: checkPermissions },
        { name: 'Required Files', fn: checkRequiredFiles },
        { name: 'Dependencies', fn: checkDependencies },
        { name: 'Hardcoded Secrets', fn: checkHardcodedSecrets },
        { name: 'Database Security', fn: checkDatabaseSecurity }
    ];
    
    const results = [];
    
    for (const check of checks) {
        try {
            const result = check.fn();
            results.push({ name: check.name, passed: result });
        } catch (error) {
            logError(`Error in ${check.name}: ${error.message}`);
            results.push({ name: check.name, passed: false });
        }
    }
    
    // Summary
    console.log('\n📊 Security Check Summary');
    console.log('========================');
    
    const passed = results.filter(r => r.passed).length;
    const total = results.length;
    
    results.forEach(result => {
        if (result.passed) {
            logSuccess(`${result.name}: PASSED`);
        } else {
            logError(`${result.name}: FAILED`);
        }
    });
    
    console.log(`\nOverall: ${passed}/${total} checks passed`);
    
    if (passed === total) {
        console.log(`${colors.green}${colors.bold}✅ All security checks passed!${colors.reset}`);
        process.exit(0);
    } else {
        console.log(`${colors.red}${colors.bold}❌ Some security checks failed. Please review and fix the issues above.${colors.reset}`);
        process.exit(1);
    }
}

// Run the security check
if (require.main === module) {
    runSecurityCheck().catch(error => {
        console.error('Security check failed:', error);
        process.exit(1);
    });
}

module.exports = { runSecurityCheck };
