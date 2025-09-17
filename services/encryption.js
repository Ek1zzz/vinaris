/**
 * Advanced Encryption Service for VINaris
 * Provides comprehensive data encryption for sensitive information
 */

const crypto = require('crypto');
const bcrypt = require('bcryptjs');

class EncryptionService {
    constructor() {
        this.algorithm = 'aes-256-gcm';
        this.keyLength = 32; // 256 bits
        this.ivLength = 16; // 128 bits
        this.tagLength = 16; // 128 bits
        this.saltLength = 32; // 256 bits
    }

    // Generate encryption key from environment variable
    getEncryptionKey() {
        const key = process.env.ENCRYPTION_KEY;
        if (!key || key.length < 32) {
            throw new Error('ENCRYPTION_KEY must be at least 32 characters long');
        }
        return crypto.scryptSync(key, 'vinaris-salt', this.keyLength);
    }

    // Encrypt sensitive data
    encrypt(text) {
        if (!text) return null;
        
        try {
            const key = this.getEncryptionKey();
            const iv = crypto.randomBytes(this.ivLength);
            const cipher = crypto.createCipher(this.algorithm, key);
            cipher.setAAD(Buffer.from('vinaris-data', 'utf8'));
            
            let encrypted = cipher.update(text, 'utf8', 'hex');
            encrypted += cipher.final('hex');
            
            const tag = cipher.getAuthTag();
            
            return {
                encrypted,
                iv: iv.toString('hex'),
                tag: tag.toString('hex')
            };
        } catch (error) {
            console.error('Encryption error:', error);
            throw new Error('Failed to encrypt data');
        }
    }

    // Decrypt sensitive data
    decrypt(encryptedData) {
        if (!encryptedData || !encryptedData.encrypted) return null;
        
        try {
            const key = this.getEncryptionKey();
            const iv = Buffer.from(encryptedData.iv, 'hex');
            const tag = Buffer.from(encryptedData.tag, 'hex');
            
            const decipher = crypto.createDecipher(this.algorithm, key);
            decipher.setAAD(Buffer.from('vinaris-data', 'utf8'));
            decipher.setAuthTag(tag);
            
            let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            
            return decrypted;
        } catch (error) {
            console.error('Decryption error:', error);
            throw new Error('Failed to decrypt data');
        }
    }

    // Hash sensitive data (one-way)
    hash(data) {
        if (!data) return null;
        return crypto.createHash('sha256').update(data).digest('hex');
    }

    // Generate secure random string
    generateSecureRandom(length = 32) {
        return crypto.randomBytes(length).toString('hex');
    }

    // Encrypt user data
    encryptUserData(userData) {
        const sensitiveFields = ['email', 'phone', 'address', 'notes'];
        const encrypted = { ...userData };
        
        sensitiveFields.forEach(field => {
            if (userData[field]) {
                encrypted[field] = this.encrypt(userData[field]);
            }
        });
        
        return encrypted;
    }

    // Decrypt user data
    decryptUserData(encryptedUserData) {
        const sensitiveFields = ['email', 'phone', 'address', 'notes'];
        const decrypted = { ...encryptedUserData };
        
        sensitiveFields.forEach(field => {
            if (encryptedUserData[field] && typeof encryptedUserData[field] === 'object') {
                decrypted[field] = this.decrypt(encryptedUserData[field]);
            }
        });
        
        return decrypted;
    }
}

module.exports = new EncryptionService();
