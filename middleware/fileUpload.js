/**
 * Secure File Upload Middleware for VINaris API
 * Handles file uploads with comprehensive security checks
 */

const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { validateFileUpload, securityConfig } = require('../config/security');

// Configure multer for secure file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadPath = process.env.UPLOAD_PATH || './uploads';
        const quarantinePath = path.join(uploadPath, 'quarantine');
        
        // Create directories if they don't exist
        if (!fs.existsSync(uploadPath)) {
            fs.mkdirSync(uploadPath, { recursive: true, mode: 0o755 });
        }
        if (!fs.existsSync(quarantinePath)) {
            fs.mkdirSync(quarantinePath, { recursive: true, mode: 0o755 });
        }
        
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
        // Generate secure filename
        const timestamp = Date.now();
        const randomString = crypto.randomBytes(16).toString('hex');
        const extension = path.extname(file.originalname);
        const safeName = `${timestamp}_${randomString}${extension}`;
        
        cb(null, safeName);
    }
});

// File filter for security
const fileFilter = (req, file, cb) => {
    // Check file type
    const allowedTypes = securityConfig.upload.allowedTypes;
    if (!allowedTypes.includes(file.mimetype)) {
        return cb(new Error(`File type ${file.mimetype} is not allowed`), false);
    }
    
    // Check file extension
    const allowedExtensions = securityConfig.upload.allowedExtensions;
    const extension = path.extname(file.originalname).toLowerCase();
    if (!allowedExtensions.includes(extension)) {
        return cb(new Error(`File extension ${extension} is not allowed`), false);
    }
    
    cb(null, true);
};

// Configure multer
const upload = multer({
    storage: storage,
    fileFilter: fileFilter,
    limits: {
        fileSize: securityConfig.upload.maxFileSize,
        files: 1, // Only allow one file at a time
        fields: 10, // Maximum number of non-file fields
        fieldNameSize: 100, // Maximum field name size
        fieldSize: 1000000, // Maximum field value size
        parts: 20, // Maximum number of parts (fields + files)
        headerPairs: 2000 // Maximum number of header key-value pairs
    }
});

// Middleware to validate uploaded file
const validateUploadedFile = (req, res, next) => {
    if (!req.file) {
        return res.status(400).json({
            error: 'No file uploaded',
            message: 'File is required'
        });
    }
    
    // Validate file using security config
    const validation = validateFileUpload(req.file);
    if (!validation.isValid) {
        // Delete the uploaded file if validation fails
        if (req.file.path && fs.existsSync(req.file.path)) {
            fs.unlinkSync(req.file.path);
        }
        
        return res.status(400).json({
            error: 'File validation failed',
            message: 'Invalid file',
            details: validation.errors
        });
    }
    
    // Additional security checks
    const filePath = req.file.path;
    const fileStats = fs.statSync(filePath);
    
    // Check if file is empty
    if (fileStats.size === 0) {
        fs.unlinkSync(filePath);
        return res.status(400).json({
            error: 'Invalid file',
            message: 'File is empty'
        });
    }
    
    // Check for suspicious file content (basic check)
    if (req.file.mimetype === 'application/pdf') {
        const fileBuffer = fs.readFileSync(filePath, { start: 0, end: 1023 });
        const fileHeader = fileBuffer.toString('hex', 0, 4);
        
        // Check PDF magic number
        if (fileHeader !== '25504446') {
            fs.unlinkSync(filePath);
            return res.status(400).json({
                error: 'Invalid file',
                message: 'File does not appear to be a valid PDF'
            });
        }
    }
    
    // Add file info to request
    req.fileInfo = {
        originalName: req.file.originalname,
        filename: req.file.filename,
        path: req.file.path,
        size: req.file.size,
        mimetype: req.file.mimetype,
        uploadedAt: new Date().toISOString()
    };
    
    next();
};

// Middleware to scan for malware (basic implementation)
const scanForMalware = async (req, res, next) => {
    if (!req.file) {
        return next();
    }
    
    try {
        const filePath = req.file.path;
        const fileBuffer = fs.readFileSync(filePath, { start: 0, end: 10240 }); // Read first 10KB
        const fileContent = fileBuffer.toString('utf8', 0, Math.min(10240, fileBuffer.length));
        
        // Basic malware patterns (this is a simplified example)
        const malwarePatterns = [
            /eval\s*\(/i,
            /exec\s*\(/i,
            /system\s*\(/i,
            /shell_exec\s*\(/i,
            /passthru\s*\(/i,
            /<script[^>]*>.*?<\/script>/gi,
            /javascript:/gi,
            /vbscript:/gi,
            /onload\s*=/gi,
            /onerror\s*=/gi
        ];
        
        for (const pattern of malwarePatterns) {
            if (pattern.test(fileContent)) {
                // Move file to quarantine
                const quarantinePath = path.join(process.env.UPLOAD_PATH || './uploads', 'quarantine', req.file.filename);
                fs.renameSync(filePath, quarantinePath);
                
                console.warn(`Malware detected in file: ${req.file.originalname}`);
                
                return res.status(400).json({
                    error: 'File rejected',
                    message: 'File contains potentially malicious content'
                });
            }
        }
        
        next();
    } catch (error) {
        console.error('Malware scan error:', error);
        next(); // Continue if scan fails
    }
};

// Cleanup middleware to remove files on error
const cleanupOnError = (req, res, next) => {
    const originalSend = res.send;
    
    res.send = function(data) {
        // If response is an error, clean up uploaded file
        if (res.statusCode >= 400 && req.file && req.file.path) {
            try {
                if (fs.existsSync(req.file.path)) {
                    fs.unlinkSync(req.file.path);
                }
            } catch (error) {
                console.error('Error cleaning up file:', error);
            }
        }
        
        return originalSend.call(this, data);
    };
    
    next();
};

// Middleware to log file uploads
const logFileUpload = (req, res, next) => {
    if (req.file) {
        console.log(`File uploaded: ${req.file.originalname} (${req.file.size} bytes) by user ${req.user?.id || 'anonymous'}`);
    }
    next();
};

module.exports = {
    upload,
    validateUploadedFile,
    scanForMalware,
    cleanupOnError,
    logFileUpload
};
