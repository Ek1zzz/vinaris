/**
 * VINaris Email Service
 * Handles all email notifications for the system
 */

const nodemailer = require('nodemailer');
const fs = require('fs').promises;
const path = require('path');

class EmailService {
    constructor() {
        this.transporter = null;
        this.templates = {};
        this.initializeTransporter();
        this.loadTemplates();
    }

    async initializeTransporter() {
        try {
            this.transporter = nodemailer.createTransporter({
                host: process.env.SMTP_HOST || 'smtp.gmail.com',
                port: process.env.SMTP_PORT || 587,
                secure: process.env.SMTP_SECURE === 'true',
                auth: {
                    user: process.env.SMTP_USER,
                    pass: process.env.SMTP_PASS
                },
                tls: {
                    rejectUnauthorized: false
                }
            });

            // Verify connection
            await this.transporter.verify();
            console.log('✅ Email service initialized successfully');
        } catch (error) {
            console.error('❌ Email service initialization failed:', error.message);
            this.transporter = null;
        }
    }

    async loadTemplates() {
        const templatesDir = path.join(__dirname, '../templates/email');
        
        try {
            const templateFiles = await fs.readdir(templatesDir);
            
            for (const file of templateFiles) {
                if (file.endsWith('.html')) {
                    const templateName = file.replace('.html', '');
                    const content = await fs.readFile(path.join(templatesDir, file), 'utf8');
                    this.templates[templateName] = content;
                }
            }
            
            console.log(`✅ Loaded ${Object.keys(this.templates).length} email templates`);
        } catch (error) {
            console.log('⚠️ Email templates directory not found, using default templates');
            this.loadDefaultTemplates();
        }
    }

    loadDefaultTemplates() {
        this.templates = {
            welcome: `
                <h2>Welcome to VINaris!</h2>
                <p>Hello {{name}},</p>
                <p>Welcome to VINaris - your professional VIN checking service!</p>
                <p>Your account has been created successfully with {{credits}} free credits.</p>
                <p>Get started by submitting your first VIN check at <a href="{{siteUrl}}">vinaris.ge</a></p>
                <p>Best regards,<br>The VINaris Team</p>
            `,
            
            vinReportReady: `
                <h2>Your VIN Report is Ready!</h2>
                <p>Hello {{name}},</p>
                <p>Your VIN report for {{vin}} is now ready for download.</p>
                <p><strong>Report Details:</strong></p>
                <ul>
                    <li>VIN: {{vin}}</li>
                    <li>Plan: {{plan}}</li>
                    <li>Generated: {{date}}</li>
                </ul>
                <p><a href="{{downloadUrl}}" style="background: #e60000; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Download Report</a></p>
                <p>Best regards,<br>The VINaris Team</p>
            `,
            
            passwordReset: `
                <h2>Password Reset Request</h2>
                <p>Hello {{name}},</p>
                <p>You requested a password reset for your VINaris account.</p>
                <p>Click the link below to reset your password:</p>
                <p><a href="{{resetUrl}}" style="background: #e60000; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Reset Password</a></p>
                <p>This link will expire in 1 hour for security reasons.</p>
                <p>If you didn't request this reset, please ignore this email.</p>
                <p>Best regards,<br>The VINaris Team</p>
            `,
            
            lowCredits: `
                <h2>Low Credit Balance</h2>
                <p>Hello {{name}},</p>
                <p>Your VINaris account has {{credits}} credits remaining.</p>
                <p>To continue using our service, please purchase additional credits.</p>
                <p><a href="{{buyCreditsUrl}}" style="background: #e60000; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Buy Credits</a></p>
                <p>Best regards,<br>The VINaris Team</p>
            `,
            
            adminNotification: `
                <h2>Admin Notification</h2>
                <p>{{message}}</p>
                <p><strong>Details:</strong></p>
                <ul>
                    <li>Time: {{timestamp}}</li>
                    <li>User: {{userEmail}}</li>
                    <li>Action: {{action}}</li>
                </ul>
                <p><a href="{{adminUrl}}">View in Admin Panel</a></p>
            `
        };
    }

    async sendEmail(to, subject, templateName, data = {}) {
        if (!this.transporter) {
            console.error('❌ Email service not available');
            return false;
        }

        try {
            let html = this.templates[templateName];
            if (!html) {
                throw new Error(`Email template '${templateName}' not found`);
            }

            // Replace template variables
            html = this.replaceTemplateVariables(html, data);

            const mailOptions = {
                from: process.env.SMTP_USER,
                to: to,
                subject: subject,
                html: html,
                text: this.htmlToText(html)
            };

            const result = await this.transporter.sendMail(mailOptions);
            console.log(`✅ Email sent successfully to ${to}: ${result.messageId}`);
            return true;

        } catch (error) {
            console.error(`❌ Failed to send email to ${to}:`, error.message);
            return false;
        }
    }

    replaceTemplateVariables(template, data) {
        let html = template;
        
        // Default values
        const defaults = {
            siteUrl: 'https://vinaris.ge',
            adminUrl: 'https://vinaris.ge/admin',
            buyCreditsUrl: 'https://vinaris.ge/buy-credits',
            date: new Date().toLocaleDateString(),
            timestamp: new Date().toISOString()
        };

        const allData = { ...defaults, ...data };

        // Replace all variables
        Object.keys(allData).forEach(key => {
            const regex = new RegExp(`{{${key}}}`, 'g');
            html = html.replace(regex, allData[key] || '');
        });

        return html;
    }

    htmlToText(html) {
        return html
            .replace(/<[^>]*>/g, '')
            .replace(/&nbsp;/g, ' ')
            .replace(/&amp;/g, '&')
            .replace(/&lt;/g, '<')
            .replace(/&gt;/g, '>')
            .trim();
    }

    // Specific email methods
    async sendWelcomeEmail(user) {
        return this.sendEmail(
            user.email,
            'Welcome to VINaris!',
            'welcome',
            {
                name: user.name,
                credits: user.credits || 3,
                email: user.email
            }
        );
    }

    async sendVINReportReady(user, vinRequest, downloadUrl) {
        return this.sendEmail(
            user.email,
            'Your VIN Report is Ready!',
            'vinReportReady',
            {
                name: user.name,
                vin: vinRequest.vin,
                plan: vinRequest.plan,
                downloadUrl: downloadUrl,
                date: new Date(vinRequest.processed_at).toLocaleDateString()
            }
        );
    }

    async sendPasswordReset(user, resetToken) {
        const resetUrl = `https://vinaris.ge/reset-password?token=${resetToken}`;
        
        return this.sendEmail(
            user.email,
            'Reset Your VINaris Password',
            'passwordReset',
            {
                name: user.name,
                resetUrl: resetUrl,
                email: user.email
            }
        );
    }

    async sendLowCreditsWarning(user) {
        return this.sendEmail(
            user.email,
            'Low Credit Balance - VINaris',
            'lowCredits',
            {
                name: user.name,
                credits: user.credits,
                email: user.email
            }
        );
    }

    async sendAdminNotification(message, details = {}) {
        const adminEmail = process.env.ADMIN_EMAIL || 'admin@vinaris.ge';
        
        return this.sendEmail(
            adminEmail,
            'VINaris Admin Notification',
            'adminNotification',
            {
                message: message,
                ...details
            }
        );
    }

    async sendSystemAlert(alertType, details) {
        const adminEmail = process.env.ADMIN_EMAIL || 'admin@vinaris.ge';
        
        const alertMessages = {
            'high_error_rate': `High error rate detected: ${details.errorRate}%`,
            'database_connection': 'Database connection issues detected',
            'disk_space': `Low disk space: ${details.availableSpace}`,
            'security_breach': 'Potential security breach detected',
            'backup_failed': 'Automated backup failed'
        };

        const message = alertMessages[alertType] || `System alert: ${alertType}`;

        return this.sendEmail(
            adminEmail,
            `VINaris System Alert: ${alertType}`,
            'adminNotification',
            {
                message: message,
                action: alertType,
                timestamp: new Date().toISOString(),
                details: JSON.stringify(details, null, 2)
            }
        );
    }
}

// Create singleton instance
const emailService = new EmailService();

module.exports = emailService;
