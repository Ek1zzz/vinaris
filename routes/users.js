const express = require('express');
const { authenticateToken, requireOwnership } = require('../middleware/auth');
const db = require('../database/db-helper');

const router = express.Router();

// GET /api/users/profile - Get user profile
router.get('/profile', authenticateToken, async (req, res) => {
    try {
        const user = await db.getUserById(req.user.id);
        const transactions = await db.getCreditTransactions(req.user.id);
        const activities = await db.getUserActivities(req.user.id, 10);

        if (!user) {
            return res.status(404).json({
                error: 'User not found',
                message: 'User profile could not be found'
            });
        }

        res.json({
            success: true,
            user: {
                id: user.id,
                uniqueId: user.unique_id,
                name: user.name,
                email: user.email,
                phone: user.phone,
                company: user.company,
                credits: user.credits,
                type: user.user_type,
                totalVinChecked: user.total_vin_checked,
                totalCreditsEarned: user.total_credits_earned,
                totalCreditsSpent: user.total_credits_spent,
                joinDate: user.created_at,
                lastLogin: user.last_login_at
            },
            recentTransactions: transactions.slice(0, 5),
            recentActivities: activities
        });
    } catch (error) {
        console.error('Profile fetch error:', error);
        res.status(500).json({
            error: 'Profile fetch failed',
            message: 'Unable to fetch user profile'
        });
    }
});

// GET /api/users/credits - Get credit balance
router.get('/credits', authenticateToken, async (req, res) => {
    try {
        const user = await db.getUserById(req.user.id);
        const transactions = await db.getCreditTransactions(req.user.id);

        res.json({
            success: true,
            credits: user.credits,
            totalEarned: user.total_credits_earned,
            totalSpent: user.total_credits_spent,
            transactions: transactions
        });
    } catch (error) {
        console.error('Credits fetch error:', error);
        res.status(500).json({
            error: 'Credits fetch failed',
            message: 'Unable to fetch credit information'
        });
    }
});

// GET /api/users/history - Get request history
router.get('/history', authenticateToken, async (req, res) => {
    try {
        const requests = await db.getVinRequestsByUser(req.user.id);

        res.json({
            success: true,
            requests: requests.map(request => ({
                id: request.id,
                requestId: request.request_id,
                vin: request.vin,
                plan: request.plan,
                status: request.status,
                createdAt: request.created_at,
                processedAt: request.processed_at,
                notes: request.processing_notes,
                pdf_filename: request.pdf_filename,
                pdfPath: request.pdf_path
            }))
        });
    } catch (error) {
        console.error('History fetch error:', error);
        res.status(500).json({
            error: 'History fetch failed',
            message: 'Unable to fetch request history'
        });
    }
});

// POST /api/users/payment-request - Create bank transfer payment request
router.post('/payment-request', authenticateToken, async (req, res) => {
    try {
        const { 
            amount, 
            credits, 
            payment_date, 
            payment_time, 
            invoice_number, 
            user_notes = '', 
            currency = 'GEL', 
            payment_method = 'bank_transfer' 
        } = req.body;

        // Validate required fields
        if (!amount || !credits || !payment_date || !payment_time || !invoice_number) {
            return res.status(400).json({
                error: 'Missing required fields',
                message: 'Amount, credits, payment_date, payment_time, and invoice_number are required'
            });
        }

        // Validate amount and credits
        if (amount <= 0 || credits <= 0) {
            return res.status(400).json({
                error: 'Invalid values',
                message: 'Amount and credits must be positive numbers'
            });
        }


        // Create payment request record with shorter, more readable ID
        const timestamp = Date.now().toString(36);
        const randomPart = Math.random().toString(36).substr(2, 4);
        const paymentRequestId = `PAY-${timestamp.substr(-6)}-${randomPart}`;
        
        await db.run(`
            INSERT INTO payment_requests (
                payment_request_id, user_id, amount, credits, currency, 
                payment_method, payment_date, payment_time, invoice_number, 
                user_notes, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
        `, [
            paymentRequestId,
            req.user.id,
            parseFloat(amount),
            parseInt(credits),
            currency,
            payment_method,
            payment_date,
            payment_time,
            invoice_number,
            user_notes,
            'pending'
        ]);

        // Log activity
        await db.logActivity(
            req.user.id,
            'payment_request_created',
            `Created bank transfer payment request for ${credits} credits (${amount} ${currency})`,
            JSON.stringify({ 
                paymentRequestId, 
                amount, 
                credits, 
                invoice_number,
                payment_method 
            })
        );


        res.json({
            success: true,
            message: 'Payment request created successfully',
            paymentRequestId,
            amount,
            credits,
            invoice_number,
            status: 'pending'
        });

    } catch (error) {
        console.error('Payment request creation error:', error);
        res.status(500).json({
            error: 'Payment request creation failed',
            message: 'Unable to create payment request'
        });
    }
});

// GET /api/users/payment-requests - Get user payment requests
router.get('/payment-requests', authenticateToken, async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 20;
        
        
        const requests = await db.all(`
            SELECT * FROM payment_requests 
            WHERE user_id = ? 
            ORDER BY created_at DESC 
            LIMIT ?
        `, [req.user.id, limit]);
        
        
        const formattedRequests = requests.map(request => ({
            id: request.id,
            paymentRequestId: request.payment_request_id,
            amount: request.amount,
            credits: request.credits,
            currency: request.currency,
            paymentMethod: request.payment_method,
            paymentDate: request.payment_date,
            paymentTime: request.payment_time,
            invoiceNumber: request.invoice_number,
            status: request.status,
            userNotes: request.user_notes,
            createdAt: request.created_at,
            updatedAt: request.updated_at
        }));
        
        res.json({
            success: true,
            requests: formattedRequests
        });
        
    } catch (error) {
        console.error('Payment requests fetch error:', error);
        res.status(500).json({
            error: 'Payment requests fetch failed',
            message: 'Unable to fetch payment requests'
        });
    }
});

// GET /api/users/download-pdf/:requestId - Download PDF for a VIN request
router.get('/download-pdf/:requestId', authenticateToken, async (req, res) => {
    try {
        const { requestId } = req.params;
        
        // Get the VIN request to verify ownership and get PDF filename
        const request = await db.get(`
            SELECT id, user_id, pdf_filename, pdf_path, vin, status 
            FROM vin_requests 
            WHERE request_id = ? AND user_id = ?
        `, [requestId, req.user.id]);
        
        if (!request) {
            return res.status(404).json({
                error: 'Request not found',
                message: 'VIN request not found or you do not have permission to access it'
            });
        }
        
        if (!request.pdf_filename) {
            return res.status(404).json({
                error: 'PDF not available',
                message: 'PDF file is not available for this request'
            });
        }
        
        if (request.status !== 'processed' && request.status !== 'delivered' && request.status !== 'completed') {
            return res.status(400).json({
                error: 'PDF not ready',
                message: 'PDF is not ready for download yet'
            });
        }
        
        // Check if we have a real PDF file path
        if (request.pdf_path && request.pdf_path !== 'null') {
            // Serve the actual uploaded PDF file
            const fs = require('fs');
            const path = require('path');
            
            try {
                // Check if the file exists
                if (fs.existsSync(request.pdf_path)) {
                    const fileBuffer = fs.readFileSync(request.pdf_path);
                    res.setHeader('Content-Type', 'application/pdf');
                    res.setHeader('Content-Disposition', `attachment; filename="VINaris_Report_${request.vin}.pdf"`);
                    res.send(fileBuffer);
                    return;
                }
            } catch (fileError) {
                console.error('Error reading PDF file:', fileError);
                // Fall through to generate a PDF if file reading fails
            }
        }
        
        // If no real PDF file exists, generate a proper VIN report PDF
        // This would typically use a PDF generation library like puppeteer or pdfkit
        const pdfContent = `%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj

2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj

3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents 4 0 R
/Resources <<
/Font <<
/F1 <<
/Type /Font
/Subtype /Type1
/BaseFont /Helvetica
>>
>>
>>
endobj

4 0 obj
<<
/Length 200
>>
stream
BT
/F1 16 Tf
100 700 Td
(VINaris Vehicle Report) Tj
0 -30 Td
/F1 12 Tf
(VIN Number: ${request.vin}) Tj
0 -20 Td
(Status: ${request.status}) Tj
0 -20 Td
(Generated: ${new Date().toLocaleDateString()}) Tj
0 -40 Td
(Note: This is a placeholder PDF. In production, this would contain) Tj
0 -15 Td
(the actual vehicle data and detailed report information.) Tj
ET
endstream
endobj

xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000204 00000 n 
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
450
%%EOF`;

        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="VINaris_Report_${request.vin}.pdf"`);
        res.send(pdfContent);
        
    } catch (error) {
        console.error('PDF download error:', error);
        res.status(500).json({
            error: 'Download failed',
            message: 'Unable to download PDF file'
        });
    }
});

module.exports = router;
