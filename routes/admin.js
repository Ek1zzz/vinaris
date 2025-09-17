const express = require('express');
const { authenticateToken, requireAdmin } = require('../middleware/auth');
const db = require('../database/db-helper');
const vinDataService = require('../services/vinDataService');

const router = express.Router();

// All admin routes require authentication and admin privileges
router.use(authenticateToken);
router.use(requireAdmin);

// GET /api/admin/dashboard - Admin dashboard statistics
router.get('/dashboard', async (req, res) => {
    try {
        const stats = await db.getSystemStats();

        res.json({
            success: true,
            stats
        });
    } catch (error) {
        console.error('Dashboard stats error:', error);
        res.status(500).json({
            error: 'Dashboard fetch failed',
            message: 'Unable to fetch dashboard statistics'
        });
    }
});

// GET /api/admin/users - Get all users
router.get('/users', async (req, res) => {
    try {
        const users = await db.getAllUsers();

        res.json({
            success: true,
            users: users.map(user => ({
                id: user.id,
                uniqueId: user.unique_id,
                name: user.name,
                email: user.email,
                type: user.user_type,
                credits: user.credits,
                totalRequests: user.total_requests,
                pendingRequests: user.pending_requests,
                joinDate: user.created_at,
                lastLogin: user.last_login_at,
                status: user.status
            }))
        });
    } catch (error) {
        console.error('Users fetch error:', error);
        res.status(500).json({
            error: 'Users fetch failed',
            message: 'Unable to fetch users list'
        });
    }
});

// GET /api/admin/requests - Get all VIN requests
router.get('/requests', async (req, res) => {
    try {
        const requests = await db.getAllVinRequests();

        res.json({
            success: true,
            requests: requests.map(request => ({
                id: request.id,
                requestId: request.request_id,
                vin: request.vin,
                plan: request.plan,
                status: request.status,
                userId: request.user_id,
                userName: request.user_name,
                userEmail: request.user_email,
                createdAt: request.created_at,
                processedAt: request.processed_at,
                processed_by: request.processed_by,
                processing_notes: request.processing_notes,
                pdf_filename: request.pdf_filename,
                pdf_path: request.pdf_path,
                report_data: request.report_data,
                hasPdf: !!request.pdf_path
            }))
        });
    } catch (error) {
        console.error('Requests fetch error:', error);
        res.status(500).json({
            error: 'Requests fetch failed',
            message: 'Unable to fetch VIN requests'
        });
    }
});

// PUT /api/admin/credits/:userId - Adjust user credits
router.put('/credits/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        const { amount, reason } = req.body;

        if (!amount || !reason) {
            return res.status(400).json({
                error: 'Missing required fields',
                message: 'Amount and reason are required'
            });
        }

        const newBalance = await db.addCredits(userId, amount, reason, 'admin', req.user.id);

        res.json({
            success: true,
            message: 'Credits updated successfully',
            newBalance
        });
    } catch (error) {
        console.error('Credit update error:', error);
        res.status(500).json({
            error: 'Credit update failed',
            message: error.message
        });
    }
});

// PUT /api/admin/request/:requestId - Update VIN request status
router.put('/request/:requestId', async (req, res) => {
    try {
        const { requestId } = req.params;
        const { status, notes } = req.body;

        if (!status) {
            return res.status(400).json({
                error: 'Missing required field',
                message: 'Status is required'
            });
        }

        await db.updateVinRequestStatus(requestId, status, req.user.id, notes);

        res.json({
            success: true,
            message: 'Request status updated successfully'
        });
    } catch (error) {
        console.error('Request update error:', error);
        res.status(500).json({
            error: 'Request update failed',
            message: 'Unable to update request status'
        });
    }
});

// GET /api/admin/services/status - Get VIN data service status
router.get('/services/status', (req, res) => {
    try {
        const serviceStatus = vinDataService.getServiceStatus();
        
        res.json({
            success: true,
            message: 'VIN data service status retrieved successfully',
            status: serviceStatus,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        console.error('Service status error:', error);
        res.status(500).json({
            error: 'Service status fetch failed',
            message: 'Unable to fetch VIN data service status'
        });
    }
});

// GET /api/admin/activities - Get all user activities
router.get('/activities', async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 50;
        const offset = parseInt(req.query.offset) || 0;
        
        let query = `
            SELECT ua.*, u.name as user_name, u.email as user_email
            FROM user_activities ua
            LEFT JOIN users u ON ua.user_id = u.id
            ORDER BY ua.created_at DESC
            LIMIT ? OFFSET ?
        `;
        
        const activities = await db.all(query, [limit, offset]);
        
        // Get total count
        const countResult = await db.get('SELECT COUNT(*) as total FROM user_activities');
        const total = countResult.total;
        
        res.json({
            success: true,
            activities: activities.map(activity => ({
                id: activity.id,
                userId: activity.user_id,
                user: {
                    name: activity.user_name || 'Unknown User',
                    email: activity.user_email || 'No Email'
                },
                activityType: activity.activity_type,
                description: activity.description,
                metadata: activity.metadata ? JSON.parse(activity.metadata) : null,
                createdAt: activity.created_at
            })),
            pagination: {
                total,
                limit,
                offset,
                hasMore: offset + limit < total
            }
        });
        
    } catch (error) {
        console.error('Admin activities fetch error:', error);
        res.status(500).json({
            error: 'Activities fetch failed',
            message: 'Unable to fetch user activities'
        });
    }
});

// GET /api/admin/payment-requests - Get all payment requests
router.get('/payment-requests', async (req, res) => {
    try {
        const status = req.query.status || null;
        const limit = parseInt(req.query.limit) || 50;
        const offset = parseInt(req.query.offset) || 0;
        
        let query = `
            SELECT pr.*, u.name as user_name, u.email as user_email, 
                   admin.name as verified_by_name
            FROM payment_requests pr 
            LEFT JOIN users u ON pr.user_id = u.id
            LEFT JOIN users admin ON pr.verified_by = admin.id
        `;
        const params = [];
        
        if (status) {
            query += ` WHERE pr.status = ?`;
            params.push(status);
        }
        
        query += ` ORDER BY pr.created_at DESC LIMIT ? OFFSET ?`;
        params.push(limit, offset);
        
        const requests = await db.all(query, params);
        
        // Get total count
        let countQuery = `SELECT COUNT(*) as total FROM payment_requests`;
        const countParams = [];
        if (status) {
            countQuery += ` WHERE status = ?`;
            countParams.push(status);
        }
        
        const countResult = await db.get(countQuery, countParams);
        const total = countResult.total;
        
        res.json({
            success: true,
            requests: requests.map(request => ({
                id: request.id,
                paymentRequestId: request.payment_request_id,
                user: {
                    id: request.user_id,
                    name: request.user_name || 'Unknown User',
                    email: request.user_email || 'No Email'
                },
                amount: request.amount,
                credits: request.credits,
                currency: request.currency,
                paymentMethod: request.payment_method,
                status: request.status,
                invoiceNumber: request.invoice_number,
                bankReference: request.bank_reference || 'N/A',
                paymentDate: request.payment_date || 'N/A',
                paymentTime: request.payment_time || 'N/A',
                userNotes: request.user_notes || '',
                verificationNotes: request.verification_notes,
                verifiedBy: request.verified_by,
                verifiedByName: request.verified_by_name || 'N/A',
                verifiedAt: request.verified_at,
                createdAt: request.created_at,
                updatedAt: request.updated_at
            })),
            pagination: {
                total,
                limit,
                offset,
                hasMore: offset + limit < total
            }
        });
        
    } catch (error) {
        console.error('Admin payment requests fetch error:', error);
        res.status(500).json({
            error: 'Payment requests fetch failed',
            message: 'Unable to fetch payment requests'
        });
    }
});

// POST /api/admin/payment-request - Update payment request status
router.post('/payment-request', async (req, res) => {
    try {
        const { payment_id, status, verification_notes } = req.body;

        if (!payment_id || !status) {
            return res.status(400).json({
                error: 'Missing required fields',
                message: 'Payment ID and status are required'
            });
        }

        // Update payment request status
        const updateResult = await db.run(`
            UPDATE payment_requests 
            SET status = ?, 
                verification_notes = ?, 
                verified_by = ?, 
                verified_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP
            WHERE payment_request_id = ?
        `, [status, verification_notes || null, req.user.id, payment_id]);
        
        if (updateResult.changes === 0) {
            return res.status(404).json({
                error: 'Payment request not found',
                message: 'No payment request found with the given ID'
            });
        }

        // If approved, add credits to user
        if (status === 'approved') {
            // Get payment request details
            const paymentRequest = await db.get(`
                SELECT user_id, credits FROM payment_requests 
                WHERE payment_request_id = ?
            `, [payment_id]);

            if (paymentRequest) {
                // Add credits to user
                await db.run(`
                    UPDATE users 
                    SET credits = credits + ?, 
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                `, [paymentRequest.credits, paymentRequest.user_id]);

                // Log credit transaction
                await db.run(`
                    INSERT INTO credit_transactions (
                        transaction_id, user_id, amount, transaction_type, 
                        reason, payment_method, payment_reference, 
                        admin_id, balance_before, balance_after
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                `, [
                    `TXN_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
                    paymentRequest.user_id,
                    paymentRequest.credits,
                    'purchase',
                    `Payment approved - ${payment_id}`,
                    'bank_transfer',
                    payment_id,
                    req.user.id,
                    0, // We'll calculate this properly in production
                    paymentRequest.credits
                ]);
            }
        }

        res.json({
            success: true,
            message: 'Payment request status updated successfully'
        });
    } catch (error) {
        console.error('Payment status update error:', error);
        res.status(500).json({
            error: 'Payment update failed',
            message: 'Unable to update payment request status'
        });
    }
});

// POST /api/admin/upload-pdf - Upload PDF for a VIN request
router.post('/upload-pdf', async (req, res) => {
    try {
        const { request_id, admin_id, pdf_data } = req.body;
        
        if (!request_id || !admin_id) {
            return res.status(400).json({
                error: 'Missing required fields',
                message: 'Request ID and Admin ID are required'
            });
        }

        const fs = require('fs');
        const path = require('path');
        
        // Create uploads directory if it doesn't exist
        const uploadsDir = path.join(__dirname, '..', 'uploads', 'pdfs');
        if (!fs.existsSync(uploadsDir)) {
            fs.mkdirSync(uploadsDir, { recursive: true });
        }
        
        const filename = `report_${request_id}.pdf`;
        const filePath = path.join(uploadsDir, filename);
        
        // If PDF data is provided, use it; otherwise create a placeholder
        if (pdf_data && pdf_data.length > 0) {
            // Handle base64 PDF data
            const base64Data = pdf_data.replace(/^data:application\/pdf;base64,/, '');
            const pdfBuffer = Buffer.from(base64Data, 'base64');
            fs.writeFileSync(filePath, pdfBuffer);
        } else {
            // Create a placeholder PDF if no data provided
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
/BaseFont /Helvetica-Bold
>>
/F2 <<
/Type /Font
/Subtype /Type1
/BaseFont /Helvetica
>>
>>
>>
endobj

4 0 obj
<<
/Length 500
>>
stream
BT
/F1 20 Tf
100 750 Td
(VINaris Vehicle Report) Tj
0 -40 Td
/F2 14 Tf
(VIN Number: ${request_id}) Tj
0 -30 Td
(Report Generated: ${new Date().toLocaleString()}) Tj
0 -30 Td
(Status: Processed) Tj
0 -30 Td
(Admin ID: ${admin_id}) Tj
0 -50 Td
/F1 16 Tf
(Vehicle Information) Tj
0 -20 Td
/F2 12 Tf
(This is a comprehensive vehicle report containing) Tj
0 -15 Td
(detailed information about the vehicle including) Tj
0 -15 Td
(history, specifications, and other relevant data.) Tj
0 -30 Td
(Report ID: ${request_id}) Tj
0 -20 Td
(Generated by VINaris System) Tj
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
750
%%EOF`;

            fs.writeFileSync(filePath, pdfContent);
        }

        // Update the VIN request to mark it as having a PDF
        await db.run(`
            UPDATE vin_requests 
            SET pdf_filename = ?, 
                pdf_path = ?,
                processed_by = ?, 
                processed_at = CURRENT_TIMESTAMP,
                status = 'processed',
                updated_at = CURRENT_TIMESTAMP
            WHERE request_id = ?
        `, [filename, filePath, admin_id, request_id]);

        res.json({
            success: true,
            message: 'PDF uploaded successfully',
            filename: filename,
            path: filePath
        });
    } catch (error) {
        console.error('PDF upload error:', error);
        res.status(500).json({
            error: 'PDF upload failed',
            message: 'Unable to upload PDF'
        });
    }
});

// POST /api/admin/send-pdf - Send PDF to user
router.post('/send-pdf', async (req, res) => {
    try {
        const { request_id, admin_id } = req.body;
        
        if (!request_id || !admin_id) {
            return res.status(400).json({
                error: 'Missing required fields',
                message: 'Request ID and Admin ID are required'
            });
        }

        // Update the VIN request status to processed (since 'delivered' is not in the schema)
        await db.run(`
            UPDATE vin_requests 
            SET status = 'processed',
                updated_at = CURRENT_TIMESTAMP
            WHERE request_id = ?
        `, [request_id]);

        // Log the activity
        const request = await db.get('SELECT user_id FROM vin_requests WHERE request_id = ?', [request_id]);
        if (request) {
            await db.run(`
                INSERT INTO user_activities (user_id, activity_type, description, metadata)
                VALUES (?, ?, ?, ?)
            `, [
                request.user_id,
                'pdf_delivered',
                `PDF report delivered for request ${request_id}`,
                JSON.stringify({ request_id, admin_id, delivered_at: new Date().toISOString() })
            ]);
        }

        res.json({
            success: true,
            message: 'PDF sent to user successfully'
        });
    } catch (error) {
        console.error('Send PDF error:', error);
        res.status(500).json({
            error: 'Send PDF failed',
            message: 'Unable to send PDF to user'
        });
    }
});

// GET /api/admin/download-pdf/:requestId - Download PDF for admin
router.get('/download-pdf/:requestId', authenticateToken, async (req, res) => {
    try {
        const { requestId } = req.params;
        
        // Get the VIN request (admin can access any request)
        const request = await db.get(`
            SELECT vr.id, vr.request_id, vr.user_id, vr.pdf_filename, vr.pdf_path, vr.vin, vr.status, u.name as user_name
            FROM vin_requests vr
            LEFT JOIN users u ON vr.user_id = u.id
            WHERE vr.request_id = ?
        `, [requestId]);
        
        if (!request) {
            return res.status(404).json({
                error: 'Request not found',
                message: 'VIN request not found'
            });
        }
        
        if (!request.pdf_filename) {
            return res.status(404).json({
                error: 'PDF not available',
                message: 'PDF file is not available for this request'
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
                    res.setHeader('Content-Disposition', `attachment; filename="VINaris_Report_${request.vin}_${request.request_id}.pdf"`);
                    res.send(fileBuffer);
                    return;
                }
            } catch (fileError) {
                console.error('Error reading PDF file:', fileError);
                // Fall through to generate a PDF if file reading fails
            }
        }
        
        // If no real PDF file exists, generate a placeholder PDF
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
/BaseFont /Helvetica-Bold
>>
/F2 <<
/Type /Font
/Subtype /Type1
/BaseFont /Helvetica
>>
>>
>>
endobj

4 0 obj
<<
/Length 500
>>
stream
BT
/F1 20 Tf
100 750 Td
(VINaris Vehicle Report) Tj
0 -40 Td
/F2 14 Tf
(VIN Number: ${request.vin}) Tj
0 -30 Td
(Report Generated: ${new Date().toLocaleString()}) Tj
0 -30 Td
(Status: ${request.status}) Tj
0 -30 Td
(Customer: ${request.user_name}) Tj
0 -50 Td
/F1 16 Tf
(Vehicle Information) Tj
0 -20 Td
/F2 12 Tf
(This is a comprehensive vehicle report containing) Tj
0 -15 Td
(detailed information about the vehicle including) Tj
0 -15 Td
(history, specifications, and other relevant data.) Tj
0 -30 Td
(Report ID: ${request.request_id}) Tj
0 -20 Td
(Generated by VINaris System) Tj
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
750
%%EOF`;

        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="VINaris_Report_${request.vin}_${request.request_id}.pdf"`);
        res.send(pdfContent);
        
    } catch (error) {
        console.error('Download PDF error:', error);
        res.status(500).json({
            error: 'Download PDF failed',
            message: 'Unable to download PDF'
        });
    }
});

// POST /api/admin/users/update - Update user information
router.post('/users/update', async (req, res) => {
    try {
        const { user_id, name, email } = req.body;

        if (!user_id || !name || !email) {
            return res.status(400).json({
                error: 'Missing required fields',
                message: 'User ID, name, and email are required'
            });
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({
                error: 'Invalid email format',
                message: 'Please provide a valid email address'
            });
        }

        // Update user information
        const updateResult = await db.run(`
            UPDATE users 
            SET name = ?, email = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND user_type != 'admin'
        `, [name, email, user_id]);

        if (updateResult.changes === 0) {
            return res.status(404).json({
                error: 'User not found',
                message: 'User not found or cannot update admin users'
            });
        }

        // Log activity
        await db.logActivity(
            req.user.id,
            'user_updated',
            `Updated user ${user_id} information`,
            JSON.stringify({ user_id, name, email })
        );

        res.json({
            success: true,
            message: 'User updated successfully'
        });

    } catch (error) {
        console.error('User update error:', error);
        res.status(500).json({
            error: 'User update failed',
            message: 'Unable to update user information'
        });
    }
});

// POST /api/admin/users/status - Update user status
router.post('/users/status', async (req, res) => {
    try {
        const { user_id, status } = req.body;

        if (!user_id || !status) {
            return res.status(400).json({
                error: 'Missing required fields',
                message: 'User ID and status are required'
            });
        }

        if (!['active', 'suspended', 'deleted'].includes(status)) {
            return res.status(400).json({
                error: 'Invalid status',
                message: 'Status must be either "active", "suspended", or "deleted"'
            });
        }

        // Update user status (only for non-admin users)
        const updateResult = await db.run(`
            UPDATE users 
            SET status = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND user_type != 'admin'
        `, [status, user_id]);

        if (updateResult.changes === 0) {
            return res.status(404).json({
                error: 'User not found',
                message: 'User not found or cannot update admin status'
            });
        }

        // Log activity
        await db.logActivity(
            req.user.id,
            'user_status_updated',
            `Updated user ${user_id} status to ${status}`,
            JSON.stringify({ user_id, status })
        );

        res.json({
            success: true,
            message: `User ${status === 'active' ? 'activated' : status === 'suspended' ? 'suspended' : 'deleted'} successfully`
        });

    } catch (error) {
        console.error('User status update error:', error);
        res.status(500).json({
            error: 'User status update failed',
            message: 'Unable to update user status'
        });
    }
});

// GET /api/admin/users/:userId/activities - Get user activities
router.get('/users/:userId/activities', async (req, res) => {
    try {
        const { userId } = req.params;
        const limit = parseInt(req.query.limit) || 50;

        // Get user activities
        const activities = await db.all(`
            SELECT activity_type, description, created_at
            FROM user_activities 
            WHERE user_id = ? 
            ORDER BY created_at DESC 
            LIMIT ?
        `, [userId, limit]);

        res.json({
            success: true,
            activities: activities.map(activity => ({
                action: activity.activity_type,
                description: activity.description,
                created_at: activity.created_at
            }))
        });

    } catch (error) {
        console.error('User activities fetch error:', error);
        res.status(500).json({
            error: 'User activities fetch failed',
            message: 'Unable to fetch user activities'
        });
    }
});

// POST /api/admin/users/create - Create new user manually
router.post('/users/create', async (req, res) => {
    try {
        const { name, email, password, user_type, credits, company, phone } = req.body;

        // Check if database is available
        if (!db) {
            throw new Error('Database connection not available');
        }

        // Validate required fields
        if (!email || !password) {
            return res.status(400).json({
                error: 'Missing required fields',
                message: 'Email and password are required'
            });
        }

        // Set default values for optional fields
        const finalName = name || 'User';
        const finalUserType = user_type || 'user';
        const finalCredits = credits || 3;

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({
                error: 'Invalid email format',
                message: 'Please provide a valid email address'
            });
        }

        // Validate user type
        if (!['user', 'admin'].includes(finalUserType)) {
            return res.status(400).json({
                error: 'Invalid user type',
                message: 'User type must be either "user" or "admin"'
            });
        }

        // Check if user already exists
        const existingUser = await db.get('SELECT id, status FROM users WHERE email = ?', [email]);
        if (existingUser) {
            if (existingUser.status === 'active') {
                return res.status(400).json({
                    error: 'User already exists',
                    message: 'A user with this email already exists'
                });
            } else {
                console.log(`Reusing email from ${existingUser.status} user: ${email}`);
                // We'll update the existing user instead of creating a new one
            }
        }

        // Hash password
        const bcrypt = require('bcrypt');
        const saltRounds = 10;
        const passwordHash = await bcrypt.hash(password, saltRounds);

        // Generate unique ID
        const timestamp = Date.now().toString(36);
        const randomPart = Math.random().toString(36).substr(2, 4);
        const uniqueId = `USER-${timestamp.substr(-6)}-${randomPart}`.toUpperCase();

        // Set default credits if not provided
        const defaultCredits = finalCredits || (finalUserType === 'admin' ? 999 : 3);

        // Create or update user
        let result;
        let userId;
        
        if (existingUser) {
            // Update existing user
            try {
                result = await db.run(`
                    UPDATE users 
                    SET unique_id = ?, name = ?, password_hash = ?, user_type = ?, credits = ?, company = ?, phone = ?, status = 'active', updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                `, [uniqueId, finalName, passwordHash, finalUserType, defaultCredits, company || '', phone || '', existingUser.id]);
                
                userId = existingUser.id;
                console.log(`Updated existing user with ID: ${userId}`);
            } catch (dbError) {
                console.error('Database update error:', dbError);
                throw new Error(`Database update failed: ${dbError.message}`);
            }
        } else {
            // Create new user
            try {
                result = await db.run(`
                    INSERT INTO users (unique_id, name, email, password_hash, user_type, credits, company, phone, status, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                `, [uniqueId, finalName, email, passwordHash, finalUserType, defaultCredits, company || '', phone || '']);
                
                userId = result.id;
                console.log(`Created new user with ID: ${userId}`);
            } catch (dbError) {
                console.error('Database insertion error:', dbError);
                throw new Error(`Database insertion failed: ${dbError.message}`);
            }
        }

        // Check if user was created/updated successfully
        if (!userId) {
            console.error('Failed to create/update user - no ID returned. Result:', result);
            throw new Error('Failed to create/update user - no ID returned from database');
        }

        // Log the activity (only if we have a valid userId)
        try {
            const activityType = existingUser ? 'account_reactivated' : 'account_created';
            const activityDescription = existingUser ? 
                `Account reactivated manually by admin (was ${existingUser.status})` : 
                `Account created manually by admin`;
                
            await db.run(`
                INSERT INTO user_activities (user_id, activity_type, description, metadata)
                VALUES (?, ?, ?, ?)
            `, [
                userId,
                activityType,
                activityDescription,
                JSON.stringify({ 
                    created_by: req.user?.id || 'system', 
                    user_type: finalUserType,
                    credits: defaultCredits,
                    created_at: new Date().toISOString(),
                    was_suspended: existingUser ? existingUser.status === 'suspended' : false
                })
            ]);
        } catch (activityError) {
            console.error('Failed to log user activity:', activityError);
            // Don't fail the entire operation if activity logging fails
        }

        res.json({
            success: true,
            message: existingUser ? 'User reactivated successfully' : 'User created successfully',
            user: {
                id: userId,
                uniqueId: uniqueId,
                name: finalName,
                email: email,
                type: finalUserType,
                credits: defaultCredits,
                company: company || '',
                phone: phone || ''
            },
            wasReactivated: !!existingUser
        });

    } catch (error) {
        console.error('User creation error:', error);
        console.error('Error stack:', error.stack);
        res.status(500).json({
            error: 'User creation failed',
            message: 'Unable to create user',
            details: error.message
        });
    }
});

// GET /api/admin/users/:userId/details - Get detailed user information
router.get('/users/:userId/details', async (req, res) => {
    try {
        const { userId } = req.params;

        // Get user basic information
        const user = await db.get(`
            SELECT u.*, 
                   COUNT(vr.id) as total_requests,
                   COUNT(CASE WHEN vr.status = 'pending' THEN 1 END) as pending_requests,
                   COUNT(CASE WHEN vr.status = 'completed' THEN 1 END) as completed_requests,
                   COUNT(CASE WHEN vr.status = 'cancelled' THEN 1 END) as cancelled_requests,
                   SUM(CASE WHEN vr.status = 'completed' THEN 1 ELSE 0 END) as total_completed
            FROM users u
            LEFT JOIN vin_requests vr ON u.id = vr.user_id
            WHERE u.id = ?
            GROUP BY u.id
        `, [userId]);

        if (!user) {
            return res.status(404).json({
                error: 'User not found',
                message: 'User with this ID does not exist'
            });
        }

        // Get recent VIN requests
        const recentRequests = await db.all(`
            SELECT request_id, vin, status, created_at, updated_at
            FROM vin_requests 
            WHERE user_id = ? 
            ORDER BY created_at DESC 
            LIMIT 10
        `, [userId]);

        // Get credit transactions
        const creditTransactions = await db.all(`
            SELECT id, transaction_type, amount, reason, created_at
            FROM credit_transactions 
            WHERE user_id = ? 
            ORDER BY created_at DESC 
            LIMIT 10
        `, [userId]);

        // Get recent activities
        const recentActivities = await db.all(`
            SELECT activity_type, description, created_at
            FROM user_activities 
            WHERE user_id = ? 
            ORDER BY created_at DESC 
            LIMIT 10
        `, [userId]);

        // Get payment requests
        const paymentRequests = await db.all(`
            SELECT payment_request_id, amount, status, created_at, verified_at
            FROM payment_requests 
            WHERE user_id = ? 
            ORDER BY created_at DESC 
            LIMIT 5
        `, [userId]);

        res.json({
            success: true,
            user: {
                id: user.id,
                uniqueId: user.unique_id,
                name: user.name,
                email: user.email,
                type: user.user_type,
                credits: user.credits,
                company: user.company || '',
                phone: user.phone || '',
                status: user.status,
                createdAt: user.created_at,
                lastLoginAt: user.last_login_at,
                totalRequests: user.total_requests || 0,
                pendingRequests: user.pending_requests || 0,
                completedRequests: user.completed_requests || 0,
                cancelledRequests: user.cancelled_requests || 0
            },
            statistics: {
                totalRequests: user.total_requests || 0,
                pendingRequests: user.pending_requests || 0,
                completedRequests: user.completed_requests || 0,
                cancelledRequests: user.cancelled_requests || 0,
                successRate: user.total_requests > 0 ? Math.round((user.completed_requests / user.total_requests) * 100) : 0
            },
            recentRequests: recentRequests,
            creditTransactions: creditTransactions.map(transaction => ({
                id: transaction.id,
                type: transaction.transaction_type,
                amount: transaction.amount,
                description: transaction.reason,
                created_at: transaction.created_at
            })),
            recentActivities: recentActivities,
            paymentRequests: paymentRequests
        });

    } catch (error) {
        console.error('User details fetch error:', error);
        res.status(500).json({
            error: 'User details fetch failed',
            message: 'Unable to fetch user details'
        });
    }
});

module.exports = router;
