const express = require('express');
const Joi = require('joi');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
const { authenticateToken, requireCredits } = require('../middleware/auth');
const db = require('../database/db-helper');
const pdfGenerator = require('../services/pdfGenerator');
const vinDataService = require('../services/vinDataService');

const router = express.Router();

// VIN validation schema
const vinCheckSchema = Joi.object({
    vin: Joi.string().length(17).pattern(/^[A-HJ-NPR-Z0-9]{17}$/).required(),
    plan: Joi.string().valid('basic', 'premium', 'business').default('basic')
});

// POST /api/vin/check - Submit VIN request
router.post('/check', authenticateToken, requireCredits(1), async (req, res) => {
    try {
        // Validate input
        const { error, value } = vinCheckSchema.validate(req.body);
        if (error) {
            return res.status(400).json({
                error: 'Validation Error',
                message: error.details[0].message
            });
        }

        const { vin, plan } = value;

        // Create VIN request with shorter, more readable ID
        const timestamp = Date.now().toString(36);
        const randomPart = Math.random().toString(36).substr(2, 4);
        const requestId = `VIN-${timestamp.substr(-6)}-${randomPart}`;
        
        const vinRequestId = await db.createVinRequest({
            requestId,
            userId: req.user.id,
            vin: vin.toUpperCase(),
            plan,
            userAgent: req.get('User-Agent'),
            source: 'api',
            ipAddress: req.ip
        });

        // Get comprehensive VIN data using the VIN data service
        let vinData = null;
        try {
            console.log('Fetching VIN data for:', vin.toUpperCase(), 'plan:', plan);
            
            // Check cache first
            const cachedData = await db.get(
                'SELECT * FROM vin_data_cache WHERE vin = ? ORDER BY created_at DESC LIMIT 1',
                [vin.toUpperCase()]
            );
            
            if (cachedData && new Date(cachedData.expires_at) > new Date()) {
                console.log('📋 Using cached VIN data for', vin.toUpperCase());
                vinData = JSON.parse(cachedData.cached_data);
            } else {
                console.log('🔍 Fetching fresh VIN data for', vin.toUpperCase());
                
                // For now, let's use basic NHTSA data without calling the VIN data service
                // to avoid database connection issues
                try {
                    const axios = require('axios');
                    const response = await axios.get(
                        `https://vpic.nhtsa.dot.gov/api/vehicles/decodevin/${vin.toUpperCase()}?format=json`,
                        { timeout: 10000 }
                    );

                    if (response.data && response.data.Results) {
                        const results = response.data.Results;
                        vinData = {
                            make: results.find(r => r.Variable === 'Make')?.Value || 'Unknown',
                            model: results.find(r => r.Variable === 'Model')?.Value || 'Unknown',
                            year: results.find(r => r.Variable === 'Model Year')?.Value || 'Unknown',
                            bodyClass: results.find(r => r.Variable === 'Body Class')?.Value || 'Unknown',
                            engineInfo: results.find(r => r.Variable === 'Engine Model')?.Value || 'Unknown',
                            engineSize: results.find(r => r.Variable === 'Displacement (L)')?.Value || 'Unknown',
                            cylinders: results.find(r => r.Variable === 'Engine Number of Cylinders')?.Value || 'Unknown',
                            transmission: results.find(r => r.Variable === 'Transmission Style')?.Value || 'Unknown',
                            driveType: results.find(r => r.Variable === 'Drive Type')?.Value || 'Unknown',
                            fuelType: results.find(r => r.Variable === 'Fuel Type - Primary')?.Value || 'Unknown',
                            vehicleType: results.find(r => r.Variable === 'Vehicle Type')?.Value || 'Unknown',
                            plantCountry: results.find(r => r.Variable === 'Plant Country')?.Value || 'Unknown',
                            manufacturer: results.find(r => r.Variable === 'Manufacturer Name')?.Value || 'Unknown',
                            _metadata: {
                                sources: ['NHTSA'],
                                plan: plan,
                                lastUpdated: new Date().toISOString(),
                                cacheExpires: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
                            }
                        };
                        
                        console.log('VIN data fetched successfully:', !!vinData);
                        
                        // Cache the result
                        const sources = vinData._metadata?.sources?.join(',') || 'unknown';
                        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
                        
                        await db.run(`
                            INSERT OR REPLACE INTO vin_data_cache (vin, data_source, cached_data, expires_at)
                            VALUES (?, ?, ?, ?)
                        `, [vin.toUpperCase(), sources, JSON.stringify(vinData), expiresAt]);
                        console.log('💾 Cached VIN data for', vin.toUpperCase());
                    }
                } catch (apiError) {
                    console.error('NHTSA API error:', apiError.message);
                    vinData = {
                        make: 'Unknown',
                        model: 'Unknown', 
                        year: 'Unknown',
                        error: 'Unable to fetch VIN data from NHTSA'
                    };
                }
            }
            
            // Store comprehensive report data in the request
            if (vinData) {
                console.log('Storing VIN data in database...');
                await db.run(`
                    UPDATE vin_requests 
                    SET report_data = ? 
                    WHERE request_id = ?
                `, [JSON.stringify(vinData), requestId]);
                console.log('VIN data stored successfully');
            }
        } catch (apiError) {
            console.error('VIN data service error:', apiError.message);
            console.error('VIN data service stack:', apiError.stack);
            // Set basic fallback data
            vinData = {
                make: 'Unknown',
                model: 'Unknown', 
                year: 'Unknown',
                error: 'Unable to fetch comprehensive VIN data'
            };
        }

        // Get updated user credits
        const updatedUser = await db.getUserById(req.user.id);

        res.status(201).json({
            success: true,
            message: 'VIN request submitted successfully',
            requestId,
            vin: vin.toUpperCase(),
            plan,
            status: 'pending',
            estimatedCompletion: new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString(),
            basicData: vinData,
            creditsRemaining: updatedUser.credits
        });

    } catch (error) {
        console.error('VIN check error:', error);
        console.error('Error stack:', error.stack);
        res.status(500).json({
            error: 'VIN check failed',
            message: 'Unable to process VIN request',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// GET /api/vin/requests - Get user's VIN requests
router.get('/requests', authenticateToken, async (req, res) => {
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
                estimatedCompletion: request.estimated_completion_time,
                notes: request.processing_notes,
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

// GET /api/vin/request/:requestId - Get specific request details
router.get('/request/:requestId', authenticateToken, async (req, res) => {
    try {
        const { requestId } = req.params;

        const request = await db.get(
            'SELECT * FROM vin_requests WHERE request_id = ? AND user_id = ?',
            [requestId, req.user.id]
        );

        if (!request) {
            return res.status(404).json({
                error: 'Request not found',
                message: 'VIN request not found or access denied'
            });
        }

        res.json({
            success: true,
            request: {
                id: request.id,
                requestId: request.request_id,
                vin: request.vin,
                plan: request.plan,
                status: request.status,
                createdAt: request.created_at,
                processedAt: request.processed_at,
                estimatedCompletion: request.estimated_completion_time,
                notes: request.processing_notes,
                reportData: request.report_data ? JSON.parse(request.report_data) : null,
                pdfPath: request.pdf_path
            }
        });
    } catch (error) {
        console.error('Request fetch error:', error);
        res.status(500).json({
            error: 'Request fetch failed',
            message: 'Unable to fetch VIN request details'
        });
    }
});

// POST /api/vin/generate-pdf/:requestId - Generate PDF report for a request
router.post('/generate-pdf/:requestId', authenticateToken, async (req, res) => {
    try {
        const { requestId } = req.params;

        
        // Get the VIN request
        const request = await db.get(
            'SELECT * FROM vin_requests WHERE request_id = ? AND user_id = ?',
            [requestId, req.user.id]
        );
        
        if (!request) {
            return res.status(404).json({
                error: 'Request not found',
                message: 'VIN request not found or access denied'
            });
        }
        
        // Check if PDF already exists
        if (request.pdf_path && fs.existsSync(request.pdf_path)) {
            return res.json({
                success: true,
                message: 'PDF already exists',
                pdfPath: request.pdf_path,
                filename: request.pdf_filename
            });
        }
        
        // Get cached VIN data
        let vinData = {};
        const cachedData = await db.get(
            'SELECT cached_data FROM vin_data_cache WHERE vin = ?',
            [request.vin]
        );
        
        if (cachedData) {
            vinData = JSON.parse(cachedData.cached_data);
        }
        
        // Add VIN to the data
        vinData.vin = request.vin;
        
        const requestInfo = {
            requestId: request.request_id,
            vin: request.vin,
            plan: request.plan,
            userId: request.user_id
        };
        
        // Generate PDF
        const pdfResult = await pdfGenerator.createVINReport(vinData, requestInfo);
        
        if (!pdfResult.success) {
            return res.status(500).json({
                error: 'PDF generation failed',
                message: pdfResult.error
            });
        }
        
        // Update the request with PDF information
        await db.run(`
            UPDATE vin_requests 
            SET pdf_filename = ?, pdf_path = ?, pdf_size = ?, status = 'processed', processed_at = ?
            WHERE request_id = ?
        `, [pdfResult.filename, pdfResult.path, pdfResult.size, new Date().toISOString(), requestId]);
        
        
        res.json({
            success: true,
            message: 'PDF report generated successfully',
            pdfPath: pdfResult.relativePath,
            filename: pdfResult.filename,
            size: pdfResult.size,
            generatedAt: pdfResult.generatedAt
        });
        
    } catch (error) {
        console.error('PDF generation error:', error);
        res.status(500).json({
            error: 'PDF generation failed',
            message: 'Unable to generate PDF report'
        });
    }
});

// GET /api/vin/download/:requestId - Download PDF report
router.get('/download/:requestId', authenticateToken, async (req, res) => {
    try {
        const { requestId } = req.params;

        const request = await db.get(
            'SELECT * FROM vin_requests WHERE request_id = ? AND user_id = ?',
            [requestId, req.user.id]
        );

        if (!request) {
            return res.status(404).json({
                error: 'Request not found',
                message: 'VIN request not found or access denied'
            });
        }

        if (!request.pdf_path || !fs.existsSync(request.pdf_path)) {
            return res.status(404).json({
                error: 'PDF not found',
                message: 'PDF report has not been generated yet. Please generate it first.'
            });
        }

        // Set appropriate headers for PDF download
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="${request.pdf_filename}"`);
        res.setHeader('Content-Length', request.pdf_size);

        // Stream the PDF file
        const fileStream = fs.createReadStream(request.pdf_path);
        fileStream.pipe(res);

    } catch (error) {
        console.error('PDF download error:', error);
        res.status(500).json({
            error: 'PDF download failed',
            message: 'Unable to download PDF report'
        });
    }
});

module.exports = router;
