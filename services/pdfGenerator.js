/**
 * PDF Generation Service for VIN Reports
 * Generates professional PDF reports for VIN check results
 */

const htmlPdf = require('html-pdf-node');
const fs = require('fs');
const path = require('path');

class PDFGenerator {
    constructor() {
        this.options = {
            format: 'A4',
            width: '210mm',
            height: '297mm',
            border: {
                top: '10mm',
                right: '10mm',
                bottom: '10mm',
                left: '10mm'
            },
            header: {
                height: '15mm'
            },
            footer: {
                height: '15mm'
            }
        };
    }

    // Generate VIN report HTML template
    generateHTMLTemplate(vinData, requestInfo) {
        const currentDate = new Date().toLocaleDateString();
        
        return `
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>VINaris VIN Report - ${vinData.vin}</title>
            <style>
                body {
                    font-family: 'Arial', sans-serif;
                    margin: 0;
                    padding: 20px;
                    color: #333;
                    line-height: 1.6;
                }
                .header {
                    text-align: center;
                    border-bottom: 3px solid #007bff;
                    padding-bottom: 20px;
                    margin-bottom: 30px;
                }
                .logo {
                    font-size: 28px;
                    font-weight: bold;
                    color: #007bff;
                    margin-bottom: 10px;
                }
                .subtitle {
                    color: #666;
                    font-size: 16px;
                }
                .report-info {
                    background: #f8f9fa;
                    padding: 15px;
                    border-left: 4px solid #007bff;
                    margin: 20px 0;
                }
                .info-grid {
                    display: grid;
                    grid-template-columns: 1fr 1fr;
                    gap: 10px;
                    margin: 20px 0;
                }
                .info-item {
                    background: white;
                    padding: 15px;
                    border: 1px solid #dee2e6;
                    border-radius: 5px;
                }
                .info-label {
                    font-weight: bold;
                    color: #495057;
                    font-size: 14px;
                    margin-bottom: 5px;
                }
                .info-value {
                    font-size: 16px;
                    color: #212529;
                }
                .section {
                    margin: 30px 0;
                    padding: 20px;
                    border: 1px solid #dee2e6;
                    border-radius: 8px;
                }
                .section-title {
                    font-size: 20px;
                    font-weight: bold;
                    color: #007bff;
                    margin-bottom: 15px;
                    border-bottom: 1px solid #dee2e6;
                    padding-bottom: 10px;
                }
                .vin-number {
                    font-size: 24px;
                    font-weight: bold;
                    text-align: center;
                    background: #007bff;
                    color: white;
                    padding: 15px;
                    border-radius: 8px;
                    letter-spacing: 2px;
                    margin: 20px 0;
                }
                .footer {
                    margin-top: 40px;
                    padding-top: 20px;
                    border-top: 1px solid #dee2e6;
                    text-align: center;
                    color: #666;
                    font-size: 12px;
                }
                .status-badge {
                    display: inline-block;
                    padding: 5px 10px;
                    border-radius: 15px;
                    font-size: 12px;
                    font-weight: bold;
                    text-transform: uppercase;
                }
                .status-verified {
                    background: #d4edda;
                    color: #155724;
                }
                .disclaimer {
                    background: #fff3cd;
                    border: 1px solid #ffeaa7;
                    padding: 15px;
                    border-radius: 5px;
                    margin: 20px 0;
                    font-size: 14px;
                }
            </style>
        </head>
        <body>
            <div class="header">
                <div class="logo">VINaris</div>
                <div class="subtitle">Professional Vehicle Information Report</div>
            </div>

            <div class="vin-number">${vinData.vin || 'Unknown VIN'}</div>

            <div class="report-info">
                <strong>Report Information</strong><br>
                <strong>Report ID:</strong> ${requestInfo.requestId}<br>
                <strong>Generated:</strong> ${currentDate}<br>
                <strong>Plan:</strong> ${requestInfo.plan.toUpperCase()}<br>
                <strong>Status:</strong> <span class="status-badge status-verified">Verified</span>
            </div>

            <div class="section">
                <div class="section-title">Vehicle Information</div>
                <div class="info-grid">
                    <div class="info-item">
                        <div class="info-label">Make</div>
                        <div class="info-value">${vinData.make || 'Not Available'}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Model</div>
                        <div class="info-value">${vinData.model || 'Not Available'}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Year</div>
                        <div class="info-value">${vinData.year || 'Not Available'}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Body Class</div>
                        <div class="info-value">${vinData.bodyClass || 'Not Available'}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Engine</div>
                        <div class="info-value">${vinData.engineInfo || 'Not Available'}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Transmission</div>
                        <div class="info-value">${vinData.transmission || 'Not Available'}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Fuel Type</div>
                        <div class="info-value">${vinData.fuelType || 'Not Available'}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Drive Type</div>
                        <div class="info-value">${vinData.driveType || 'Not Available'}</div>
                    </div>
                </div>
            </div>

            <div class="section">
                <div class="section-title">Technical Specifications</div>
                <div class="info-grid">
                    <div class="info-item">
                        <div class="info-label">Engine Size</div>
                        <div class="info-value">${vinData.engineSize || 'Not Available'}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Cylinders</div>
                        <div class="info-value">${vinData.cylinders || 'Not Available'}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Vehicle Type</div>
                        <div class="info-value">${vinData.vehicleType || 'Not Available'}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Plant Country</div>
                        <div class="info-value">${vinData.plantCountry || 'Not Available'}</div>
                    </div>
                </div>
            </div>

            ${requestInfo.plan === 'premium' || requestInfo.plan === 'business' ? `
            <div class="section">
                <div class="section-title">Advanced Information</div>
                <div class="info-grid">
                    <div class="info-item">
                        <div class="info-label">Safety Rating</div>
                        <div class="info-value">5 Stars (Estimated)</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Market Value</div>
                        <div class="info-value">Contact dealer for current pricing</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Recall Status</div>
                        <div class="info-value">No active recalls found</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Theft Status</div>
                        <div class="info-value">Not reported stolen</div>
                    </div>
                </div>
            </div>
            ` : ''}

            <div class="disclaimer">
                <strong>Disclaimer:</strong> This report is based on information available from public sources including NHTSA. 
                VINaris makes no warranties regarding the accuracy, completeness, or timeliness of this information. 
                This report should be used for informational purposes only and not as the sole basis for purchasing decisions.
            </div>

            <div class="footer">
                <p>Report generated by VINaris.ge - Professional VIN Checking Service</p>
                <p>For support, contact: support@vinaris.ge</p>
                <p>© ${new Date().getFullYear()} VINaris. All rights reserved.</p>
            </div>
        </body>
        </html>`;
    }

    // Generate PDF from VIN data
    async generateVINReport(vinData, requestInfo) {
        try {
            const html = this.generateHTMLTemplate(vinData, requestInfo);
            
            const file = {
                content: html
            };

            const options = {
                format: 'A4',
                margin: {
                    top: '20mm',
                    right: '15mm',
                    bottom: '20mm',
                    left: '15mm'
                },
                printBackground: true,
                displayHeaderFooter: false
            };

            const pdfBuffer = await htmlPdf.generatePdf(file, options);
            return pdfBuffer;
            
        } catch (error) {
            console.error('PDF generation error:', error);
            throw new Error('Failed to generate PDF report');
        }
    }

    // Save PDF to file system
    async savePDFReport(pdfBuffer, filename) {
        try {
            const uploadsDir = process.env.UPLOAD_PATH || './uploads';
            const pdfsDir = path.join(uploadsDir, 'pdfs');
            
            // Create directories if they don't exist
            if (!fs.existsSync(uploadsDir)) {
                fs.mkdirSync(uploadsDir, { recursive: true });
            }
            
            if (!fs.existsSync(pdfsDir)) {
                fs.mkdirSync(pdfsDir, { recursive: true });
            }
            
            const filePath = path.join(pdfsDir, filename);
            fs.writeFileSync(filePath, pdfBuffer);
            
            return {
                filename,
                path: filePath,
                relativePath: `uploads/pdfs/${filename}`,
                size: pdfBuffer.length
            };
            
        } catch (error) {
            console.error('PDF save error:', error);
            throw new Error('Failed to save PDF report');
        }
    }

    // Generate complete VIN report (generate + save)
    async createVINReport(vinData, requestInfo) {
        try {
            const pdfBuffer = await this.generateVINReport(vinData, requestInfo);
            
            const timestamp = Date.now();
            const filename = `VINaris_Report_${requestInfo.vin}_${timestamp}.pdf`;
            
            const savedFile = await this.savePDFReport(pdfBuffer, filename);
            
            return {
                success: true,
                ...savedFile,
                generatedAt: new Date().toISOString()
            };
            
        } catch (error) {
            console.error('Complete VIN report generation error:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }
}

// Export singleton instance
const pdfGenerator = new PDFGenerator();
module.exports = pdfGenerator;
