/**
 * VIN Data Integration Service
 * Integrates with multiple VIN data providers for comprehensive vehicle information
 */

const axios = require('axios');
const db = require('../database/db-helper');

class VINDataService {
    constructor() {
        this.sources = {
            nhtsa: {
                name: 'NHTSA',
                baseUrl: 'https://vpic.nhtsa.dot.gov/api',
                apiKey: null, // NHTSA is free
                enabled: true,
                priority: 1
            },
            vinaudit: {
                name: 'VinAudit',
                baseUrl: 'https://www.vinaudit.com/vin-check-api',
                apiKey: process.env.VINAUDIT_API_KEY,
                enabled: !!process.env.VINAUDIT_API_KEY,
                priority: 2
            },
            carmd: {
                name: 'CarMD',
                baseUrl: 'https://api.carmd.com/v3.0',
                apiKey: process.env.CARMD_API_KEY,
                enabled: !!process.env.CARMD_API_KEY,
                priority: 3
            }
        };
    }

    // Get comprehensive VIN data from multiple sources
    async getComprehensiveVINData(vin, plan = 'basic') {
        const vinUpper = vin.toUpperCase();
        
        try {
            // Check cache first
            const cachedData = await this.getCachedData(vinUpper);
            if (cachedData && !this.isCacheExpired(cachedData)) {
                console.log(`📋 Using cached VIN data for ${vinUpper}`);
                return JSON.parse(cachedData.cached_data);
            }

            console.log(`🔍 Fetching fresh VIN data for ${vinUpper}`);
            
            // Fetch data from available sources based on plan
            const vinData = await this.fetchFromSources(vinUpper, plan);
            
            // Cache the result
            await this.cacheVINData(vinUpper, vinData);
            
            return vinData;
            
        } catch (error) {
            console.error('Comprehensive VIN data fetch error:', error);
            
            // Fallback to cached data even if expired
            const fallbackData = await this.getCachedData(vinUpper);
            if (fallbackData) {
                console.log(`⚠️ Using expired cached data as fallback for ${vinUpper}`);
                return JSON.parse(fallbackData.cached_data);
            }
            
            throw new Error('Unable to fetch VIN data from any source');
        }
    }

    // Fetch VIN data from multiple sources
    async fetchFromSources(vin, plan) {
        const results = {
            basic: {},
            premium: {},
            business: {},
            sources: [],
            lastUpdated: new Date().toISOString()
        };

        // Always start with NHTSA (free and reliable)
        try {
            const nthsaData = await this.fetchFromNHTSA(vin);
            if (nthsaData) {
                results.basic = { ...results.basic, ...nthsaData };
                results.sources.push('NHTSA');
                console.log('✅ NHTSA data fetched successfully');
            }
        } catch (error) {
            console.error('NHTSA fetch error:', error.message);
        }

        // For premium and business plans, fetch from additional sources
        if (plan === 'premium' || plan === 'business') {
            // Try VinAudit
            if (this.sources.vinaudit.enabled) {
                try {
                    const vinauditData = await this.fetchFromVinAudit(vin);
                    if (vinauditData) {
                        results.premium = { ...results.premium, ...vinauditData };
                        results.sources.push('VinAudit');
                        console.log('✅ VinAudit data fetched successfully');
                    }
                } catch (error) {
                    console.error('VinAudit fetch error:', error.message);
                }
            }

            // For business plan, also try CarMD
            if (plan === 'business' && this.sources.carmd.enabled) {
                try {
                    const carmdData = await this.fetchFromCarMD(vin);
                    if (carmdData) {
                        results.business = { ...results.business, ...carmdData };
                        results.sources.push('CarMD');
                        console.log('✅ CarMD data fetched successfully');
                    }
                } catch (error) {
                    console.error('CarMD fetch error:', error.message);
                }
            }
        }

        // Merge all data based on plan
        const mergedData = this.mergeVINData(results, plan);
        return mergedData;
    }

    // Fetch data from NHTSA (free government database)
    async fetchFromNHTSA(vin) {
        try {
            const response = await axios.get(
                `${this.sources.nhtsa.baseUrl}/vehicles/decodevin/${vin}?format=json`,
                { timeout: 10000 }
            );

            if (!response.data || !response.data.Results) {
                return null;
            }

            const results = response.data.Results;
            const data = {
                make: this.findValue(results, 'Make'),
                model: this.findValue(results, 'Model'),
                year: this.findValue(results, 'Model Year'),
                bodyClass: this.findValue(results, 'Body Class'),
                engineInfo: this.findValue(results, 'Engine Model'),
                engineSize: this.findValue(results, 'Displacement (L)'),
                cylinders: this.findValue(results, 'Engine Number of Cylinders'),
                transmission: this.findValue(results, 'Transmission Style'),
                driveType: this.findValue(results, 'Drive Type'),
                fuelType: this.findValue(results, 'Fuel Type - Primary'),
                vehicleType: this.findValue(results, 'Vehicle Type'),
                plantCountry: this.findValue(results, 'Plant Country'),
                manufacturer: this.findValue(results, 'Manufacturer Name'),
                series: this.findValue(results, 'Series')
            };

            // Clean up data - remove empty values
            Object.keys(data).forEach(key => {
                if (!data[key] || data[key] === 'Not Available' || data[key] === '') {
                    delete data[key];
                }
            });

            return data;
            
        } catch (error) {
            console.error('NHTSA API error:', error.message);
            return null;
        }
    }

    // Fetch data from VinAudit (premium service)
    async fetchFromVinAudit(vin) {
        if (!this.sources.vinaudit.apiKey) {
            return null;
        }

        try {
            // VinAudit API simulation (replace with actual API call)
            // const response = await axios.get(
            //     `${this.sources.vinaudit.baseUrl}/decode`,
            //     {
            //         params: { vin, key: this.sources.vinaudit.apiKey },
            //         timeout: 15000
            //     }
            // );

            // For demo, return mock premium data
            return {
                marketValue: '$15,000 - $18,000',
                accidentHistory: 'No accidents reported',
                previousOwners: '2 previous owners',
                serviceRecords: '15 service records found',
                recalls: 'No open recalls',
                theftRecord: 'Not reported stolen',
                lienRecord: 'No liens found',
                mileageHistory: 'Consistent mileage progression'
            };
            
        } catch (error) {
            console.error('VinAudit API error:', error.message);
            return null;
        }
    }

    // Fetch data from CarMD (business tier)
    async fetchFromCarMD(vin) {
        if (!this.sources.carmd.apiKey) {
            return null;
        }

        try {
            // CarMD API simulation (replace with actual API call)
            // const response = await axios.get(
            //     `${this.sources.carmd.baseUrl}/decode`,
            //     {
            //         headers: { 
            //             'authorization': `Basic ${this.sources.carmd.apiKey}`,
            //             'partner-token': process.env.CARMD_PARTNER_TOKEN
            //         },
            //         params: { vin },
            //         timeout: 15000
            //     }
            // );

            // For demo, return mock business data
            return {
                maintenanceSchedule: 'Available',
                commonProblems: ['Transmission issues at 80k+ miles', 'AC compressor replacement needed'],
                partsPricing: 'Available for 15,000+ parts',
                laborEstimates: 'Available for common repairs',
                warranties: 'Factory warranty expired',
                technicalBulletins: '3 TSBs found',
                safetyRatings: '5-star overall NHTSA rating',
                fuelEconomy: '24 city / 35 highway MPG'
            };
            
        } catch (error) {
            console.error('CarMD API error:', error.message);
            return null;
        }
    }

    // Helper function to find value in NHTSA results
    findValue(results, variable) {
        const item = results.find(r => r.Variable === variable);
        return item?.Value || null;
    }

    // Merge VIN data based on plan
    mergeVINData(results, plan) {
        let mergedData = { ...results.basic };
        
        if (plan === 'premium' || plan === 'business') {
            mergedData = { ...mergedData, ...results.premium };
        }
        
        if (plan === 'business') {
            mergedData = { ...mergedData, ...results.business };
        }

        // Add metadata
        mergedData._metadata = {
            sources: results.sources,
            plan: plan,
            lastUpdated: results.lastUpdated,
            cacheExpires: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
        };

        return mergedData;
    }

    // Get cached VIN data
    async getCachedData(vin) {
        try {
            // Check if database is already connected
            if (!db.db) {
                await db.connect();
            }
            const cached = await db.get(
                'SELECT * FROM vin_data_cache WHERE vin = ? ORDER BY created_at DESC LIMIT 1',
                [vin]
            );
            // Don't close connection here - let the caller manage it
            return cached;
        } catch (error) {
            console.error('Cache fetch error:', error);
            return null;
        }
    }

    // Check if cached data is expired
    isCacheExpired(cachedData) {
        const expiresAt = new Date(cachedData.expires_at);
        return expiresAt < new Date();
    }

    // Cache VIN data
    async cacheVINData(vin, data) {
        try {
            // Check if database is already connected
            if (!db.db) {
                await db.connect();
            }
            
            const sources = data._metadata?.sources?.join(',') || 'unknown';
            const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
            
            await db.run(`
                INSERT OR REPLACE INTO vin_data_cache (vin, data_source, cached_data, expires_at)
                VALUES (?, ?, ?, ?)
            `, [vin, sources, JSON.stringify(data), expiresAt]);
            
            // Don't close connection here - let the caller manage it
            console.log(`💾 Cached VIN data for ${vin} (expires: ${expiresAt})`);
            
        } catch (error) {
            console.error('Cache save error:', error);
        }
    }

    // Get service status
    getServiceStatus() {
        const status = {
            services: {},
            totalEnabled: 0,
            totalDisabled: 0
        };

        Object.entries(this.sources).forEach(([key, source]) => {
            status.services[key] = {
                name: source.name,
                enabled: source.enabled,
                hasApiKey: !!source.apiKey,
                priority: source.priority
            };

            if (source.enabled) {
                status.totalEnabled++;
            } else {
                status.totalDisabled++;
            }
        });

        return status;
    }

    // Validate VIN format
    static isValidVIN(vin) {
        if (!vin || typeof vin !== 'string') return false;
        
        // Remove spaces and convert to uppercase
        const cleanVIN = vin.replace(/\s/g, '').toUpperCase();
        
        // Check length
        if (cleanVIN.length !== 17) return false;
        
        // Check format (no I, O, Q characters)
        const vinPattern = /^[A-HJ-NPR-Z0-9]{17}$/;
        return vinPattern.test(cleanVIN);
    }
}

// Export singleton instance
const vinDataService = new VINDataService();
module.exports = vinDataService;
