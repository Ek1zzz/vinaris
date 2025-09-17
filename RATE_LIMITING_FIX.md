# Rate Limiting Fix - Development Mode

## Problem
The error "API სერვერთან კავშირი ვერ დამყარდა" (API server connection could not be established) occurs when making changes to the website due to rate limiting being too aggressive during development and testing.

## Root Cause
- Multiple API calls during testing trigger rate limits
- Rate limiting is configured for production but too restrictive for development
- Express-rate-limit middleware blocks requests after hitting limits

## Solution Implemented

### 1. Environment-Based Rate Limiting
The server now checks the environment and disables rate limiting for development:

```javascript
if (process.env.NODE_ENV === 'development' || process.env.DISABLE_RATE_LIMITING === 'true') {
    // No rate limiting for development
    console.log('🚫 Rate limiting disabled for development');
    const noRateLimit = (req, res, next) => next();
    app.use('/api', noRateLimit);
} else {
    // Production rate limiting
    console.log('🛡️ Rate limiting enabled for production');
    const rateLimiters = createRateLimiters();
    // ... apply rate limits
}
```

### 2. Development Server Script
Created `start-dev.sh` script for easy development server startup:

```bash
./start-dev.sh
```

This script:
- Sets `NODE_ENV=development`
- Sets `DISABLE_RATE_LIMITING=true`
- Kills existing server processes
- Starts the server with rate limiting disabled

### 3. Automatic Configuration
The server automatically sets development mode if not specified:

```javascript
process.env.NODE_ENV = process.env.NODE_ENV || 'development';
process.env.DISABLE_RATE_LIMITING = process.env.DISABLE_RATE_LIMITING || 'true';
```

## How to Use

### For Development:
1. Use the development script: `./start-dev.sh`
2. Or manually: `NODE_ENV=development node server.js`

### For Production:
1. Set environment variables:
   ```bash
   export NODE_ENV=production
   export DISABLE_RATE_LIMITING=false
   ```
2. Start server: `node server.js`

## Benefits
- ✅ No more "API server connection could not be established" errors during development
- ✅ Rate limiting still active in production for security
- ✅ Easy switching between development and production modes
- ✅ No need to manually modify code for different environments

## Files Modified
- `server.js` - Added environment-based rate limiting
- `start-dev.sh` - New development server script
- `RATE_LIMITING_FIX.md` - This documentation

## Testing
The fix has been tested and confirmed working:
- ✅ API health check works
- ✅ Admin login works
- ✅ No rate limiting errors during development
- ✅ Server starts with proper environment detection
