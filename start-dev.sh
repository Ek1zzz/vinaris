#!/bin/bash

# VINaris Development Server Starter
# This script starts the server with development-friendly settings

echo "🚀 Starting VINaris Development Server..."

# Set development environment variables
export NODE_ENV=development
export DISABLE_RATE_LIMITING=true

# Kill any existing server processes
pkill -f "node server.js" 2>/dev/null

# Wait a moment for processes to close
sleep 2

# Start the server
echo "📡 Starting server with rate limiting disabled..."
node server.js
