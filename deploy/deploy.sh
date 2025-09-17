#!/bin/bash

# VINaris Production Deployment Script
# This script deploys the VINaris application to production

set -e  # Exit on any error

# Configuration
APP_NAME="vinaris"
APP_DIR="/var/www/vinaris"
BACKUP_DIR="/var/backups/vinaris"
SERVICE_NAME="vinaris-api"
NGINX_CONFIG="/etc/nginx/sites-available/vinaris.ge"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        error "This script should not be run as root for security reasons"
        exit 1
    fi
}

# Function to check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check if required commands exist
    local required_commands=("node" "npm" "git" "nginx" "systemctl")
    for cmd in "${required_commands[@]}"; do
        if ! command -v $cmd &> /dev/null; then
            error "Required command '$cmd' not found"
            exit 1
        fi
    done
    
    # Check Node.js version
    local node_version=$(node --version | cut -d'v' -f2 | cut -d'.' -f1)
    if [ "$node_version" -lt 16 ]; then
        error "Node.js version 16 or higher is required (current: $(node --version))"
        exit 1
    fi
    
    success "Prerequisites check passed"
}

# Function to create backup
create_backup() {
    log "Creating backup of current deployment..."
    
    if [ -d "$APP_DIR" ]; then
        local backup_name="backup_$(date +%Y%m%d_%H%M%S)"
        local backup_path="$BACKUP_DIR/$backup_name"
        
        mkdir -p "$backup_path"
        
        # Backup current application
        cp -r "$APP_DIR" "$backup_path/app"
        
        # Backup database if it exists
        if [ -f "$APP_DIR/database/vinaris.db" ]; then
            cp "$APP_DIR/database/vinaris.db" "$backup_path/vinaris.db"
        fi
        
        # Backup nginx config
        if [ -f "$NGINX_CONFIG" ]; then
            cp "$NGINX_CONFIG" "$backup_path/nginx.conf"
        fi
        
        success "Backup created: $backup_path"
    else
        warning "No existing deployment found, skipping backup"
    fi
}

# Function to stop services
stop_services() {
    log "Stopping services..."
    
    # Stop the application service
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        sudo systemctl stop "$SERVICE_NAME"
        success "Stopped $SERVICE_NAME service"
    fi
    
    # Reload nginx to stop serving the old version
    if systemctl is-active --quiet nginx; then
        sudo systemctl reload nginx
        success "Reloaded nginx"
    fi
}

# Function to deploy application
deploy_application() {
    log "Deploying application..."
    
    # Create application directory
    sudo mkdir -p "$APP_DIR"
    
    # Copy application files
    sudo cp -r . "$APP_DIR/"
    
    # Set proper ownership
    sudo chown -R www-data:www-data "$APP_DIR"
    
    # Set proper permissions
    sudo chmod -R 755 "$APP_DIR"
    sudo chmod -R 777 "$APP_DIR/uploads"
    sudo chmod -R 777 "$APP_DIR/logs"
    
    # Install dependencies
    cd "$APP_DIR"
    sudo -u www-data npm install --production
    
    success "Application deployed to $APP_DIR"
}

# Function to setup database
setup_database() {
    log "Setting up database..."
    
    cd "$APP_DIR"
    
    # Run database migrations
    sudo -u www-data npm run migrate
    
    # Seed initial data if needed
    if [ ! -f "$APP_DIR/database/vinaris.db" ] || [ ! -s "$APP_DIR/database/vinaris.db" ]; then
        sudo -u www-data npm run seed
        success "Database seeded with initial data"
    fi
    
    success "Database setup completed"
}

# Function to setup systemd service
setup_service() {
    log "Setting up systemd service..."
    
    # Create systemd service file
    sudo tee /etc/systemd/system/$SERVICE_NAME.service > /dev/null <<EOF
[Unit]
Description=VINaris API Service
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=$APP_DIR
Environment=NODE_ENV=production
EnvironmentFile=$APP_DIR/production.env
ExecStart=/usr/bin/node server.js
Restart=always
RestartSec=10
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=vinaris-api

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd and enable service
    sudo systemctl daemon-reload
    sudo systemctl enable "$SERVICE_NAME"
    
    success "Systemd service configured"
}

# Function to setup nginx
setup_nginx() {
    log "Setting up nginx configuration..."
    
    # Create nginx configuration
    sudo tee "$NGINX_CONFIG" > /dev/null <<EOF
server {
    listen 80;
    server_name vinaris.ge www.vinaris.ge;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name vinaris.ge www.vinaris.ge;

    # SSL Configuration (update with your certificate paths)
    ssl_certificate /etc/letsencrypt/live/vinaris.ge/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/vinaris.ge/privkey.pem;
    
    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
    
    # Rate Limiting
    limit_req_zone \$binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone \$binary_remote_addr zone=auth:10m rate=1r/s;
    
    # Main Application
    location / {
        proxy_pass http://localhost:3001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
    }
    
    # API Rate Limiting
    location /api/ {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://localhost:3001;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    # Authentication Rate Limiting
    location /api/auth/ {
        limit_req zone=auth burst=5 nodelay;
        proxy_pass http://localhost:3001;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    # Static Files
    location /static/ {
        alias $APP_DIR/public/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
    
    # Uploaded Files
    location /uploads/ {
        alias $APP_DIR/uploads/;
        expires 1d;
        add_header Cache-Control "private";
    }
}
EOF

    # Enable site
    sudo ln -sf "$NGINX_CONFIG" /etc/nginx/sites-enabled/
    
    # Test nginx configuration
    sudo nginx -t
    
    success "Nginx configuration updated"
}

# Function to setup SSL
setup_ssl() {
    log "Setting up SSL certificate..."
    
    if command -v certbot &> /dev/null; then
        sudo certbot --nginx -d vinaris.ge -d www.vinaris.ge --non-interactive --agree-tos --email admin@vinaris.ge
        success "SSL certificate configured"
    else
        warning "Certbot not found. Please install SSL certificate manually"
    fi
}

# Function to start services
start_services() {
    log "Starting services..."
    
    # Start the application service
    sudo systemctl start "$SERVICE_NAME"
    sudo systemctl status "$SERVICE_NAME" --no-pager
    
    # Reload nginx
    sudo systemctl reload nginx
    
    success "Services started successfully"
}

# Function to run health checks
run_health_checks() {
    log "Running health checks..."
    
    # Wait for service to start
    sleep 5
    
    # Check if service is running
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        success "Service is running"
    else
        error "Service failed to start"
        sudo journalctl -u "$SERVICE_NAME" --no-pager -n 20
        exit 1
    fi
    
    # Check API health endpoint
    if curl -f -s http://localhost:3001/api/health > /dev/null; then
        success "API health check passed"
    else
        error "API health check failed"
        exit 1
    fi
    
    # Check nginx
    if systemctl is-active --quiet nginx; then
        success "Nginx is running"
    else
        error "Nginx is not running"
        exit 1
    fi
}

# Function to setup monitoring
setup_monitoring() {
    log "Setting up monitoring..."
    
    # Create log rotation configuration
    sudo tee /etc/logrotate.d/vinaris > /dev/null <<EOF
$APP_DIR/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 www-data www-data
    postrotate
        systemctl reload $SERVICE_NAME
    endscript
}
EOF

    # Setup automated backups
    sudo tee /etc/cron.d/vinaris-backup > /dev/null <<EOF
0 2 * * * www-data $APP_DIR/backup/automated-backup.sh
EOF

    success "Monitoring and backup configured"
}

# Main deployment function
main() {
    log "Starting VINaris deployment..."
    
    check_root
    check_prerequisites
    create_backup
    stop_services
    deploy_application
    setup_database
    setup_service
    setup_nginx
    setup_ssl
    start_services
    run_health_checks
    setup_monitoring
    
    success "🎉 VINaris deployment completed successfully!"
    
    log "Deployment summary:"
    echo "  - Application: $APP_DIR"
    echo "  - Service: $SERVICE_NAME"
    echo "  - Nginx config: $NGINX_CONFIG"
    echo "  - SSL: Configured"
    echo "  - Monitoring: Enabled"
    echo "  - Backups: Automated"
    
    log "Next steps:"
    echo "  1. Update DNS records to point to this server"
    echo "  2. Configure email settings in production.env"
    echo "  3. Set up payment gateway credentials"
    echo "  4. Test all functionality"
    echo "  5. Monitor logs: sudo journalctl -u $SERVICE_NAME -f"
}

# Run main function
main "$@"
