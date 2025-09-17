#!/bin/bash

# VINaris Automated Backup Script
# This script creates automated backups of the database and uploads

# Configuration
BACKUP_DIR="/var/backups/vinaris"
DB_NAME="vinaris_production"
DB_USER="vinaris_prod_user"
DB_HOST="localhost"
UPLOAD_DIR="/var/www/vinaris/uploads"
RETENTION_DAYS=30
S3_BUCKET="vinaris-backups"

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

# Generate timestamp
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="vinaris_backup_${TIMESTAMP}"

echo "🚀 Starting VINaris backup process..."
echo "📅 Timestamp: $TIMESTAMP"

# Function to log messages
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Function to handle errors
handle_error() {
    log "❌ ERROR: $1"
    exit 1
}

# Create database backup
log "🗄️ Creating database backup..."
if command -v pg_dump &> /dev/null; then
    # PostgreSQL backup
    pg_dump -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
        --no-password --format=custom --compress=9 \
        --file="$BACKUP_DIR/${BACKUP_FILE}.sql.gz" \
        || handle_error "Database backup failed"
else
    # SQLite backup (fallback)
    if [ -f "/var/www/vinaris/database/vinaris.db" ]; then
        sqlite3 /var/www/vinaris/database/vinaris.db \
            ".backup '$BACKUP_DIR/${BACKUP_FILE}.db'" \
            || handle_error "SQLite backup failed"
    else
        handle_error "No database found"
    fi
fi

# Create uploads backup
log "📁 Creating uploads backup..."
if [ -d "$UPLOAD_DIR" ]; then
    tar -czf "$BACKUP_DIR/${BACKUP_FILE}_uploads.tar.gz" \
        -C "$UPLOAD_DIR" . \
        || handle_error "Uploads backup failed"
else
    log "⚠️ Warning: Uploads directory not found: $UPLOAD_DIR"
fi

# Create configuration backup
log "⚙️ Creating configuration backup..."
tar -czf "$BACKUP_DIR/${BACKUP_FILE}_config.tar.gz" \
    -C "/var/www/vinaris" \
    production.env \
    package.json \
    server.js \
    database/schema.sql \
    || handle_error "Configuration backup failed"

# Create combined backup archive
log "📦 Creating combined backup archive..."
tar -czf "$BACKUP_DIR/${BACKUP_FILE}_complete.tar.gz" \
    -C "$BACKUP_DIR" \
    "${BACKUP_FILE}.sql.gz" \
    "${BACKUP_FILE}_uploads.tar.gz" \
    "${BACKUP_FILE}_config.tar.gz" \
    || handle_error "Combined backup failed"

# Calculate backup size
BACKUP_SIZE=$(du -h "$BACKUP_DIR/${BACKUP_FILE}_complete.tar.gz" | cut -f1)
log "✅ Backup created successfully: ${BACKUP_FILE}_complete.tar.gz (${BACKUP_SIZE})"

# Upload to S3 (if configured)
if [ ! -z "$S3_BUCKET" ] && command -v aws &> /dev/null; then
    log "☁️ Uploading backup to S3..."
    aws s3 cp "$BACKUP_DIR/${BACKUP_FILE}_complete.tar.gz" \
        "s3://$S3_BUCKET/backups/" \
        || handle_error "S3 upload failed"
    log "✅ Backup uploaded to S3 successfully"
fi

# Clean old backups
log "🧹 Cleaning old backups..."
find "$BACKUP_DIR" -name "vinaris_backup_*" -type f -mtime +$RETENTION_DAYS -delete
log "✅ Old backups cleaned (retention: $RETENTION_DAYS days)"

# Verify backup integrity
log "🔍 Verifying backup integrity..."
if tar -tzf "$BACKUP_DIR/${BACKUP_FILE}_complete.tar.gz" > /dev/null 2>&1; then
    log "✅ Backup integrity verified"
else
    handle_error "Backup integrity check failed"
fi

# Send notification (if email is configured)
if [ ! -z "$NOTIFICATION_EMAIL" ] && command -v mail &> /dev/null; then
    echo "VINaris backup completed successfully at $(date)" | \
        mail -s "VINaris Backup Success" "$NOTIFICATION_EMAIL"
fi

log "🎉 Backup process completed successfully!"
log "📊 Backup details:"
log "   - File: ${BACKUP_FILE}_complete.tar.gz"
log "   - Size: $BACKUP_SIZE"
log "   - Location: $BACKUP_DIR"

exit 0
