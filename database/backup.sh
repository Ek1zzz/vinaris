#!/bin/bash

# VINaris Database Backup Script
# Creates timestamped backups of the SQLite database

# Configuration
DB_PATH="./vinaris.db"
BACKUP_DIR="./backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_NAME="vinaris_backup_${TIMESTAMP}.sql"
COMPRESSED_NAME="vinaris_backup_${TIMESTAMP}.sql.gz"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔄 VINaris Database Backup Script${NC}"
echo "======================================"

# Create backup directory if it doesn't exist
if [ ! -d "$BACKUP_DIR" ]; then
    echo -e "${YELLOW}📁 Creating backup directory...${NC}"
    mkdir -p "$BACKUP_DIR"
fi

# Check if database exists
if [ ! -f "$DB_PATH" ]; then
    echo -e "${RED}❌ Database file not found: $DB_PATH${NC}"
    exit 1
fi

echo -e "${BLUE}📦 Creating backup: $BACKUP_NAME${NC}"

# Create SQL dump
sqlite3 "$DB_PATH" ".dump" > "$BACKUP_DIR/$BACKUP_NAME"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ SQL dump created successfully${NC}"
    
    # Compress the backup
    echo -e "${BLUE}🗜️  Compressing backup...${NC}"
    gzip "$BACKUP_DIR/$BACKUP_NAME"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Backup compressed: $COMPRESSED_NAME${NC}"
        
        # Show backup info
        BACKUP_SIZE=$(ls -lh "$BACKUP_DIR/$COMPRESSED_NAME" | awk '{print $5}')
        echo -e "${GREEN}📊 Backup size: $BACKUP_SIZE${NC}"
        
        # Show total backups
        BACKUP_COUNT=$(ls -1 "$BACKUP_DIR"/*.gz 2>/dev/null | wc -l)
        echo -e "${GREEN}📁 Total backups: $BACKUP_COUNT${NC}"
        
        # Cleanup old backups (keep last 10)
        echo -e "${YELLOW}🧹 Cleaning up old backups (keeping last 10)...${NC}"
        ls -1t "$BACKUP_DIR"/*.gz 2>/dev/null | tail -n +11 | xargs -r rm
        
        echo -e "${GREEN}✅ Backup completed successfully!${NC}"
        echo -e "${GREEN}📍 Location: $BACKUP_DIR/$COMPRESSED_NAME${NC}"
        
    else
        echo -e "${RED}❌ Failed to compress backup${NC}"
        exit 1
    fi
else
    echo -e "${RED}❌ Failed to create SQL dump${NC}"
    exit 1
fi

# Show recent backups
echo ""
echo -e "${BLUE}📋 Recent Backups:${NC}"
ls -lt "$BACKUP_DIR"/*.gz 2>/dev/null | head -5 | while read -r line; do
    echo -e "${GREEN}   $line${NC}"
done

echo ""
echo -e "${BLUE}💡 To restore a backup:${NC}"
echo "   gunzip backup_file.sql.gz"
echo "   sqlite3 new_database.db < backup_file.sql"
