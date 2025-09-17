# SSL/HTTPS Setup for VINaris Production

## 1. SSL Certificate Options

### Option A: Let's Encrypt (Recommended - Free)
```bash
# Install Certbot
sudo apt update
sudo apt install certbot python3-certbot-nginx

# Get certificate for your domain
sudo certbot --nginx -d vinaris.ge -d www.vinaris.ge

# Auto-renewal setup
sudo crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

### Option B: Commercial SSL Certificate
- Purchase from: DigiCert, Comodo, GoDaddy, etc.
- Upload to server and configure Nginx/Apache

## 2. Nginx Configuration (Recommended)

Create `/etc/nginx/sites-available/vinaris.ge`:

```nginx
server {
    listen 80;
    server_name vinaris.ge www.vinaris.ge;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name vinaris.ge www.vinaris.ge;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/vinaris.ge/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/vinaris.ge/privkey.pem;
    
    # SSL Security Settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
    
    # Rate Limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=auth:10m rate=1r/s;
    
    # Main Application
    location / {
        proxy_pass http://localhost:3001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
    
    # API Rate Limiting
    location /api/ {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://localhost:3001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Authentication Rate Limiting
    location /api/auth/ {
        limit_req zone=auth burst=5 nodelay;
        proxy_pass http://localhost:3001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Static Files
    location /static/ {
        alias /var/www/vinaris/public/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
    
    # Uploaded Files
    location /uploads/ {
        alias /var/www/vinaris/uploads/;
        expires 1d;
        add_header Cache-Control "private";
    }
}
```

## 3. Enable Site
```bash
sudo ln -s /etc/nginx/sites-available/vinaris.ge /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

## 4. Firewall Configuration
```bash
# Allow HTTPS
sudo ufw allow 443/tcp
sudo ufw allow 80/tcp

# Block direct access to Node.js port
sudo ufw deny 3001/tcp
```
