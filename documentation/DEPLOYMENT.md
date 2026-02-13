# 🌐 Deployment Guide - Host Your Own Secure Chat

This guide shows you how to deploy your secure chat server so friends can connect from anywhere on the internet.

---

## 📋 Table of Contents

1. [Quick Setup (Home Network)](#quick-setup-home-network)
2. [Production Deployment (VPS)](#production-deployment-vps)
3. [Docker Deployment](#docker-deployment)
4. [Security Hardening](#security-hardening)
5. [Troubleshooting](#troubleshooting)

---

## 🏠 Quick Setup (Home Network)

**Perfect for:** Testing with friends on different networks, learning deployment

**Requirements:**
- Computer that stays on
- Internet connection
- Router access (for port forwarding)

### Step 1: Prepare Your Server

```bash
cd secure-chat

# Make sure everything works locally first
python certs/generate_certs.py
pytest tests/test_complete.py -v
```

### Step 2: Enable Internet Access

Edit `server/server_complete.py` line ~60:

```python
# Change from:
self.host = "localhost"

# To:
self.host = "0.0.0.0"  # Accept connections from anywhere
```

### Step 3: Configure Your Router (Port Forwarding)

1. **Find your local IP:**
   ```bash
   # Linux/Mac
   hostname -I
   
   # Windows
   ipconfig
   ```
   Example: `192.168.1.100`

2. **Log into your router:**
   - Open browser to `192.168.1.1` (or `192.168.0.1`)
   - Login (username/password usually on router sticker)

3. **Set up port forwarding:**
   - Find "Port Forwarding" section
   - Add new rule:
     - **External Port:** 4443
     - **Internal Port:** 4443
     - **Internal IP:** Your local IP (e.g., `192.168.1.100`)
     - **Protocol:** TCP
   - Save

4. **Find your public IP:**
   ```bash
   curl ifconfig.me
   ```
   Example: `203.0.113.42`

### Step 4: Configure Firewall

```bash
# Ubuntu/Debian
sudo ufw allow 4443/tcp
sudo ufw enable

# CentOS/RHEL
sudo firewall-cmd --permanent --add-port=4443/tcp
sudo firewall-cmd --reload

# Windows
# Control Panel → Windows Defender Firewall → Advanced Settings
# Inbound Rules → New Rule → Port → TCP 4443 → Allow
```

### Step 5: Start Server

```bash
python server/server_complete.py
```

You should see:
```
[SERVER] ✅ Server running
[SERVER] Waiting for client connections...
```

### Step 6: Friends Connect

Your friends edit `client/client_complete.py` line ~380:

```python
# Change from:
client = ClientProtocol(client_id, "localhost", 4443)

# To:
client = ClientProtocol(client_id, "203.0.113.42", 4443)  # Your public IP
```

Then they run:
```bash
python client/client_complete.py
```

### ⚠️ Limitations of Home Hosting

- ❌ IP changes when router reboots (use Dynamic DNS to fix)
- ❌ ISP may block incoming connections
- ❌ Limited bandwidth
- ❌ Computer must stay on 24/7
- ⚠️ Your home IP is exposed to friends

**Solution:** Use a VPS for reliable hosting (see below)

---

## ☁️ Production Deployment (VPS)

**Perfect for:** Reliable 24/7 hosting, better performance, privacy

**Recommended VPS Providers:**
- **DigitalOcean** - $5/month, easy to use
- **Linode** - $5/month, reliable
- **Vultr** - $3.50/month, fast
- **AWS Lightsail** - $3.50/month
- **Hetzner** - €4/month, excellent value

### Step 1: Create VPS

1. Sign up for a VPS provider
2. Create a **Droplet/Instance**:
   - **OS:** Ubuntu 22.04 LTS
   - **Size:** 1GB RAM ($5/month is enough)
   - **Region:** Closest to you/friends
3. Note your **server IP** (e.g., `203.0.113.42`)

### Step 2: Connect to VPS

```bash
ssh root@203.0.113.42
```

### Step 3: Install Dependencies

```bash
# Update system
apt update && apt upgrade -y

# Install Python and git
apt install python3 python3-pip git -y

# Install required packages
pip3 install cryptography pytest
```

### Step 4: Deploy Your Code

```bash
# Clone your repository
git clone https://github.com/OMNIPOTENTHAVOC/secure-chat.git
cd secure-chat

# Generate certificates
python3 certs/generate_certs.py

# Test it works
python3 -m pytest tests/test_complete.py -v
```

### Step 5: Enable Internet Access

Edit `server/server_complete.py`:

```python
self.host = "0.0.0.0"
```

### Step 6: Configure Firewall

```bash
# Enable firewall
ufw allow 22/tcp    # SSH (keep this or you'll lock yourself out!)
ufw allow 4443/tcp  # Your chat server
ufw enable
```

### Step 7: Run as Background Service

Create `/etc/systemd/system/secure-chat.service`:

```bash
sudo nano /etc/systemd/system/secure-chat.service
```

Paste this:

```ini
[Unit]
Description=Secure Chat Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/secure-chat
ExecStart=/usr/bin/python3 /root/secure-chat/server/server_complete.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable secure-chat
sudo systemctl start secure-chat
sudo systemctl status secure-chat
```

Should see:
```
● secure-chat.service - Secure Chat Server
   Active: active (running)
```

### Step 8: View Logs

```bash
# Real-time logs
sudo journalctl -u secure-chat -f

# Last 50 lines
sudo journalctl -u secure-chat -n 50
```

### Step 9: Friends Connect

Friends edit `client/client_complete.py`:

```python
client = ClientProtocol(client_id, "203.0.113.42", 4443)  # Your VPS IP
```

---

## 🐳 Docker Deployment

**Perfect for:** Easy deployment, consistency across environments

### Step 1: Create Dockerfile

In your `secure-chat/` directory, create `Dockerfile`:

```dockerfile
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Generate certificates on first run
RUN python certs/generate_certs.py

# Expose port
EXPOSE 4443

# Run server
CMD ["python", "server/server_complete.py"]
```

### Step 2: Create docker-compose.yml

```yaml
version: '3.8'

services:
  secure-chat:
    build: .
    ports:
      - "4443:4443"
    restart: unless-stopped
    volumes:
      - ./certs:/app/certs
    environment:
      - PYTHONUNBUFFERED=1
```

### Step 3: Build and Run

```bash
# Build
docker-compose build

# Start
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

### Step 4: Deploy to Cloud

**Option A: Docker Hub**

```bash
# Login to Docker Hub
docker login

# Tag image
docker tag secure-chat yourusername/secure-chat:latest

# Push
docker push yourusername/secure-chat:latest

# Deploy anywhere
docker pull yourusername/secure-chat:latest
docker run -d -p 4443:4443 yourusername/secure-chat:latest
```

**Option B: DigitalOcean App Platform**

1. Go to DigitalOcean → App Platform
2. Click "Create App"
3. Select "Docker Hub" or "GitHub"
4. Configure:
   - **Port:** 4443
   - **Health Check:** None (optional: add later)
5. Deploy!

---

## 🔒 Security Hardening

### 1. Use Real SSL Certificates (Recommended)

**Get free certificates from Let's Encrypt:**

```bash
# Install certbot
sudo apt install certbot

# Stop your server temporarily
sudo systemctl stop secure-chat

# Get certificates (replace with your domain)
sudo certbot certonly --standalone -d chat.yourdomain.com

# Certificates will be in:
# /etc/letsencrypt/live/chat.yourdomain.com/
```

**Update server to use them:**

Edit `server/server_complete.py`:

```python
def start(self, 
          cert_path: str = "/etc/letsencrypt/live/chat.yourdomain.com/fullchain.pem",
          key_path: str = "/etc/letsencrypt/live/chat.yourdomain.com/privkey.pem",
          ca_cert_path: str = "/etc/letsencrypt/live/chat.yourdomain.com/chain.pem"):
```

**Auto-renewal:**

```bash
# Test renewal
sudo certbot renew --dry-run

# Add to crontab
sudo crontab -e

# Add this line:
0 3 * * * certbot renew --quiet --post-hook "systemctl restart secure-chat"
```

### 2. Add Rate Limiting

Edit `server/server_complete.py`, add this class:

```python
from collections import defaultdict
import time

class RateLimiter:
    """Prevent DoS attacks by limiting requests per client."""
    
    def __init__(self, max_requests=100, window=60):
        self.requests = defaultdict(list)
        self.max_requests = max_requests
        self.window = window
        self.lock = threading.Lock()
    
    def allow(self, client_id: str) -> bool:
        """Check if client is within rate limit."""
        with self.lock:
            now = time.time()
            
            # Remove old requests outside window
            self.requests[client_id] = [
                t for t in self.requests[client_id] 
                if now - t < self.window
            ]
            
            # Check limit
            if len(self.requests[client_id]) >= self.max_requests:
                return False
            
            # Record request
            self.requests[client_id].append(now)
            return True
```

Then in `ServerProtocol.__init__`:

```python
self.rate_limiter = RateLimiter(max_requests=100, window=60)
```

And in `_handle_client` before processing messages:

```python
if not self.rate_limiter.allow(client_id):
    print(f"[SERVER] ⚠️ Rate limit exceeded for {client_id}")
    return
```

### 3. Add Password Authentication

Create `auth.py` in `common/`:

```python
import hashlib
import secrets

class Authenticator:
    """Simple password authentication."""
    
    def __init__(self):
        # In production, use a database
        self.users = {}
    
    def register(self, username: str, password: str) -> bool:
        """Register new user."""
        if username in self.users:
            return False
        
        salt = secrets.token_hex(16)
        password_hash = self._hash_password(password, salt)
        self.users[username] = (password_hash, salt)
        return True
    
    def authenticate(self, username: str, password: str) -> bool:
        """Verify password."""
        if username not in self.users:
            return False
        
        stored_hash, salt = self.users[username]
        password_hash = self._hash_password(password, salt)
        return password_hash == stored_hash
    
    def _hash_password(self, password: str, salt: str) -> str:
        """Hash password with salt."""
        return hashlib.pbkdf2_hmac('sha256', 
                                   password.encode(), 
                                   salt.encode(), 
                                   100000).hex()
```

### 4. Enable Logging

Add to `server/server_complete.py`:

```python
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('server.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

# Use throughout code:
logger.info(f"Client connected: {client_id}")
logger.warning(f"Failed authentication: {client_id}")
logger.error(f"Error processing message: {e}")
```

### 5. Monitor Your Server

```bash
# Install monitoring tools
sudo apt install htop nethogs

# Check resource usage
htop

# Check network usage
sudo nethogs

# Check who's connected
sudo netstat -tulpn | grep :4443
```

---

## 🐛 Troubleshooting

### Friends Can't Connect

**Check 1: Is server running?**
```bash
sudo systemctl status secure-chat
```

**Check 2: Is port open?**
```bash
# On server
sudo netstat -tulpn | grep :4443

# From friend's computer
telnet YOUR_SERVER_IP 4443
```

**Check 3: Firewall blocking?**
```bash
sudo ufw status
# Should show: 4443/tcp ALLOW
```

**Check 4: Wrong IP in client?**
- Make sure friends use your PUBLIC IP, not 127.0.0.1 or localhost

### Certificate Errors

**Error:** "Certificate verify failed"

**Fix:** Make sure all clients have the same CA certificate, or use real Let's Encrypt certs.

### Port Already in Use

**Error:** "Address already in use"

**Fix:**
```bash
# Find what's using port 4443
sudo lsof -i :4443

# Kill it
sudo kill -9 <PID>

# Or use different port in server_complete.py:
self.port = 4444
```

### Server Crashes

**Check logs:**
```bash
sudo journalctl -u secure-chat -n 100
```

**Common issues:**
- Out of memory (upgrade VPS)
- Certificate files missing
- Port permission denied (run as root or use port > 1024)

---

## 📊 Performance Optimization

### For 100+ Concurrent Users

**1. Increase System Limits**

Edit `/etc/security/limits.conf`:
```
* soft nofile 65536
* hard nofile 65536
```

**2. Use nginx Reverse Proxy**

```nginx
upstream secure_chat {
    server 127.0.0.1:4443;
}

server {
    listen 443 ssl;
    server_name chat.yourdomain.com;
    
    ssl_certificate /etc/letsencrypt/live/chat.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/chat.yourdomain.com/privkey.pem;
    
    location / {
        proxy_pass https://secure_chat;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

**3. Enable Connection Pooling**

Future improvement: Implement async/await instead of threading.

---

## ✅ Deployment Checklist

Before going live:

- [ ] Server accessible from internet
- [ ] Firewall configured (port 4443 open)
- [ ] SSL certificates installed (Let's Encrypt recommended)
- [ ] Rate limiting enabled
- [ ] Logging configured
- [ ] Monitoring set up
- [ ] Backup plan (save certificates, config)
- [ ] Test with friends
- [ ] Document your server IP/domain for friends

---

## 🎯 Next Steps

Once deployed:

1. **Share with friends:**
   - Give them your server IP or domain
   - Help them configure their client
   - Create a shared room

2. **Monitor usage:**
   - Check logs regularly
   - Watch for attacks or abuse
   - Monitor resource usage

3. **Implement roadmap features:**
   - Add web interface
   - Enable file sharing
   - Add message history

---

**Need help?** Open an issue on GitHub: https://github.com/OMNIPOTENTHAVOC/secure-chat/issues
