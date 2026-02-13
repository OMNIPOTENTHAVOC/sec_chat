# 🔐 Secure Encrypted Chatroom

**End-to-end encrypted group chat with military-grade cryptography**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-40%2B%20passing-brightgreen.svg)](tests/)

A production-grade secure chat system built from scratch using **X25519 ECDH**, **HKDF**, and **AES-256-GCM**. Zero-knowledge server architecture ensures your messages stay private.

**[View Demo](#quick-demo)** | **[Deploy for Friends](#deployment-guide)** | **[Architecture](ARCHITECTURE.md)** | **[Roadmap](#roadmap)**

---

## 🌟 Features

### ✅ Current Features

- **🔒 End-to-End Encryption**: Messages encrypted on your device, server never sees plaintext
- **👥 Group Chat**: Multi-party key establishment (3+ participants)
- **🛡️ Replay Attack Protection**: Sequence numbers + sliding window detection
- **🔐 Forward Secrecy**: Unique ephemeral keys per room
- **📡 TLS 1.3**: Encrypted transport layer
- **✅ AEAD Authentication**: AES-256-GCM prevents message tampering
- **🧪 40+ Security Tests**: Comprehensive test suite (all passing)
- **🎯 Zero-Knowledge Server**: Server is untrusted relay, can't decrypt messages

### 🚀 Coming Soon (Roadmap)

- **🔄 Message Ratcheting**: Per-message forward secrecy (Signal Protocol)
- **📱 Web Interface**: Browser-based GUI
- **💾 Message History**: Encrypted persistence with client-side decryption
- **🔔 Push Notifications**: Real-time alerts
- **📎 File Sharing**: Encrypted file transfers
- **👤 User Profiles**: Avatars, status, typing indicators
- **🌍 Public Rooms**: Discoverable public channels
- **🔗 Invite Links**: Easy room sharing
- **📊 Admin Dashboard**: Server monitoring and management

---

## 🎬 Quick Demo

**See it in action in under 2 minutes:**

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Generate certificates
python certs/generate_certs.py

# 3. Run automated demo (shows 3-party encrypted chat)
python demo.py
```

**Expected output:**
```
✅ All clients connected via TLS
✅ All clients derived IDENTICAL room key
✅ All messages sent and received
✅ Replay attack BLOCKED
```

---

## 📦 Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Setup

```bash
# 1. Clone the repository
git clone https://github.com/OMNIPOTENTHAVOC/secure-chat.git
cd secure-chat

# 2. Install dependencies
pip install -r requirements.txt

# 3. Generate TLS certificates
python certs/generate_certs.py
```

---

## 🚀 Usage

### Local Testing (Safe, No Internet Exposure)

**Terminal 1 - Start Server:**
```bash
python server/server_complete.py
```

**Terminal 2 - Client (Alice):**
```bash
python client/client_complete.py
Enter your username: alice
> /join lobby
> Hello everyone!
```

**Terminal 3 - Client (Bob):**
```bash
python client/client_complete.py
Enter your username: bob
> /join lobby
> Hi Alice!
```

### Commands

```
/join <room>    - Join a chatroom
/quit           - Exit
<message>       - Send message (no command needed)
```

---

## 🌐 Deployment Guide

### Deploy So Friends Can Join (Internet-Accessible)

#### Option 1: Quick Deploy (Home Server/VPS)

**Step 1: Update Server Configuration**

Edit `server/server_complete.py`:

```python
# Change this line (around line 60):
self.host = "0.0.0.0"  # Accept connections from anywhere (was "localhost")
```

**Step 2: Get Your IP Address**

```bash
# Public IP (for internet)
curl ifconfig.me

# Or local IP (for LAN only)
hostname -I
```

**Step 3: Configure Firewall**

```bash
# Allow port 4443
sudo ufw allow 4443/tcp
sudo ufw enable
```

**Step 4: Start Server**

```bash
python server/server_complete.py
```

**Step 5: Friends Connect**

Your friends edit `client/client_complete.py`:

```python
# Change line 380:
client = ClientProtocol(client_id, "YOUR.PUBLIC.IP", 4443)
```

Then they run:
```bash
python client/client_complete.py
```

---

#### Option 2: Production Deploy (Recommended for Public Use)

**Prerequisites:**
- Domain name (e.g., `chat.yourdomain.com`)
- VPS (DigitalOcean, AWS, etc.)

**Step 1: Get Real SSL Certificates**

```bash
# Install certbot
sudo apt install certbot

# Get free Let's Encrypt certificates
sudo certbot certonly --standalone -d chat.yourdomain.com
```

**Step 2: Update Server to Use Real Certs**

Edit `server/server_complete.py`:

```python
def start(self, 
          cert_path: str = "/etc/letsencrypt/live/chat.yourdomain.com/fullchain.pem",
          key_path: str = "/etc/letsencrypt/live/chat.yourdomain.com/privkey.pem",
          ca_cert_path: str = "/etc/letsencrypt/live/chat.yourdomain.com/chain.pem"):
```

**Step 3: Run as Service (Ubuntu/Debian)**

Create `/etc/systemd/system/secure-chat.service`:

```ini
[Unit]
Description=Secure Chat Server
After=network.target

[Service]
Type=simple
User=youruser
WorkingDirectory=/home/youruser/secure-chat
ExecStart=/usr/bin/python3 /home/youruser/secure-chat/server/server_complete.py
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable secure-chat
sudo systemctl start secure-chat
sudo systemctl status secure-chat
```

**Step 4: Friends Connect to Your Domain**

```python
# In client/client_complete.py:
client = ClientProtocol(client_id, "chat.yourdomain.com", 4443)
```

---

### Option 3: Docker Deploy (Easiest)

**Create `Dockerfile`:**

```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN python certs/generate_certs.py

EXPOSE 4443

CMD ["python", "server/server_complete.py"]
```

**Build and Run:**

```bash
# Build image
docker build -t secure-chat .

# Run container
docker run -d -p 4443:4443 --name chat-server secure-chat

# View logs
docker logs -f chat-server
```

**Deploy to Cloud:**

```bash
# Tag for Docker Hub
docker tag secure-chat yourusername/secure-chat:latest

# Push
docker push yourusername/secure-chat:latest

# Deploy anywhere (DigitalOcean, AWS, etc.)
```

---

## 🧪 Testing

### Run All Tests

```bash
pytest tests/test_complete.py -v
```

**Expected: 40+ tests passing**

### Run Specific Test Categories

```bash
# Cryptography tests only
pytest tests/test_complete.py::TestCryptoEngine -v

# Replay protection tests
pytest tests/test_complete.py::TestReplayProtection -v

# Integration tests
pytest tests/test_complete.py::TestEndToEnd -v
```

---

## 📁 Project Structure

```
secure-chat/
├── client/
│   └── client_complete.py       # Complete client implementation
├── server/
│   └── server_complete.py       # Complete server implementation
├── common/
│   ├── crypto.py               # Encryption engine (X25519, HKDF, AES-GCM)
│   ├── protocol.py             # Message protocol & replay protection
│   └── client_state.py         # Session state management
├── tests/
│   └── test_complete.py        # 40+ security tests
├── certs/
│   └── generate_certs.py       # Certificate generator
├── demo.py                     # Automated demo
├── requirements.txt            # Python dependencies
└── README.md                   # This file
```

---

## 🔐 Security

### Cryptographic Primitives

| Component | Algorithm | Standard |
|-----------|-----------|----------|
| **Key Exchange** | X25519 ECDH | RFC 7748 |
| **Key Derivation** | HKDF-SHA256 | RFC 5869 |
| **Encryption** | AES-256-GCM | NIST SP 800-38D |
| **Transport** | TLS 1.3 | RFC 8446 |

### Security Properties

- ✅ **Confidentiality**: All messages encrypted end-to-end
- ✅ **Integrity**: AEAD authentication detects tampering
- ✅ **Replay Protection**: Sequence numbers prevent replay attacks
- ✅ **Forward Secrecy**: Unique ephemeral keys per room
- ✅ **Zero-Knowledge Server**: Server never sees plaintext or keys

### What This Protects Against

| Threat | Protected | Mechanism |
|--------|-----------|-----------|
| Network eavesdropping | ✅ Yes | TLS + E2E encryption |
| Man-in-the-middle | ✅ Yes | TLS certificate validation |
| Replay attacks | ✅ Yes | Sequence numbers + sliding window |
| Message tampering | ✅ Yes | AEAD authentication tags |
| Server compromise | ✅ Yes | Zero-knowledge architecture |

### Known Limitations

| Limitation | Impact | Future Fix |
|------------|--------|------------|
| No per-message ratcheting | Room key compromise affects all messages | Implement Double Ratchet |
| Metadata visible to server | Server sees who joins which room | Use anonymity network (Tor) |
| No deniability | Recipients can prove sender | Add deniable authentication |
| Self-signed certs (default) | MITM possible without verification | Use Let's Encrypt in production |

---

## 🛠️ Roadmap

### Phase 1: Core Improvements (Q1 2026)
- [ ] **Message Ratcheting** - Per-message forward secrecy (Signal Protocol)
- [ ] **Rate Limiting** - DoS protection (100 msgs/minute per user)
- [ ] **User Authentication** - Password/token-based auth
- [ ] **Production Certs** - Let's Encrypt integration
- [ ] **Logging & Monitoring** - Security event tracking

### Phase 2: Usability (Q2 2026)
- [ ] **Web Interface** - Browser-based GUI (React + WebSockets)
- [ ] **Mobile App** - iOS/Android clients
- [ ] **File Sharing** - Encrypted file transfers (up to 100MB)
- [ ] **Message History** - Encrypted persistence
- [ ] **User Profiles** - Avatars, status, display names

### Phase 3: Advanced Features (Q3 2026)
- [ ] **Voice/Video Calls** - WebRTC with E2E encryption
- [ ] **Public Rooms** - Discoverable channels
- [ ] **Invite Links** - Easy room sharing
- [ ] **Multi-Device Sync** - Cross-device key management
- [ ] **Push Notifications** - Real-time alerts

### Phase 4: Enterprise (Q4 2026)
- [ ] **Admin Dashboard** - Server management UI
- [ ] **Compliance Tools** - Audit logs, data export
- [ ] **LDAP/SSO Integration** - Enterprise authentication
- [ ] **On-Premise Deployment** - Self-hosted enterprise edition
- [ ] **API** - REST API for integrations

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

### Feature Requests
- Open an issue with the `enhancement` label
- Describe the feature and why it's useful
- If implementing Signal Protocol features, reference the spec

### Bug Reports
- Open an issue with the `bug` label
- Include steps to reproduce
- Include error logs and Python version

### Pull Requests
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests if applicable
5. Ensure all tests pass (`pytest tests/test_complete.py -v`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

### Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR-USERNAME/secure-chat.git
cd secure-chat

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dev dependencies
pip install -r requirements.txt
pip install pytest-cov black flake8

# Run tests with coverage
pytest tests/test_complete.py -v --cov=.

# Format code
black .
```

---

## 📚 Documentation

- **[ARCHITECTURE.md](ARCHITECTURE.md)** - Technical deep dive, cryptographic design
- **[TESTING_GUIDE.md](TESTING_GUIDE.md)** - Test documentation and security validation
- **[DEPLOYMENT.md](DEPLOYMENT.md)** - Production deployment guide *(coming soon)*
- **[API.md](API.md)** - API documentation *(coming soon)*

---

## 📖 Learn More

### Cryptography Resources
- [RFC 7748](https://tools.ietf.org/html/rfc7748) - X25519 Elliptic Curve Diffie-Hellman
- [RFC 5869](https://tools.ietf.org/html/rfc5869) - HKDF Key Derivation
- [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf) - AES-GCM Specification
- [Signal Protocol](https://signal.org/docs/) - Double Ratchet Algorithm

### Books
- "Serious Cryptography" by Jean-Philippe Aumasson
- "Cryptography Engineering" by Ferguson, Schneier, Kohno
- "Real-World Cryptography" by David Wong

### Similar Projects
- [Signal](https://github.com/signalapp) - E2E encrypted messaging (gold standard)
- [Matrix](https://github.com/matrix-org) - Federated E2E encrypted chat
- [Wire](https://github.com/wireapp) - Secure collaboration platform

---

## ⚖️ License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2026 Siddhansh Srivastava

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 👤 Author

**Siddhansh Srivastava** (OMNIPOTENTHAVOC)

- GitHub: [@OMNIPOTENTHAVOC](https://github.com/OMNIPOTENTHAVOC)
- LinkedIn: [Siddhansh Srivastava](https://www.linkedin.com/in/siddhansh-srivastava-86214a326/)
- Email: [Your Email]

---

## 🙏 Acknowledgments

Built with:
- [cryptography](https://cryptography.io/) - Python Cryptographic Authority
- [pytest](https://pytest.org/) - Testing framework

Inspired by:
- [Signal Protocol](https://signal.org/docs/) - E2E encryption standard
- [Matrix Protocol](https://matrix.org/) - Federated secure messaging
- [OTR Messaging](https://otr.cypherpunks.ca/) - Off-the-Record messaging

---

## ⭐ Star This Repository

If you found this project useful or learned something from it, please consider giving it a star! ⭐

It helps others discover this project and motivates continued development.

---

## 🚀 Quick Links

- **[Installation](#installation)** - Get started in 5 minutes
- **[Local Testing](#local-testing-safe-no-internet-exposure)** - Try it safely
- **[Deploy for Friends](#deployment-guide)** - Host your own server
- **[Roadmap](#roadmap)** - See what's coming
- **[Contributing](#contributing)** - Help improve the project

---

**Built with ❤️ and 🔐 by Siddhansh Srivastava**

*Understanding failure is the foundation of security.*
