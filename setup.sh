#!/bin/bash
# =============================================================================
# Cyber Surakshya — One-Click Server Setup Script
# Tested on Ubuntu 22.04 / 24.04 / 26.04 LTS
# Run as root or with sudo: sudo bash setup.sh
# =============================================================================

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging
LOG_FILE="/var/log/cybersurakshya-setup.log"
exec > >(tee -a "$LOG_FILE") 2>&1

print_step() { echo -e "\n${BLUE}==>${NC} $1"; }
print_ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
print_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_err()  { echo -e "${RED}[ERROR]${NC} $1"; }

# =============================================================================
# PRE-FLIGHT CHECKS
# =============================================================================
print_step "Running pre-flight checks..."

if [ "$EUID" -ne 0 ]; then
    print_err "Please run as root: sudo bash setup.sh"
    exit 1
fi

# Detect Ubuntu version
UBUNTU_VERSION=$(lsb_release -rs)
UBUNTU_CODENAME=$(lsb_release -cs)
print_ok "Detected Ubuntu $UBUNTU_VERSION ($UBUNTU_CODENAME)"

# Auto-detect network interface (skip loopback)
NET_IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
if [ -z "$NET_IFACE" ]; then
    NET_IFACE=$(ip link show | grep -v lo | grep 'UP' | awk -F': ' '{print $2}' | head -1)
fi
print_ok "Detected network interface: $NET_IFACE"

# Auto-detect local subnet
LOCAL_IP=$(ip addr show "$NET_IFACE" | grep 'inet ' | awk '{print $2}' | head -1)
LOCAL_SUBNET=$(python3 -c "
import ipaddress
net = ipaddress.ip_interface('$LOCAL_IP').network
print(str(net))
" 2>/dev/null || echo "192.168.0.0/16")
print_ok "Detected local subnet: $LOCAL_SUBNET"

# Detect CPU cores for Zeek
CPU_CORES=$(nproc)
print_ok "Detected CPU cores: $CPU_CORES"

echo ""
echo "======================================"
echo " Cyber Surakshya Setup Configuration"
echo "======================================"
echo " Interface : $NET_IFACE"
echo " Subnet    : $LOCAL_SUBNET"
echo " CPU Cores : $CPU_CORES"
echo " Ubuntu    : $UBUNTU_VERSION"
echo "======================================"
echo ""
read -p "Proceed with setup? (y/n): " CONFIRM
if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
    echo "Setup cancelled."
    exit 0
fi

# =============================================================================
# PHASE 1 — BASE SERVER PREPARATION
# =============================================================================
print_step "PHASE 1 — Base Server Preparation"

# Update and upgrade
print_step "Updating system packages..."
apt update -y && apt upgrade -y
print_ok "System updated"

# Install essential tools
print_step "Installing essential tools..."
apt install -y curl wget git net-tools htop ufw build-essential \
    software-properties-common ca-certificates gnupg lsb-release
print_ok "Essential tools installed"

# Set hostname
print_step "Setting hostname to cybersurakshya..."
hostnamectl set-hostname cybersurakshya
print_ok "Hostname set"

# Create cybersurakshya user if not exists
if ! id "cybersurakshya" &>/dev/null; then
    print_step "Creating cybersurakshya user..."
    useradd -m -s /bin/bash -G sudo cybersurakshya
    echo "cybersurakshya:CyberSurakshya@2025" | chpasswd
    print_ok "User cybersurakshya created (default password: CyberSurakshya@2025)"
    print_warn "Please change the password after setup: sudo passwd cybersurakshya"
else
    print_ok "User cybersurakshya already exists"
fi

# Copy SSH keys if available
if [ -f /home/ubuntu/.ssh/authorized_keys ]; then
    mkdir -p /home/cybersurakshya/.ssh
    cp /home/ubuntu/.ssh/authorized_keys /home/cybersurakshya/.ssh/
    chown -R cybersurakshya:cybersurakshya /home/cybersurakshya/.ssh
    chmod 700 /home/cybersurakshya/.ssh
    chmod 600 /home/cybersurakshya/.ssh/authorized_keys
    print_ok "SSH keys copied to cybersurakshya user"
fi

# Configure UFW firewall
print_step "Configuring UFW firewall..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 8000:8010/tcp
ufw allow 4317/tcp
ufw --force enable
print_ok "UFW configured and enabled"

# Create swap file if less than 2GB RAM
TOTAL_RAM=$(free -m | awk '/^Mem:/{print $2}')
if [ "$TOTAL_RAM" -lt 2000 ] && [ ! -f /swapfile ]; then
    print_step "Low RAM detected ($TOTAL_RAM MB) — creating 2GB swap file..."
    fallocate -l 2G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
    print_ok "2GB swap file created"
else
    print_ok "RAM sufficient or swap already exists — skipping swap"
fi

print_ok "PHASE 1 COMPLETE"

# =============================================================================
# PHASE 2 — DOCKER
# =============================================================================
print_step "PHASE 2 — Docker Installation"

# Remove old Docker versions
apt remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true

# Add Docker GPG key
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
    gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

# Add Docker repository
# Use jammy for Ubuntu versions without their own Docker repo
DOCKER_CODENAME="$UBUNTU_CODENAME"
if [ "$UBUNTU_VERSION" = "26.04" ] || [ "$UBUNTU_VERSION" = "24.10" ]; then
    DOCKER_CODENAME="noble"
fi

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $DOCKER_CODENAME stable" | \
    tee /etc/apt/sources.list.d/docker.list > /dev/null

apt update -y
apt install -y docker-ce docker-ce-cli containerd.io \
    docker-buildx-plugin docker-compose-plugin

# Add users to docker group
usermod -aG docker cybersurakshya
usermod -aG docker ubuntu 2>/dev/null || true

# Enable Docker on boot
systemctl enable docker
systemctl enable containerd
systemctl start docker

print_ok "PHASE 2 COMPLETE"

# =============================================================================
# PHASE 3 — ZEEK
# =============================================================================
print_step "PHASE 3 — Zeek Installation"

# Add Zeek repository
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' | \
    tee /etc/apt/sources.list.d/zeek.list

curl -fsSL https://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/Release.key | \
    gpg --dearmor | tee /etc/apt/trusted.gpg.d/zeek.gpg > /dev/null

apt update -y
DEBIAN_FRONTEND=noninteractive apt install -y zeek
print_ok "Zeek installed"

# Add Zeek to PATH
echo 'export PATH=/opt/zeek/bin:$PATH' > /etc/profile.d/zeek.sh
export PATH=/opt/zeek/bin:$PATH

# Configure node.cfg
cat > /opt/zeek/etc/node.cfg << ZEEK_NODE
[zeek]
type=standalone
host=localhost
interface=$NET_IFACE
ZEEK_NODE
print_ok "node.cfg configured with interface $NET_IFACE"

# Configure networks.cfg
cat > /opt/zeek/etc/networks.cfg << ZEEK_NET
# Local networks
$LOCAL_SUBNET    Local Network
ZEEK_NET
print_ok "networks.cfg configured with subnet $LOCAL_SUBNET"

# Configure zeekctl.cfg
sed -i 's/^MailTo.*/MailTo =/' /opt/zeek/etc/zeekctl.cfg
sed -i 's/^MailConnectionSummary.*//' /opt/zeek/etc/zeekctl.cfg
print_ok "zeekctl.cfg configured"

# Configure JSON logging for Zeek 8+
cat >> /opt/zeek/share/zeek/site/local.zeek << ZEEK_LOCAL

# Enable JSON log output
redef LogAscii::json_timestamps = JSON::TS_ISO8601;
@load base/frameworks/logging/writers/ascii
ZEEK_LOCAL
print_ok "local.zeek configured for JSON logging"

# Add cybersurakshya to zeek group
usermod -aG zeek cybersurakshya 2>/dev/null || true

# Deploy Zeek
print_step "Deploying Zeek..."
/opt/zeek/bin/zeekctl deploy 2>/dev/null || true
sleep 5

# Create Zeek systemd service
cat > /etc/systemd/system/zeek.service << 'ZEEK_SERVICE'
[Unit]
Description=Zeek Network Monitor
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/opt/zeek/bin/zeekctl deploy
ExecStop=/opt/zeek/bin/zeekctl stop
User=root

[Install]
WantedBy=multi-user.target
ZEEK_SERVICE

systemctl daemon-reload
systemctl enable zeek
print_ok "PHASE 3 COMPLETE"

# =============================================================================
# PHASE 4 — SURICATA
# =============================================================================
print_step "PHASE 4 — Suricata Installation"

add-apt-repository -y ppa:oisf/suricata-stable
apt update -y
DEBIAN_FRONTEND=noninteractive apt install -y suricata suricata-update
print_ok "Suricata installed"

# Configure suricata.yaml
sed -i "s|HOME_NET:.*|HOME_NET: \"[$LOCAL_SUBNET]\"|" /etc/suricata/suricata.yaml
sed -i "s/interface: eth0/interface: $NET_IFACE/" /etc/suricata/suricata.yaml
sed -i '/eve-log:/,/enabled:/{s/enabled: no/enabled: yes/}' /etc/suricata/suricata.yaml
sed -i 's/community-id: false/community-id: true/' /etc/suricata/suricata.yaml
print_ok "suricata.yaml configured"

# Download rules
print_step "Downloading Suricata rules..."
suricata-update
print_ok "Suricata rules downloaded"

# Fix systemd timeout for slow rule loading
mkdir -p /etc/systemd/system/suricata.service.d/
cat > /etc/systemd/system/suricata.service.d/timeout.conf << 'SURI_TIMEOUT'
[Service]
TimeoutStartSec=300
SURI_TIMEOUT

systemctl daemon-reload
systemctl enable suricata
systemctl start suricata
print_ok "PHASE 4 COMPLETE"

# =============================================================================
# PHASE 5 — PROJECT FOLDER STRUCTURE
# =============================================================================
print_step "PHASE 5 — Project Folder Structure"

# Create directories
mkdir -p /opt/cybersurakshya/{zeek-watcher,response-agent,logs,config,docker,venv}
chown -R cybersurakshya:cybersurakshya /opt/cybersurakshya/
print_ok "Project directories created"

# Install Python venv package
PYTHON_VERSION=$(python3 --version | awk '{print $2}' | cut -d. -f1,2)
apt install -y python${PYTHON_VERSION}-venv 2>/dev/null || apt install -y python3-venv
print_ok "Python venv package installed"

# Create virtual environment
sudo -u cybersurakshya python3 -m venv /opt/cybersurakshya/venv
print_ok "Python virtual environment created"

# Install Python packages
sudo -u cybersurakshya /opt/cybersurakshya/venv/bin/pip install --quiet \
    fastapi uvicorn redis psycopg2-binary python-dotenv \
    watchdog requests pydantic sqlalchemy
print_ok "Python packages installed"

# Create .env file
cat > /opt/cybersurakshya/config/.env << 'ENV_FILE'
REDIS_URL=redis://localhost:6379
POSTGRES_URL=postgresql://cybersurakshya:password@localhost:5432/cybersurakshya
RESPONSE_AGENT_PORT=8000
LOG_DIR=/opt/cybersurakshya/logs
WEBHOOK_URL=
ENV_FILE

chown cybersurakshya:cybersurakshya /opt/cybersurakshya/config/.env
chmod 600 /opt/cybersurakshya/config/.env
print_ok "PHASE 5 COMPLETE"

# =============================================================================
# PHASE 6 — ZEEK WATCHER SERVICE
# =============================================================================
print_step "PHASE 6 — Zeek Watcher Service"

cat > /opt/cybersurakshya/zeek-watcher/watcher.py << 'WATCHER_PY'
import time
import json
import requests
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/opt/cybersurakshya/logs/watcher.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

CONN_LOG = '/opt/zeek/logs/current/conn.log'
DETECTION_API = 'http://localhost:8001/detect'

FIELDS = [
    'id.orig_h', 'id.resp_h', 'id.orig_p', 'id.resp_p',
    'proto', 'duration', 'orig_bytes', 'resp_bytes',
    'conn_state', 'orig_pkts', 'resp_pkts'
]

class ConnLogHandler(FileSystemEventHandler):
    def __init__(self):
        self._file = open(CONN_LOG, 'r')
        self._file.seek(0, 2)
        logger.info("Zeek watcher started — tailing conn.log")

    def on_modified(self, event):
        if event.src_path != CONN_LOG:
            return
        for line in self._file:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                payload = {k: record.get(k) for k in FIELDS}
                requests.post(DETECTION_API, json=payload, timeout=5)
                logger.info(f"Forwarded: {payload.get('id.orig_h')} -> {payload.get('id.resp_h')}")
            except json.JSONDecodeError:
                logger.warning(f"Skipped non-JSON line: {line[:80]}")
            except requests.exceptions.RequestException as e:
                logger.warning(f"Failed to forward to Detection API: {e}")

if __name__ == '__main__':
    event_handler = ConnLogHandler()
    observer = Observer()
    observer.schedule(event_handler, path='/opt/zeek/logs/current/', recursive=False)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
WATCHER_PY

chown cybersurakshya:cybersurakshya /opt/cybersurakshya/zeek-watcher/watcher.py

cat > /etc/systemd/system/zeek-watcher.service << 'WATCHER_SERVICE'
[Unit]
Description=Zeek Log Watcher Service
After=network.target zeek.service

[Service]
Type=simple
User=cybersurakshya
WorkingDirectory=/opt/cybersurakshya/zeek-watcher
ExecStart=/opt/cybersurakshya/venv/bin/python watcher.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
WATCHER_SERVICE

systemctl daemon-reload
systemctl enable zeek-watcher
systemctl start zeek-watcher
print_ok "PHASE 6 COMPLETE"

# =============================================================================
# PHASE 7 — RESPONSE AGENT
# =============================================================================
print_step "PHASE 7 — Response Agent FastAPI Service"

cat > /opt/cybersurakshya/response-agent/main.py << 'RESPONSE_PY'
import os
import subprocess
import logging
import redis
import threading
import requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv('/opt/cybersurakshya/config/.env')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/opt/cybersurakshya/logs/response-agent.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = FastAPI(title="Cyber Surakshya Response Agent")

REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379')
WEBHOOK_URL = os.getenv('WEBHOOK_URL', '')
LOCAL_RULES = '/etc/suricata/rules/local.rules'

class BlockRequest(BaseModel):
    ip: str
    reason: str = ""
    severity: str = "medium"

class UnblockRequest(BaseModel):
    ip: str

class SuricataRuleRequest(BaseModel):
    rule: str

class NotifyRequest(BaseModel):
    message: str
    severity: str = "info"

@app.get("/health")
def health():
    return {"status": "ok", "service": "response-agent"}

@app.post("/response/block-ip")
def block_ip(req: BlockRequest):
    try:
        subprocess.run(
            ["iptables", "-I", "INPUT", "-s", req.ip, "-j", "DROP"],
            check=True
        )
        subprocess.run(
            ["/opt/cybersurakshya/config/save-block.sh", req.ip],
            check=True
        )
        logger.info(f"Blocked IP: {req.ip} | Reason: {req.reason} | Severity: {req.severity}")
        return {"status": "blocked", "ip": req.ip}
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/response/unblock-ip")
def unblock_ip(req: UnblockRequest):
    try:
        subprocess.run(
            ["iptables", "-D", "INPUT", "-s", req.ip, "-j", "DROP"],
            check=True
        )
        subprocess.run(
            ["/opt/cybersurakshya/config/remove-block.sh", req.ip],
            check=True
        )
        logger.info(f"Unblocked IP: {req.ip}")
        return {"status": "unblocked", "ip": req.ip}
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/response/active-blocks")
def active_blocks():
    result = subprocess.run(
        ["iptables", "-L", "INPUT", "-n"],
        capture_output=True, text=True
    )
    lines = result.stdout.splitlines()
    blocked = [l.split()[3] for l in lines if "DROP" in l and len(l.split()) > 3]
    return {"blocked_ips": blocked}

@app.post("/response/add-suricata-rule")
def add_suricata_rule(req: SuricataRuleRequest):
    try:
        with open(LOCAL_RULES, 'a') as f:
            f.write(req.rule + '\n')
        subprocess.run(["kill", "-USR2", "$(pidof suricata)"], shell=True)
        logger.info(f"Added Suricata rule: {req.rule}")
        return {"status": "rule added"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/response/notify")
def notify(req: NotifyRequest):
    logger.info(f"NOTIFICATION [{req.severity.upper()}]: {req.message}")
    if WEBHOOK_URL:
        try:
            requests.post(WEBHOOK_URL, json={"message": req.message, "severity": req.severity}, timeout=5)
        except Exception as e:
            logger.warning(f"Webhook failed: {e}")
    return {"status": "notified"}

def redis_subscriber():
    try:
        r = redis.from_url(REDIS_URL)
        pubsub = r.pubsub()
        pubsub.subscribe('channel:response_command')
        logger.info("Redis subscriber started")
        for message in pubsub.listen():
            if message['type'] == 'message':
                logger.info(f"Redis command received: {message['data']}")
    except Exception as e:
        logger.warning(f"Redis not available: {e}")

@app.on_event("startup")
def startup():
    t = threading.Thread(target=redis_subscriber, daemon=True)
    t.start()
RESPONSE_PY

cat > /etc/systemd/system/response-agent.service << 'RESPONSE_SERVICE'
[Unit]
Description=Cyber Surakshya Response Agent
After=network.target redis-server.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/cybersurakshya/response-agent
ExecStart=/opt/cybersurakshya/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000
Restart=on-failure
RestartSec=5
EnvironmentFile=/opt/cybersurakshya/config/.env

[Install]
WantedBy=multi-user.target
RESPONSE_SERVICE

systemctl daemon-reload
systemctl enable response-agent
systemctl start response-agent
print_ok "PHASE 7 COMPLETE"

# =============================================================================
# PHASE 8 — IPTABLES PERSISTENCE
# =============================================================================
print_step "PHASE 8 — iptables Persistence"

cat > /opt/cybersurakshya/config/restore-blocks.sh << 'RESTORE_SH'
#!/bin/bash
BLOCKS_FILE=/opt/cybersurakshya/config/blocked-ips.txt
if [ -f "$BLOCKS_FILE" ]; then
    while IFS= read -r ip; do
        if [ ! -z "$ip" ]; then
            iptables -I INPUT -s "$ip" -j DROP
            echo "Restored block for $ip"
        fi
    done < "$BLOCKS_FILE"
fi
RESTORE_SH

cat > /opt/cybersurakshya/config/save-block.sh << 'SAVE_SH'
#!/bin/bash
IP=$1
BLOCKS_FILE=/opt/cybersurakshya/config/blocked-ips.txt
touch "$BLOCKS_FILE"
if ! grep -q "^$IP$" "$BLOCKS_FILE"; then
    echo "$IP" >> "$BLOCKS_FILE"
fi
SAVE_SH

cat > /opt/cybersurakshya/config/remove-block.sh << 'REMOVE_SH'
#!/bin/bash
IP=$1
BLOCKS_FILE=/opt/cybersurakshya/config/blocked-ips.txt
if [ -f "$BLOCKS_FILE" ]; then
    sed -i "/^$IP$/d" "$BLOCKS_FILE"
fi
REMOVE_SH

chmod +x /opt/cybersurakshya/config/restore-blocks.sh
chmod +x /opt/cybersurakshya/config/save-block.sh
chmod +x /opt/cybersurakshya/config/remove-block.sh

cat > /etc/systemd/system/restore-blocks.service << 'RESTORE_SERVICE'
[Unit]
Description=Restore IP Blocks on Boot
After=network.target

[Service]
Type=oneshot
ExecStart=/opt/cybersurakshya/config/restore-blocks.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
RESTORE_SERVICE

systemctl daemon-reload
systemctl enable restore-blocks
print_ok "PHASE 8 COMPLETE"

# =============================================================================
# PHASE 9 — LOG ROTATION
# =============================================================================
print_step "PHASE 9 — Log Rotation"

cat > /etc/logrotate.d/zeek << 'ZEEK_ROTATE'
/opt/zeek/logs/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    sharedscripts
    postrotate
        /opt/zeek/bin/zeekctl rotate
    endscript
}
ZEEK_ROTATE

cat > /etc/logrotate.d/suricata << 'SURI_ROTATE'
/var/log/suricata/eve.json {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    sharedscripts
    postrotate
        kill -HUP $(cat /var/run/suricata.pid 2>/dev/null) 2>/dev/null || true
    endscript
}
SURI_ROTATE

cat > /etc/logrotate.d/cybersurakshya << 'CS_ROTATE'
/opt/cybersurakshya/logs/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    sharedscripts
    postrotate
        systemctl restart zeek-watcher response-agent > /dev/null 2>&1 || true
    endscript
}
CS_ROTATE

# Add cron jobs
(crontab -l 2>/dev/null; echo "0 3 * * 1 /usr/bin/suricata-update && systemctl kill -s SIGUSR2 suricata") | crontab -
(crontab -l 2>/dev/null; echo "0 2 * * * find /opt/zeek/logs/ -type f -name '*.log*' -mtime +30 -delete") | crontab -

print_ok "PHASE 9 COMPLETE"

# =============================================================================
# REDIS
# =============================================================================
print_step "Installing Redis..."
apt install -y redis-server
systemctl enable redis-server
systemctl start redis-server
print_ok "Redis installed and running"

# =============================================================================
# FINAL — VERIFY ALL SERVICES
# =============================================================================
print_step "Waiting for all services to start..."
sleep 10

echo ""
echo "======================================"
echo " Cyber Surakshya — Setup Complete!"
echo "======================================"
echo ""
echo "Service Status:"
systemctl is-active zeek        && echo "  zeek            : RUNNING" || echo "  zeek            : STOPPED"
systemctl is-active suricata    && echo "  suricata        : RUNNING" || echo "  suricata        : STOPPED"
systemctl is-active zeek-watcher && echo "  zeek-watcher    : RUNNING" || echo "  zeek-watcher    : STOPPED"
systemctl is-active response-agent && echo "  response-agent  : RUNNING" || echo "  response-agent  : STOPPED"
systemctl is-active redis-server && echo "  redis-server    : RUNNING" || echo "  redis-server    : STOPPED"
echo ""
echo "Response Agent : http://$(hostname -I | awk '{print $1}'):8000"
echo "Health Check   : curl http://localhost:8000/health"
echo ""
echo "Setup log saved to: $LOG_FILE"
echo ""
print_warn "IMPORTANT: Change the cybersurakshya user password!"
echo "  sudo passwd cybersurakshya"
echo ""
echo "======================================"
