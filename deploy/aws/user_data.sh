#!/bin/bash
# ==============================================================================
# Phishing Detection & Risk Intelligence Platform
# Phase 26: AWS EC2 Cloud-Init Bootstrap Script (Amazon Linux 2023 / Ubuntu 22.04)
# ==============================================================================

set -euo pipefail

echo "=========================================================="
echo "🚀 Initializing Automated Cloud Deployment on AWS EC2..."
echo "=========================================================="

# 1. Detect Operating System & Install Dependencies
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    OS="unknown"
fi

if [ "$OS" = "amzn" ] || [ "$OS" = "fedora" ] || [ "$OS" = "rhel" ]; then
    echo "📦 Detected Amazon Linux / RPM distribution. Updating..."
    dnf update -y
    dnf install -y docker git curl
    systemctl enable --now docker
    usermod -aG docker ec2-user || true

    # Install Docker Compose Plugin
    DOCKER_PLUGINS=/usr/libexec/docker/cli-plugins
    mkdir -p "$DOCKER_PLUGINS"
    curl -SL https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64 -o "$DOCKER_PLUGINS/docker-compose"
    chmod +x "$DOCKER_PLUGINS/docker-compose"
    COMPOSE_CMD="/usr/libexec/docker/cli-plugins/docker-compose"
elif [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
    echo "📦 Detected Ubuntu / Debian distribution. Updating..."
    apt-get update -y
    apt-get install -y ca-certificates curl gnupg lsb-release git docker.io docker-compose-v2
    systemctl enable --now docker
    usermod -aG docker ubuntu || true
    COMPOSE_CMD="docker compose"
else
    echo "⚠️ Generic Linux detected. Attempting docker install..."
    curl -fsSL https://get.docker.com | sh
    systemctl enable --now docker
    COMPOSE_CMD="docker compose"
fi

# 2. Deploy Application Repository
DEPLOY_DIR="/opt/phishintel"
REPO_URL="https://github.com/Anushka-google/The_Pishing_Web.git"

if [ -d "$DEPLOY_DIR" ]; then
    echo "🔄 Existing deployment found at $DEPLOY_DIR. Pulling latest main branch..."
    cd "$DEPLOY_DIR"
    git fetch origin main
    git reset --hard origin/main
else
    echo "📥 Cloning repository from $REPO_URL..."
    mkdir -p "$DEPLOY_DIR"
    git clone "$REPO_URL" "$DEPLOY_DIR"
    cd "$DEPLOY_DIR"
fi

# 3. Create Production Environment Configuration
cat << 'EOF' > "$DEPLOY_DIR/.env"
POSTGRES_USER=phishintel_admin
POSTGRES_PASSWORD=PhishIntel_Secure_2026!
POSTGRES_DB=phishing_db
LOG_LEVEL=INFO
EOF

# 4. Launch Production Container Stack
echo "🐳 Launching Docker Compose multi-container stack..."
$COMPOSE_CMD -f docker-compose.prod.yml up -d --build

# 5. Configure Systemd Service for High-Availability Autostart
cat << EOF > /etc/systemd/system/phishintel.service
[Unit]
Description=Phishing Detection Platform Production Stack
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$DEPLOY_DIR
ExecStart=$COMPOSE_CMD -f docker-compose.prod.yml up -d
ExecStop=$COMPOSE_CMD -f docker-compose.prod.yml down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable phishintel.service

echo "=========================================================="
echo "✅ Phishing Intelligence Platform successfully deployed!"
echo "   Public Dashboard: http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 || echo 'YOUR_PUBLIC_IP')"
echo "=========================================================="
