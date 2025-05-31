#!/usr/bin/env bash
set -euo pipefail

echo "=== Step A: Check for Python 3.12 ==="
if ! command -v python3.12 >/dev/null 2>&1; then
  echo "Python 3.12 not found. Installing now..."
  sudo dnf -y makecache
  sudo dnf -y install python3.12 python3.12-devel || {
    echo "[ERROR] Could not install python3.12 from distro."
    exit 1
  }
else
  echo "Python3.12 already present."
fi

echo "=== Verify python3.12 version ==="
python3.12 --version || {
  echo "[ERROR] python3.12 command failed even after install."
  exit 1
}

echo "=== Step B: Check and install Apache/Certbot if missing ==="

# 1) Apache modules
if ! systemctl status httpd >/dev/null 2>&1; then
  echo "httpd not installed or not recognized. Installing..."
  sudo dnf -y install httpd mod_ssl || {
    echo "[ERROR] Installing httpd / mod_ssl failed."
    exit 1
  }
  sudo systemctl enable httpd
fi

# 2) Certbot
if ! command -v certbot >/dev/null 2>&1; then
  echo "Certbot not found. Installing..."
  sudo dnf -y install certbot python3-certbot-apache || {
    echo "[ERROR] Installing certbot + plugin failed."
    exit 1
  }
else
  echo "Certbot command is present."
fi

echo "=== Step C: Enable relevant Apache modules (proxy, ssl) ==="
sudo sed -i 's/^#\(LoadModule proxy_module\)/\1/' /etc/httpd/conf.modules.d/00-proxy.conf || true
sudo sed -i 's/^#\(LoadModule proxy_http_module\)/\1/' /etc/httpd/conf.modules.d/00-proxy.conf || true

# The mod_ssl is typically auto-loaded if installed

echo "=== Step D: Restart Apache to apply everything ==="
sudo systemctl restart httpd || {
  echo "[ERROR] Apache failed to restart."
  exit 1
}

echo "=== Final check ==="
echo "Python location: $(command -v python3.12)"
echo "Python version: $(python3.12 --version)"
echo "Certbot location: $(command -v certbot || echo 'not found')"
echo "Apache status:"
systemctl status httpd --no-pager || true

echo "=== All done ==="