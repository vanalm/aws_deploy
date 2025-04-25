# userdata.py

def create_userdata_script(domain, repo_url):
    """
    Writes a cloud-init script for Amazon Linux 2023 that:
      - Installs needed dependencies and dev tools
      - Builds Python 3.12.8 from source (with coverage disabled)
      - Installs Git, Apache, Certbot, etc.
      - Clones your repo
      - Writes Apache & Supervisor config via write_files
      - Sets up Apache reverse proxy & SSL
      - Starts Supervisor for FastAPI/Gradio
    Returns the filename path.
    """
    script_file = "userdata_deploy.txt"
    with open(script_file, "w") as f:
        f.write(f"""#cloud-config
package_update: true
package_upgrade: true

write_files:
  - path: /etc/httpd/conf.d/deploy.conf
    permissions: '0644'
    content: |
      <VirtualHost *:80>
          ServerName {domain}
          Redirect / https://{domain}/
      </VirtualHost>

      <VirtualHost *:443>
          ServerName {domain}
          SSLEngine on
          SSLCertificateFile /etc/letsencrypt/live/{domain}/fullchain.pem
          SSLCertificateKeyFile /etc/letsencrypt/live/{domain}/privkey.pem
          Include /etc/letsencrypt/options-ssl-apache.conf

          ProxyPreserveHost On
          ProxyRequests Off
          ProxyPass / http://127.0.0.1:8000/
          ProxyPassReverse / http://127.0.0.1:8000/
      </VirtualHost>

  - path: /etc/supervisord.d/myapp.ini
    permissions: '0644'
    content: |
      [supervisord]
      nodaemon=true

      [program:myapp]
      command=/home/ec2-user/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000
      directory=/home/ec2-user/app
      autostart=true
      autorestart=true
      stderr_logfile=/var/log/myapp_err.log
      stdout_logfile=/var/log/myapp_out.log

runcmd:
  # 1) Ensure base system is updated and dev tools are installed
  - dnf -y update
  - dnf -y groupinstall "Development Tools"
  - dnf -y install gcc-c++ openssl-devel bzip2-devel libffi-devel zlib-devel xz-devel gdbm-devel sqlite-devel tk-devel make curl
  
  # 2) Install Apache, Certbot, Git, etc.
  - dnf -y install httpd mod_ssl certbot python3-certbot-apache git awscli

  # 3) Download and build Python 3.12.8 from source
  - cd /tmp
  - curl -LO https://www.python.org/ftp/python/3.12.8/Python-3.12.8.tgz
  - tar xzf Python-3.12.8.tgz
  - cd Python-3.12.8

  # Disable coverage instrumentation to avoid '__gcov_*' linker errors
  - export CFLAGS="-fno-profile-arcs -fno-test-coverage"
  - export LDFLAGS="-fno-profile-arcs -fno-test-coverage"

  - ./configure --enable-optimizations
  - make -j 2
  - make altinstall
  - python3.12 --version

  # 4) Create a Python 3.12 venv
  - python3.12 -m venv /home/ec2-user/venv
  - /home/ec2-user/venv/bin/pip install --upgrade pip

  # 5) Pull your application code
  - mkdir -p /home/ec2-user/app
  - cd /home/ec2-user/app
  - git init
  - git remote add origin {repo_url}
  - git pull origin main
  - chown -R ec2-user:ec2-user /home/ec2-user/app

  # 6) Install python packages into the venv
  - /home/ec2-user/venv/bin/pip install fastapi gradio uvicorn supervisor

  # 7) Enable and start Apache
  - systemctl enable httpd
  - systemctl start httpd

  # On AL2023, 'mod_proxy' is typically part of the core, but sometimes commented out. Un-comment if needed:
  - sed -i '/LoadModule proxy_module/s/^#//g' /etc/httpd/conf.modules.d/00-proxy.conf || true
  - sed -i '/LoadModule proxy_http_module/s/^#//g' /etc/httpd/conf.modules.d/00-proxy.conf || true

  # 8) Try to get an SSL cert via Certbot
  - certbot --apache --non-interactive --agree-tos -d {domain} -m admin@{domain} || true

  # 9) Restart Apache to load the new config
  - systemctl restart httpd

  # 10) Make sure Supervisor runs on boot, then launch it
  - /home/ec2-user/venv/bin/pip install supervisor
  - echo "supervisord -c /etc/supervisord.d/myapp.ini" >> /etc/rc.local
  - supervisord -c /etc/supervisord.d/myapp.ini
""")
    return script_file