# userdata.py

import os

def create_userdata_script(domain: str, repo_url: str, selected_chunks: set) -> str:
    """
    Generates a cloud-init script divided into independent chunks.
    `selected_chunks` is a set containing any of:
      "apache", "supervisor", "python_source", "certbot"
    Returns the filename of the generated script.
    """

    CHUNKS = {
        "apache": f"""
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
""",
        "supervisor": """
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
""",
        "python_source": """
  # Build Python 3.12.8 from source
  - cd /tmp
  - curl -LO https://www.python.org/ftp/python/3.12.8/Python-3.12.8.tgz
  - tar xzf Python-3.12.8.tgz
  - cd Python-3.12.8

  - export CFLAGS="-fno-profile-arcs -fno-test-coverage"
  - export LDFLAGS="-fno-profile-arcs -fno-test-coverage"

  - ./configure --enable-optimizations
  - make -j "$(nproc)"
  - make altinstall
  - python3.12 --version

  # Create virtualenv
  - python3.12 -m venv /home/ec2-user/venv
  - /home/ec2-user/venv/bin/pip install --upgrade pip
""",
        "certbot": f"""
  # Obtain SSL certificate via Certbot
  - certbot --apache --non-interactive --agree-tos -d {domain} -m admin@{domain} || true
""",
    }

    # Header + base
    lines = [
        "#cloud-config",
        "package_update: true",
        "package_upgrade: true",
    ]

    # write_files section
    wf = []
    for name in ("apache", "supervisor"):
        if name in selected_chunks:
            wf.append(CHUNKS[name])
    if wf:
        lines.append("write_files:")
        lines.extend(wf)

    # runcmd section
    lines.append("runcmd:")
    # 1) Always: update + dev tools + basic services
    lines.extend([
        "  - dnf -y update",
        "  - dnf -y groupinstall \"Development Tools\"",
        "  - dnf -y install gcc-c++ openssl-devel bzip2-devel libffi-devel zlib-devel xz-devel gdbm-devel sqlite-devel tk-devel make curl",
        "  - dnf -y install httpd mod_ssl certbot python3-certbot-apache git awscli",
    ])
    # 2) Optional chunks
    for chunk in ("python_source",):
        if chunk in selected_chunks:
            lines.append(CHUNKS[chunk])
    # 3) Always: pull app & install deps
    lines.extend([
        "  - mkdir -p /home/ec2-user/app",
        "  - cd /home/ec2-user/app",
        f"  - git init && git remote add origin {repo_url} && git pull origin main",
        "  - chown -R ec2-user:ec2-user /home/ec2-user/app",
        "  - /home/ec2-user/venv/bin/pip install fastapi gradio uvicorn supervisor",
    ])
    # 4) Always: enable & start Apache + proxy modules
    lines.extend([
        "  - systemctl enable httpd && systemctl start httpd",
        "  - sed -i '/LoadModule proxy_module/s/^#//g' /etc/httpd/conf.modules.d/00-proxy.conf || true",
        "  - sed -i '/LoadModule proxy_http_module/s/^#//g' /etc/httpd/conf.modules.d/00-proxy.conf || true",
    ])
    # 5) Optional certbot
    if "certbot" in selected_chunks:
        lines.append(CHUNKS["certbot"])
    # 6) Optional supervisor run
    if "supervisor" in selected_chunks:
        lines.extend([
            "  - systemctl restart httpd",
            "  - echo \"supervisord -c /etc/supervisord.d/myapp.ini\" >> /etc/rc.local",
            "  - supervisord -c /etc/supervisord.d/myapp.ini",
        ])

    # Write to disk
    script = "\n".join(lines) + "\n"
    out_file = "userdata_deploy.txt"
    with open(out_file, "w") as f:
        f.write(script)
    return out_file