# file: deploy.py

import os
import shlex
import subprocess
import sys
from tempfile import NamedTemporaryFile

from tqdm import tqdm

from .aws_cli_utils import check_aws_cli_credentials, run_cmd
from .ec2 import (
    allocate_elastic_ip,
    associate_elastic_ip,
    create_key_pair_if_needed,
    create_security_group_if_needed,
    launch_ec2_instance,
)
from .networking import create_subnet_and_route, create_vpc_if_needed
from .rds import create_rds_postgres


def log(msg: str):
    """Simple logger function to send all output to the terminal."""
    print(msg, end="", flush=True)


def create_userdata_script(
    domain: str, ec2_name: str, skip_compile: bool, skip_certbot: bool
) -> str:
    """
    Creates a #cloud-config script that:
      - Optionally compiles Python3.12 from source OR installs from dnf.
      - Optionally runs Certbot for {domain} or just stays HTTP.
      - Clones your repo into /home/ec2-user/{ec2_name}.
      - Creates a venv in /home/ec2-user/{ec2_name}/venv.
      - Installs requirements from /home/ec2-user/{ec2_name}/requirements.txt (if present).
      - Sets up supervisor to run 'frontend' & 'backend' from that venv at ports 8000/8080.
    No EIP association here—that is done by the local Python script.
    """

    # 1) Choose compile or just install python3.12
    if not skip_compile:
        # compile from source
        python_block = r"""
  - cd /tmp
  - curl -LO https://www.python.org/ftp/python/3.12.8/Python-3.12.8.tgz
  - tar xzf Python-3.12.8.tgz
  - cd Python-3.12.8
  - ./configure --enable-optimizations
  - make -j 2
  - make altinstall
  - python3.12 --version

  - mkdir -p /home/ec2-user/{EC2_NAME}
  - cd /home/ec2-user/{EC2_NAME}
  - python3.12 -m venv venv
  - venv/bin/pip install --upgrade pip
  # We'll install requirements.txt later if present
"""
    else:
        # use distro python3.12
        python_block = r"""
  - dnf -y makecache
  - dnf -y install python3.12 python3.12-devel

  - mkdir -p /home/ec2-user/{EC2_NAME}
  - cd /home/ec2-user/{EC2_NAME}
  - python3.12 -m venv venv
  - venv/bin/pip install --upgrade pip
"""

    # 2) Optionally do certbot or just do HTTP
    if not skip_certbot:
        cert_block = rf"""
  - yum install -y certbot python3-certbot-apache
  - certbot --apache --non-interactive --agree-tos \
      -d {domain} -m admin@{domain} || true

  - sed -i '/<\/VirtualHost>/i \\    ProxyPreserveHost On\\n    ProxyPass /api/ http://127.0.0.1:8080/\\n    ProxyPassReverse /api/ http://127.0.0.1:8080/\\n    ProxyPass / http://127.0.0.1:8000/\\n    ProxyPassReverse / http://127.0.0.1:8000/' \
      /etc/httpd/conf.d/{domain}-le-ssl.conf || true
  - systemctl restart httpd
"""
    else:
        cert_block = r"""
  - echo "[INFO] Skipping Certbot. Only HTTP vHost configured."
  - sed -i '/<\/VirtualHost>/i \    ProxyPreserveHost On\n    ProxyPass /api/ http://127.0.0.1:8080/\n    ProxyPassReverse /api/ http://127.0.0.1:8080/\n    ProxyPass / http://127.0.0.1:8000/\n    ProxyPassReverse / http://127.0.0.1:8000/' \
       /etc/httpd/conf.d/001-http.conf
  - systemctl restart httpd
"""

    # Final user-data, referencing placeholders:
    userdata = rf"""#cloud-config
package_update: true
package_upgrade: all

runcmd:
  ########################################################
  # 1) Basic system prep
  ########################################################
  - yum update -y
  - yum install -y git gcc openssl-devel bzip2-devel libffi-devel zlib-devel
  - yum install -y httpd mod_ssl
  - yum install -y awscli tar make

{python_block}

  ########################################################
  # 2) Minimal HTTP vHost for {domain}
  ########################################################
  - mv /etc/httpd/conf.d/welcome.conf /etc/httpd/conf.d/welcome.conf.disabled || true
  - sed -i '/proxy_module/s/^#//g' /etc/httpd/conf.modules.d/00-proxy.conf
  - sed -i '/proxy_http_module/s/^#//g' /etc/httpd/conf.modules.d/00-proxy.conf

  - echo "<VirtualHost *:80>
      ServerName {domain}
      DocumentRoot /var/www/html
  </VirtualHost>" > /etc/httpd/conf.d/001-http.conf

  - systemctl enable httpd
  - systemctl start httpd

  ########################################################
  # 3) Pull your code into /home/ec2-user/{ec2_name}
  ########################################################
  - cd /home/ec2-user/{ec2_name}
  - git init
  - git remote add origin https://github.com/youruser/yourrepo.git
  - git pull origin main
  - chown -R ec2-user:ec2-user /home/ec2-user/{ec2_name}

  ########################################################
  # 4) Install from requirements.txt (if any)
  ########################################################
  - cd /home/ec2-user/{ec2_name}
  - if [ -f requirements.txt ]; then venv/bin/pip install -r requirements.txt || true; fi

  ########################################################
  # 5) Certbot or not
  ########################################################
{cert_block}

  ########################################################
  # 6) Supervisor config to run uvicorn from venv
  ########################################################
  - cd /home/ec2-user/{ec2_name}
  - venv/bin/pip install supervisor
  - mkdir -p /etc/supervisord.d

  - echo "[supervisord]
nodaemon=true

[program:frontend]
command=/home/ec2-user/{ec2_name}/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000
directory=/home/ec2-user/{ec2_name}
autostart=true
autorestart=true
stderr_logfile=/var/log/frontend_err.log
stdout_logfile=/var/log/frontend_out.log

[program:backend]
command=/home/ec2-user/{ec2_name}/venv/bin/uvicorn backend.main:app --host 127.0.0.1 --port 8080
directory=/home/ec2-user/{ec2_name}
autostart=true
autorestart=true
stderr_logfile=/var/log/backend_err.log
stdout_logfile=/var/log/backend_out.log
" > /etc/supervisord.d/myapp.ini

  - echo "supervisord -c /etc/supervisord.d/myapp.ini" >> /etc/rc.local
  - supervisord -c /etc/supervisord.d/myapp.ini

  - echo "=== Setup Complete ==="
"""

    # Insert actual ec2_name into placeholders
    userdata = userdata.replace("{EC2_NAME}", ec2_name)

    return userdata


def deploy(args, log=log, progress_callback=None):
    """
    Deployment flow:
      1) Confirm AWS creds
      2) Create/reuse VPC
      3) Create subnet & route
      4) Create key pair
      5) Create security group
      6) Allocate EIP
      7) Ask user to set DNS => EIP
      8) Launch EC2 with user-data
      9) Wait for instance
      10) Associate EIP
      11) Write local SSH config
      12) If local copy, rsync
      13) Done
    """

    # 1) Check creds
    creds_ok, acct = check_aws_cli_credentials(log)
    if not creds_ok:
        log(f"[ERROR] AWS credentials invalid: {acct}\n")
        sys.exit(1)
    log(f"[INFO] AWS account: {acct}\n")

    ec2_name = args.ec2_name
    key_name = args.key_name
    domain = args.domain
    region = getattr(args, "aws_region", "us-west-2")
    source_method = getattr(args, "source_method", "git")
    repo_url = getattr(args, "repo_url", None)
    local_path = getattr(args, "local_path", None)

    # Check components from GUI
    compile_python_source = "python_source" in getattr(args, "components", [])
    use_certbot = "certbot" in getattr(args, "components", [])

    # 2-5) VPC, subnet, key, SG
    vpc_id = create_vpc_if_needed(ec2_name, region, log)
    subnet_id = create_subnet_and_route(ec2_name, region, True, vpc_id, log)
    pem_path = create_key_pair_if_needed(key_name, region, log)
    sg_id = create_security_group_if_needed(ec2_name, region, vpc_id, log)

    # 6) EIP
    alloc_id, eip = allocate_elastic_ip(ec2_name, region, log)
    log(f"[INFO] EIP allocated: {eip}\n")

    # 7) Prompt user to set DNS
    log(f"[ACTION] Create/verify A-record: {domain} -> {eip}\n")
    input("[Press ENTER once DNS is updated, or continue anyway]\n")

    # 8) Generate user-data
    user_data = create_userdata_script(
        domain=domain,
        ec2_name=ec2_name,
        skip_compile=(not compile_python_source),
        skip_certbot=(not use_certbot),
    )
    with NamedTemporaryFile(delete=False, mode="w", suffix=".txt") as tmp:
        tmp.write(user_data)
        user_data_file = tmp.name

    instance_id, public_dns = launch_ec2_instance(
        ec2_name, key_name, sg_id, subnet_id, region, user_data_file, log
    )
    log(f"[INFO] Launched {instance_id}, DNS {public_dns}\n")

    # Wait for it
    run_cmd(
        f"aws ec2 wait instance-running --region {region} --instance-ids {instance_id}",
        log,
    )
    run_cmd(
        f"aws ec2 wait instance-status-ok --region {region} --instance-ids {instance_id}",
        log,
    )
    log(f"[INFO] Instance {instance_id} passed status checks.\n")

    # 10) Associate EIP
    associate_elastic_ip(instance_id, alloc_id, region, log)
    log(f"[INFO] EIP {eip} associated with {instance_id}.\n")

    # 11) Write SSH config
    ssh_config_path = os.path.expanduser("~/.ssh/config")
    config_lines = [
        f"\n# Auto-added by deploy script for {ec2_name}",
        f"Host {ec2_name}",
        f"  HostName ec2-{eip.replace('.', '-')}.{region}.compute.amazonaws.com",
        "  User ec2-user",
        f"  IdentityFile ~/.ssh/{key_name}.pem",
    ]
    try:
        with open(ssh_config_path, "a") as cfg:
            cfg.write("\n".join(config_lines) + "\n")
        log(f"[INFO] Appended SSH config to {ssh_config_path}\n")
    except Exception as ex:
        log(f"[WARNING] Could not write SSH config: {ex}\n")

    # 12) Local copy if selected
    if source_method == "copy" and local_path:
        copy_cmd = f"""rsync -av \
  --exclude='venv' \
  --exclude='__pycache__' \
  -e "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null" \
  {shlex.quote(local_path)} \
  {ec2_name}:/home/ec2-user/{ec2_name}
"""
        run_cmd(copy_cmd, log)
        log(f"[INFO] Copied local files to /home/ec2-user/{ec2_name}.\n")

    log("\n[INFO] Deployment complete.\n")
    log(f"[INFO] Domain: {domain} => {eip}\n")
    log(f"[INFO] SSH: ssh {ec2_name}\n")
