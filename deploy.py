import os
import shlex
import subprocess
import sys
from tempfile import NamedTemporaryFile

# AWS helper imports
from .aws_cli_utils import check_aws_cli_credentials, run_cmd
from .ec2 import (
    allocate_elastic_ip,
    associate_elastic_ip,
    create_key_pair_if_needed,
    create_security_group_if_needed,
    launch_ec2_instance,
)
from .networking import create_subnet_and_route, create_vpc_if_needed

# If you previously used tqdm or other imports, remove them if not needed
# from tqdm import tqdm


def log(msg: str):
    """Simple logger function to send all output to the terminal (stdout)."""
    print(msg, end="", flush=True)


def create_userdata_script(domain: str, ec2_name: str, skip_certbot: bool) -> str:
    """
    Creates a #cloud-config script that:
      - Installs Python3.12 from dnf (no source compile).
      - Installs Apache, certbot (if not skipped), etc.
      - Clones your repo into /home/ec2-user/{ec2_name}.
      - Creates a venv and installs any requirements.txt.
      - Sets up Supervisor to run 'frontend' & 'backend' from that venv at ports 8000/8080.
      - Optionally configures SSL with certbot if skip_certbot=False.
    """

    # Always install Python 3.12 with dnf
    python_block = rf"""
  - dnf -y makecache
  - dnf -y install python3.12 python3.12-devel

  - mkdir -p /home/ec2-user/{ec2_name}
  - cd /home/ec2-user/{ec2_name}
  - python3.12 -m venv venv
  - venv/bin/pip install --upgrade pip
"""

    # Optionally do certbot or just do HTTP
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

    # Final user-data
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

    # Insert the actual ec2_name into placeholders
    userdata = userdata.replace("{EC2_NAME}", ec2_name)
    return userdata


def post_deploy_checks(ec2_name: str, log_func=log):
    """
    After the instance is up, confirm that everything ran successfully.
    - Copies the cloud-init logs locally.
    - Checks python3.12, certbot, and supervisor, etc.
    """
    log_func("\n[INFO] Starting post-deployment checks...\n")

    # Download cloud-init logs
    local_log_name = f"cloud-init-output-{ec2_name}.log"
    scp_cmd = f"scp {ec2_name}:/var/log/cloud-init-output.log {local_log_name}"
    run_cmd(
        scp_cmd, log_func, check=False
    )  # check=False so it doesn't crash if scp fails

    # Check python version
    run_cmd(f"ssh {ec2_name} 'python3.12 --version'", log_func, check=False)

    # Check certbot
    run_cmd(
        f"ssh {ec2_name} 'command -v certbot || echo [WARN] certbot not found'",
        log_func,
        check=False,
    )

    # Check supervisor
    run_cmd(
        f"ssh {ec2_name} 'command -v supervisord && supervisorctl status || echo [WARN] supervisor not found'",
        log_func,
        check=False,
    )

    log_func("[INFO] Post-deployment checks complete.\n")


def deploy(args, log=log):
    """
    Minimal deployment flow:
      1) Confirm AWS creds
      2) Create/reuse VPC
      3) Create subnet & route
      4) Create key pair
      5) Create security group
      6) Allocate EIP
      7) Prompt DNS
      8) Launch EC2 w/ user-data (installs python3.12 via dnf)
      9) Wait for instance
      10) Associate EIP
      11) Write local SSH config
      12) (Optional) rsync local code
      13) Post-deploy checks (SSH in, retrieve logs, etc)
      14) Done
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
    local_path = getattr(args, "local_path", None)

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

    # 8) Generate user-data (always using dnf python3.12, optional certbot)
    user_data = create_userdata_script(
        domain=domain,
        ec2_name=ec2_name,
        skip_certbot=(not use_certbot),
    )
    with NamedTemporaryFile(delete=False, mode="w", suffix=".txt") as tmp:
        tmp.write(user_data)
        user_data_file = tmp.name

    # Launch EC2
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

    # 13) Post-deployment checks (SSH, logs, etc.)
    post_deploy_checks(ec2_name, log)

    # 14) Done
    log("\n[INFO] Deployment complete.\n")
    log(f"[INFO] Domain: {domain} => {eip}\n")
    log(f"[INFO] SSH: ssh {ec2_name}\n")
    # Example commands that run on the remote EC2 via SSH:
    run_cmd(f"ssh {ec2_name} 'sudo dnf -y install nano'", log)
    run_cmd(
        f"ssh {ec2_name} \"echo 'Hello from the new EC2!' > /home/ec2-user/hello_world.txt\"",
        log,
    )
    run_cmd(f"ssh {ec2_name} 'cat /home/ec2-user/hello_world.txt'", log)
    run_cmd(f"ssh {ec2_name} 'nano --version'", log)
