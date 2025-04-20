#!/usr/bin/env python3
"""
aws_deploy_tool.py

Automates AWS provisioning for a FastAPI+Gradio (or similar) app on Amazon Linux EC2 (t3.micro).
Optionally includes RDS Postgres. Provides a tkinter GUI or command-line usage.

Default Region: us-west-2
"""

import subprocess
import argparse
import sys
import shlex
import os
import shutil

# For the optional GUI
import tkinter as tk
from tkinter import ttk

###############################################################################
# Global constants and defaults
###############################################################################

DEFAULT_REGION = "us-west-2"
# Amazon Linux 2 AMI for us-west-2, x86_64. Adjust as needed.
DEFAULT_AMI = "ami-09e67e426f25ce0d7"

###############################################################################
# AWS CLI / Credential Checks
###############################################################################


def check_aws_cli_credentials(log_callback=None):
    """
    Checks if AWS CLI is installed and if credentials are configured.
    Returns (True, account_id_str) if credentials exist, else (False, error_message).
    Uses 'aws sts get-caller-identity --query "Account" --output text'.
    """
    cmd = "aws sts get-caller-identity --query Account --output text"
    if log_callback:
        log_callback(f"[RUN] {cmd}\n")

    try:
        process = subprocess.Popen(
            shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        stdout, stderr = process.communicate()
        rc = process.returncode

        if rc != 0:
            # CLI installed but credentials not configured or invalid
            msg = (
                f"[WARN] AWS CLI credentials not found or invalid:\n{stderr}\n"
                "Please run 'aws configure' or set AWS credentials before proceeding.\n"
            )
            return (False, msg)
        # If success, parse the account ID
        account_id = stdout.strip()
        return (True, account_id)
    except FileNotFoundError:
        # AWS CLI not installed
        msg = "[ERROR] AWS CLI not installed. Please install AWS CLI and configure credentials.\n"
        return (False, msg)


###############################################################################
# Utility functions for shell commands
###############################################################################


def run_cmd(cmd, log_callback=None, check=True):
    """
    Runs a shell command via subprocess. If log_callback is provided,
    redirect stdout/stderr lines to it for a GUI or console.
    """
    if log_callback:
        log_callback(f"[RUN] {cmd}\n")

    process = subprocess.Popen(
        shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    stdout, stderr = process.communicate()

    if log_callback:
        if stdout:
            log_callback(stdout)
        if stderr:
            log_callback(stderr)

    if check and process.returncode != 0:
        sys.exit(f"[ERROR] Command failed: {cmd}")
    return stdout, stderr


###############################################################################
# AWS Resource Creation
###############################################################################


def move_pem_to_ssh_directory(pem_file_name, log_callback=None):
    """
    Moves the .pem file into ~/.ssh if not already there,
    sets chmod 400, and returns the new path.
    """
    home = os.path.expanduser("~")
    ssh_dir = os.path.join(home, ".ssh")
    if not os.path.exists(ssh_dir):
        os.makedirs(ssh_dir, exist_ok=True)

    src = pem_file_name
    dest = os.path.join(ssh_dir, os.path.basename(pem_file_name))
    try:
        shutil.move(src, dest)
        os.chmod(dest, 0o400)
        if log_callback:
            log_callback(f"[INFO] Moved {pem_file_name} to {dest} and set chmod 400.\n")
        return dest
    except Exception as e:
        if log_callback:
            log_callback(f"[WARN] Could not move {pem_file_name} to {dest}: {e}\n")
        return pem_file_name  # fallback


def create_key_pair_if_needed(key_name, region, log_callback):
    """
    Checks if the given Key Pair exists. If not, creates and saves <key_name>.pem locally,
    then moves it to ~/.ssh.
    """
    cmd_check = f"aws ec2 describe-key-pairs --key-names {key_name} --region {region}"
    _, stderr = run_cmd(cmd_check, log_callback=log_callback, check=False)
    if "InvalidKeyPair.NotFound" in stderr:
        # Need to create key
        log_callback(f"[INFO] Creating Key Pair '{key_name}'...\n")
        cmd_create = f"aws ec2 create-key-pair --key-name {key_name} --region {region} --query 'KeyMaterial' --output text"
        stdout, _ = run_cmd(cmd_create, log_callback=log_callback)
        pem_file = f"{key_name}.pem"
        with open(pem_file, "w") as f:
            f.write(stdout)
        os.chmod(pem_file, 0o400)
        log_callback(f"[INFO] Key Pair created locally: {pem_file} (chmod 400).\n")

        # Move to ~/.ssh
        new_path = move_pem_to_ssh_directory(pem_file, log_callback=log_callback)
        return new_path
    else:
        log_callback(f"[INFO] Key Pair '{key_name}' already exists.\n")
        # Assume user might have the .pem in ~/.ssh or somewhere else
        # We won't forcibly re-download because AWS only provides private key once
        # Return a guess of where it might be:
        guessed_path = os.path.join(os.path.expanduser("~"), ".ssh", f"{key_name}.pem")
        return guessed_path


def create_security_group_if_needed(sg_name, region, log_callback):
    """
    Creates or reuses a Security Group. Opens inbound 22,80,443.
    Returns the Security Group ID.
    """
    cmd_describe = f"aws ec2 describe-security-groups --filters Name=group-name,Values={sg_name} --region {region}"
    stdout, _ = run_cmd(cmd_describe, log_callback=log_callback, check=False)

    if '"GroupId":' in stdout:
        import json

        try:
            data = json.loads(stdout)
            sg_id = data["SecurityGroups"][0]["GroupId"]
            log_callback(f"[INFO] Security Group '{sg_name}' already exists: {sg_id}\n")
            return sg_id
        except:
            pass

    # Create new SG
    log_callback(f"[INFO] Creating Security Group '{sg_name}'...\n")
    vpc_cmd = (
        f"aws ec2 describe-vpcs --region {region} --query 'Vpcs[0].VpcId' --output text"
    )
    vpc_out, _ = run_cmd(vpc_cmd, log_callback=log_callback)
    vpc_id = vpc_out.strip()

    create_cmd = f"aws ec2 create-security-group --group-name {sg_name} --description 'AppSecurityGroup' --vpc-id {vpc_id} --region {region} --query 'GroupId' --output text"
    sg_out, _ = run_cmd(create_cmd, log_callback=log_callback)
    sg_id = sg_out.strip()

    # Authorize inbound rules
    rules = [
        ("tcp", 22, 22, "0.0.0.0/0"),  # SSH
        ("tcp", 80, 80, "0.0.0.0/0"),  # HTTP
        ("tcp", 443, 443, "0.0.0.0/0"),  # HTTPS
    ]
    for proto, from_p, to_p, cidr in rules:
        auth_cmd = (
            f"aws ec2 authorize-security-group-ingress --group-id {sg_id} "
            f"--protocol {proto} --port {from_p}-{to_p} --cidr {cidr} --region {region}"
        )
        run_cmd(auth_cmd, log_callback=log_callback)

    log_callback(f"[INFO] Security Group created: {sg_id}\n")
    return sg_id


def allocate_elastic_ip(region, log_callback):
    """
    Allocates a new Elastic IP address in the given region, returns (allocation_id, public_ip).
    """
    cmd = f"aws ec2 allocate-address --domain vpc --region {region} --query '[AllocationId,PublicIp]' --output text"
    stdout, _ = run_cmd(cmd, log_callback=log_callback)
    alloc_id, public_ip = stdout.split()
    log_callback(
        f"[INFO] Allocated Elastic IP: {public_ip} (AllocationId: {alloc_id})\n"
    )
    return alloc_id, public_ip


def associate_elastic_ip(instance_id, alloc_id, region, log_callback):
    """
    Associates the allocated Elastic IP with the specified instance.
    """
    cmd = f"aws ec2 associate-address --instance-id {instance_id} --allocation-id {alloc_id} --region {region}"
    run_cmd(cmd, log_callback=log_callback)
    log_callback("[INFO] Elastic IP associated with instance.\n")


def create_rds_postgres(db_identifier, db_username, db_password, region, log_callback):
    """
    Provisions a Postgres RDS (db.t3.micro). Waits until available, returns endpoint string.
    """
    log_callback(f"[INFO] Creating RDS Postgres '{db_identifier}'...\n")
    cmd_create = f"""aws rds create-db-instance \
        --db-instance-identifier {db_identifier} \
        --db-instance-class db.t3.micro \
        --engine postgres \
        --allocated-storage 20 \
        --no-multi-az \
        --publicly-accessible \
        --master-username {db_username} \
        --master-user-password {db_password} \
        --backup-retention-period 1 \
        --db-name {db_identifier} \
        --engine-version 14 \
        --region {region} \
        --query 'DBInstance.DBInstanceIdentifier' \
        --output text
    """
    run_cmd(cmd_create, log_callback=log_callback)

    # Wait until available
    wait_cmd = f"aws rds wait db-instance-available --db-instance-identifier {db_identifier} --region {region}"
    run_cmd(wait_cmd, log_callback=log_callback)
    log_callback("[INFO] RDS Postgres is now available.\n")

    # Get endpoint
    ep_cmd = (
        f"aws rds describe-db-instances --db-instance-identifier {db_identifier} "
        f"--region {region} --query 'DBInstances[0].Endpoint.Address' --output text"
    )
    stdout, _ = run_cmd(ep_cmd, log_callback=log_callback)
    endpoint = stdout.strip()
    log_callback(f"[INFO] RDS Endpoint: {endpoint}\n")
    return endpoint


###############################################################################
# Create User-Data
###############################################################################


def create_userdata_script(domain, repo_url):
    """
    Writes a cloud-init script for Amazon Linux 2. Installs Python 3.12.8, Git, Apache, Let’s Encrypt, etc.
    Clones the specified repo and sets up Supervisor to run uvicorn on port 8000.
    Returns the filename.
    """
    script_file = "userdata_deploy.txt"
    with open(script_file, "w") as f:
        f.write(
            f"""#cloud-config
package_update: true
package_upgrade: all

runcmd:
  - yum update -y
  - yum install -y git gcc openssl-devel bzip2-devel libffi-devel zlib-devel
  - yum install -y httpd mod_ssl
  - yum install -y certbot python3-certbot-apache
  - yum install -y awscli tar make

  # Build Python 3.12.8 from source
  - cd /tmp
  - curl -LO https://www.python.org/ftp/python/3.12.8/Python-3.12.8.tgz
  - tar xzf Python-3.12.8.tgz
  - cd Python-3.12.8
  - ./configure --enable-optimizations
  - make -j 2
  - make altinstall
  - python3.12 --version

  # Create a venv
  - python3.12 -m venv /home/ec2-user/venv
  - /home/ec2-user/venv/bin/pip install --upgrade pip

  # Pull code
  - mkdir -p /home/ec2-user/app
  - cd /home/ec2-user/app
  - git init
  - git remote add origin {repo_url}
  - git pull origin main
  - chown -R ec2-user:ec2-user /home/ec2-user/app

  # pip install requirements
  - /home/ec2-user/venv/bin/pip install fastapi gradio uvicorn supervisor

  # Setup apache as a reverse proxy
  - systemctl enable httpd
  - systemctl start httpd

  - yum install -y mod_proxy mod_proxy_http
  - sed -i '/LoadModule proxy_module/s/^#//g' /etc/httpd/conf.modules.d/00-proxy.conf
  - sed -i '/LoadModule proxy_http_module/s/^#//g' /etc/httpd/conf.modules.d/00-proxy.conf

  # Attempt to get SSL cert (requires domain DNS pointing to EIP)
  - certbot --apache --non-interactive --agree-tos -d {domain} -m admin@{domain} || true

  # Apache config for domain + reverse proxy
  - echo "<VirtualHost *:80>
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
  " > /etc/httpd/conf.d/deploy.conf

  - systemctl restart httpd

  # Supervisor config for uvicorn
  - mkdir -p /etc/supervisord.d
  - echo "[supervisord]
nodaemon=true

[program:myapp]
command=/home/ec2-user/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000
directory=/home/ec2-user/app
autostart=true
autorestart=true
stderr_logfile=/var/log/myapp_err.log
stdout_logfile=/var/log/myapp_out.log
" > /etc/supervisord.d/myapp.ini

  - /home/ec2-user/venv/bin/pip install supervisor
  - echo "supervisord -c /etc/supervisord.d/myapp.ini" >> /etc/rc.local
  - supervisord -c /etc/supervisord.d/myapp.ini

"""
        )
    return script_file


###############################################################################
# Launch EC2
###############################################################################


def launch_ec2_instance(
    ec2_name, key_name, sg_id, region, user_data_script, log_callback
):
    """
    Launch a t3.micro Amazon Linux 2 instance. Wait until 'running', return (instance_id, public_dns).
    """
    log_callback(
        f"[INFO] Launching EC2 (t3.micro) in {region} with AMI {DEFAULT_AMI}...\n"
    )
    cmd_launch = f"""aws ec2 run-instances \
        --image-id {DEFAULT_AMI} \
        --count 1 \
        --instance-type t3.micro \
        --key-name {key_name} \
        --security-group-ids {sg_id} \
        --user-data file://{user_data_script} \
        --tag-specifications 'ResourceType=instance,Tags=[{{Key=Name,Value={ec2_name}}}]' \
        --region {region} \
        --query 'Instances[0].InstanceId' \
        --output text
    """
    stdout, _ = run_cmd(cmd_launch, log_callback=log_callback)
    instance_id = stdout.strip()

    log_callback(f"[INFO] Instance launched: {instance_id}\n")
    # Wait until running
    wait_cmd = (
        f"aws ec2 wait instance-running --instance-ids {instance_id} --region {region}"
    )
    run_cmd(wait_cmd, log_callback=log_callback)
    log_callback("[INFO] EC2 instance is now running.\n")

    # Public DNS
    dns_cmd = (
        f"aws ec2 describe-instances --instance-ids {instance_id} --region {region} "
        f"--query 'Reservations[0].Instances[0].PublicDnsName' --output text"
    )
    dns_out, _ = run_cmd(dns_cmd, log_callback=log_callback)
    public_dns = dns_out.strip()
    log_callback(f"[INFO] Instance Public DNS: {public_dns}\n")

    return instance_id, public_dns


###############################################################################
# Orchestrate the Deployment
###############################################################################


def deploy(args, log_callback):
    """
    Orchestrates the entire flow:
      - Check AWS creds,
      - Key Pair (and move .pem to ~/.ssh),
      - Security Group,
      - EC2 + EIP,
      - (Optional) RDS,
      - Show SSH instructions.
    """
    try:
        # 0) Check enable_rds is valid
        if args.enable_rds.lower() not in ["yes", "no"]:
            raise ValueError("--enable-rds must be 'yes' or 'no'")

        region = args.aws_region
        ec2_name = args.ec2_name
        key_name = args.key_name
        domain = args.domain
        repo_url = args.repo_url

        enable_rds = args.enable_rds.lower() == "yes"
        db_identifier = args.db_identifier
        db_username = args.db_username
        db_password = args.db_password

        # 1) Check AWS CLI / credentials
        creds_ok, result_str = check_aws_cli_credentials(log_callback)
        if creds_ok:
            log_callback(f"[INFO] Signed in as account {result_str}\n")
        else:
            log_callback(result_str)
            log_callback("[ERROR] Cannot proceed without valid AWS credentials.\n")
            return  # or sys.exit(1)

        # 2) Create Key Pair if needed (and automatically move to ~/.ssh)
        pem_path = create_key_pair_if_needed(key_name, region, log_callback)

        # 3) Security Group
        sg_id = create_security_group_if_needed(
            "AppSecurityGroup", region, log_callback
        )

        # 4) Create user-data
        user_data_script = create_userdata_script(domain, repo_url)

        # 5) Launch EC2
        instance_id, public_dns = launch_ec2_instance(
            ec2_name, key_name, sg_id, region, user_data_script, log_callback
        )

        # 6) Allocate & associate Elastic IP
        alloc_id, eip = allocate_elastic_ip(region, log_callback)
        associate_elastic_ip(instance_id, alloc_id, region, log_callback)
        log_callback(f"[INFO] Your static IP is: {eip}\n")

        # 7) Pause or skip for user DNS
        log_callback("\n--- DNS SETUP STEP ---\n")
        log_callback(
            "[INFO] To enable SSL for your domain, you should point an A-record of "
            f"'{domain}' to '{eip}' now.\n"
            "If you do it now, Let's Encrypt will succeed. If you skip, you'll have to re-run certbot later.\n"
        )
        user_input = (
            input("Type 'done' when DNS is set, or 'skip' to continue anyway: ")
            .strip()
            .lower()
        )
        if user_input != "done":
            log_callback(
                "[WARN] Skipping DNS wait. You must manually set up DNS and rerun certbot if needed.\n"
            )
        else:
            log_callback(
                "[INFO] Great! The instance user-data may succeed obtaining an SSL cert.\n"
            )

        # 8) Optional RDS
        if enable_rds:
            endpoint = create_rds_postgres(
                db_identifier, db_username, db_password, region, log_callback
            )
            # Provide a handy DB connection URL
            db_url = f"postgresql://{db_username}:{db_password}@{endpoint}:5432/{db_identifier}"
            log_callback(f"[INFO] DB Connection URL: {db_url}\n")

        # 9) Provide SSH instructions
        ssh_cmd = f"ssh -i {pem_path} ec2-user@{eip}"
        log_callback(f"\n[INFO] To SSH into your instance:\n  {ssh_cmd}\n")

        log_callback("\n[INFO] All steps completed.\n")
        log_callback(
            "[INFO] Wait a few minutes for the user-data script to finish on the EC2 instance.\n"
            f"[INFO] EC2: http://{eip} or https://{domain} (once SSL is set up)\n"
        )
    except Exception as e:
        log_callback(f"[ERROR] {e}\n")
        sys.exit(1)


###############################################################################
# SIGN OUT HELPER
###############################################################################


def sign_out_aws_credentials(log_callback=None):
    """
    Minimal approach to 'sign out' by unsetting environment variables
    for AWS credentials. Tells the user they may also need to remove
    or rename ~/.aws/credentials if they were using the default profile.

    This won't forcibly remove credentials from your local machine
    but ensures subsequent calls in this same Python process won't use them.
    """
    # Common environment variables that might hold AWS credentials
    env_vars = [
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_PROFILE",
    ]
    for var in env_vars:
        if var in os.environ:
            del os.environ[var]
    msg = "[INFO] Environment credentials cleared. If you want to fully switch accounts, run 'aws configure' again or manually edit ~/.aws/credentials.\n"
    if log_callback:
        log_callback(msg)
    else:
        print(msg)


###############################################################################
# GUI
###############################################################################


def launch_gui():
    """
    Simple tkinter GUI for collecting arguments and deploying.
    Also shows AWS account info at the top if credentials are valid.
    Adds a 'Sign Out' button to unset environment variables.
    """
    root = tk.Tk()
    root.title("AWS Deployment Tool")

    # Check AWS credentials first
    creds_ok, result_str = check_aws_cli_credentials()

    if creds_ok:
        acct_label_text = f"Signed in as account {result_str}"
        acct_label_fg = "blue"
    else:
        acct_label_text = (
            result_str.strip()
        )  # e.g. "AWS CLI not installed or credentials missing..."
        acct_label_fg = "red"

    top_label = tk.Label(root, text=acct_label_text, fg=acct_label_fg)
    top_label.grid(row=0, column=0, columnspan=2, padx=5, pady=5)

    # Default values
    defaults = {
        "aws_region": DEFAULT_REGION,
        "ec2_name": "MyEC2Instance",
        "key_name": "MyKeyPair",
        "domain": "mydomain.com",
        "repo_url": "https://github.com/youruser/yourrepo.git",
        "enable_rds": "no",
        "db_identifier": "myDB",
        "db_username": "admin",
        "db_password": "MyDbPassword123",
    }

    labels = {
        "aws_region": "AWS Region",
        "ec2_name": "EC2 Name",
        "key_name": "Key Pair Name",
        "domain": "Domain Name",
        "repo_url": "Git Repo URL",
        "enable_rds": "Enable RDS (yes/no)",
        "db_identifier": "RDS DB Identifier",
        "db_username": "RDS Username",
        "db_password": "RDS Password",
    }

    entries = {}

    # Create form (start from row=1 because row=0 has the account label)
    row = 1
    for field, label_text in labels.items():
        lbl = tk.Label(root, text=label_text)
        lbl.grid(row=row, column=0, padx=5, pady=5, sticky="e")

        var = tk.StringVar(value=defaults.get(field, ""))
        ent = tk.Entry(root, textvariable=var, width=40)
        ent.grid(row=row, column=1, padx=5, pady=5)
        entries[field] = var
        row += 1

    # Text box for logs
    log_text = tk.Text(root, width=80, height=15)
    log_text.grid(row=row, column=0, columnspan=2, padx=5, pady=5)

    def log_callback(msg):
        log_text.insert(tk.END, msg)
        log_text.see(tk.END)
        root.update()

    def on_deploy():
        # If credentials are not OK, do not proceed
        if not creds_ok:
            log_callback(
                "[ERROR] AWS CLI not ready or credentials missing. Aborting.\n"
            )
            return

        gui_args = argparse.Namespace()
        gui_args.aws_region = entries["aws_region"].get().strip()
        gui_args.ec2_name = entries["ec2_name"].get().strip()
        gui_args.key_name = entries["key_name"].get().strip()
        gui_args.domain = entries["domain"].get().strip()
        gui_args.repo_url = entries["repo_url"].get().strip()
        gui_args.enable_rds = entries["enable_rds"].get().strip()
        gui_args.db_identifier = entries["db_identifier"].get().strip()
        gui_args.db_username = entries["db_username"].get().strip()
        gui_args.db_password = entries["db_password"].get()

        try:
            deploy(gui_args, log_callback)
        except SystemExit as e:
            log_callback(f"[ERROR] {e}\n")

    def on_sign_out():
        """
        Clears environment variables. The next check_aws_cli_credentials would fail
        unless the user reconfigures. Also updates the label to indicate "signed out."
        """
        sign_out_aws_credentials(log_callback)
        top_label.config(
            text="Signed out (credentials cleared). Re-run 'aws configure' to sign in again.",
            fg="red",
        )

    # Deploy button
    btn_deploy = ttk.Button(root, text="Deploy", command=on_deploy)
    btn_deploy.grid(row=row + 1, column=0, pady=10, sticky="e")

    # Sign Out button
    btn_signout = ttk.Button(root, text="Sign Out", command=on_sign_out)
    btn_signout.grid(row=row + 1, column=1, pady=10, sticky="w")

    root.mainloop()


###############################################################################
# CLI
###############################################################################


def parse_args():
    parser = argparse.ArgumentParser(
        description="Automate AWS provisioning for a FastAPI+Gradio app."
    )
    parser.add_argument(
        "--aws-region", default=None, help="AWS Region (default us-west-2)."
    )
    parser.add_argument("--ec2-name", default=None, help="Name for the EC2 instance.")
    parser.add_argument("--key-name", default=None, help="AWS Key Pair name.")
    parser.add_argument(
        "--domain", default=None, help="Domain name (e.g. mydomain.com)."
    )
    parser.add_argument(
        "--repo-url",
        default=None,
        help="Git repo URL (e.g. https://github.com/user/repo.git).",
    )
    parser.add_argument(
        "--enable-rds",
        default="no",
        choices=["yes", "no"],
        help="Provision AWS Postgres RDS? (yes/no)",
    )
    parser.add_argument(
        "--db-identifier", default=None, help="Identifier for the RDS instance."
    )
    parser.add_argument("--db-username", default=None, help="Master username for RDS.")
    parser.add_argument("--db-password", default=None, help="Master password for RDS.")
    parser.add_argument(
        "--no-gui", action="store_true", help="Skip GUI and run from CLI args only."
    )
    return parser.parse_args()


def main():
    args = parse_args()

    # Check if no CLI arguments are given (besides --no-gui), then open GUI
    provided_args = any(
        [
            args.aws_region,
            args.ec2_name,
            args.key_name,
            args.domain,
            args.repo_url,
            args.db_identifier,
            args.db_username,
            args.db_password,
        ]
    )
    if not provided_args and not args.no_gui:
        # Show GUI
        launch_gui()
    else:
        # CLI usage
        def cli_log(msg):
            print(msg, end="", flush=True)

        # First, check credentials in CLI mode
        creds_ok, result_str = check_aws_cli_credentials(cli_log)
        if creds_ok:
            cli_log(f"[INFO] Signed in as account {result_str}\n")
        else:
            cli_log(result_str)
            cli_log("[ERROR] Cannot proceed without valid AWS credentials.\n")
            sys.exit(1)

        # Fill missing with defaults
        def default_val(cur, d):
            return cur if cur else d

        args.aws_region = default_val(args.aws_region, DEFAULT_REGION)
        args.ec2_name = default_val(args.ec2_name, "MyEC2Instance")
        args.key_name = default_val(args.key_name, "MyKeyPair")
        args.domain = default_val(args.domain, "mydomain.com")
        args.repo_url = default_val(
            args.repo_url, "https://github.com/youruser/yourrepo.git"
        )
        args.db_identifier = default_val(args.db_identifier, "myDB")
        args.db_username = default_val(args.db_username, "admin")
        args.db_password = default_val(args.db_password, "MyDbPassword123")

        deploy(args, cli_log)


if __name__ == "__main__":
    main()
