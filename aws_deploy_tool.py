#!/usr/bin/env python3
"""
aws_deploy_tool.py

Automates AWS provisioning for a FastAPI+Gradio (or similar) app on Amazon Linux EC2 (t3.micro).
Optionally includes RDS Postgres. Provides a tkinter GUI or command-line usage.

Now includes:
- Choice of subnet type (public w/ IGW or outbound-only w/ NAT).
- All resource names include the EC2 name to keep them organized.
- Hides the RDS fields if user doesn't enable RDS in the GUI.

Default Region: us-west-2
"""

import subprocess
import argparse
import sys
import shlex
import os
import shutil
import json

# For the optional GUI
import tkinter as tk
from tkinter import ttk

###############################################################################
# Global constants and defaults
###############################################################################

DEFAULT_REGION = "us-west-2"
# Amazon Linux 2 AMI for us-west-2, x86_64.
DEFAULT_AMI = "ami-05572e392e80aee89"


###############################################################################
# AWS CLI / Credential Checks
###############################################################################


def check_aws_cli_credentials(log_callback=None):
    """
    Checks if AWS CLI is installed and if credentials are configured.
    Returns (True, account_id_str) if credentials exist, else (False, error_message).
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
            msg = (
                f"[WARN] AWS CLI credentials not found or invalid:\n{stderr}\n"
                "Please run 'aws configure' or set AWS credentials before proceeding.\n"
            )
            return (False, msg)
        account_id = stdout.strip()
        return (True, account_id)
    except FileNotFoundError:
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
# AWS Resource Creation: VPC, Subnet, IGW or NAT
###############################################################################


def create_vpc_if_needed(ec2_name, region, log_callback):
    """
    Creates a VPC named <ec2_name>-vpc if it doesn't exist, or reuses it if found.
    Returns the VPC ID.
    """
    # See if there's already a VPC with our tag "Name=<ec2_name>-vpc"
    filter_name = f"{ec2_name}-vpc"
    describe_cmd = (
        f"aws ec2 describe-vpcs --region {region} "
        f"--filters Name=tag:Name,Values={filter_name}"
    )
    stdout, _ = run_cmd(describe_cmd, log_callback, check=False)

    vpc_id = None
    if '"VpcId":' in stdout:
        try:
            data = json.loads(stdout)
            vpc_id = data["Vpcs"][0]["VpcId"]
            log_callback(f"[INFO] Reusing existing VPC {vpc_id} ({filter_name}).\n")
        except Exception:
            pass

    if not vpc_id:
        log_callback(f"[INFO] Creating new VPC: {filter_name}\n")
        cidr_block = "10.0.0.0/16"
        create_cmd = (
            f"aws ec2 create-vpc --cidr-block {cidr_block} --region {region} "
            f"--query 'Vpc.VpcId' --output text"
        )
        stdout, _ = run_cmd(create_cmd, log_callback)
        vpc_id = stdout.strip()
        # Tag the VPC with a Name
        tag_cmd = (
            f"aws ec2 create-tags --resources {vpc_id} "
            f"--tags Key=Name,Value={filter_name} --region {region}"
        )
        run_cmd(tag_cmd, log_callback)
        log_callback(f"[INFO] Created and tagged VPC: {vpc_id}\n")

        # Enable DNS hostname support
        modify_cmd = f"aws ec2 modify-vpc-attribute --vpc-id {vpc_id} --enable-dns-hostnames --region {region}"
        run_cmd(modify_cmd, log_callback)

    return vpc_id


def create_subnet_and_route(ec2_name, region, use_public_subnet, vpc_id, log_callback):
    """
    Creates a single subnet (public or NAT outbound-only) in the given VPC.
    If public, attaches an IGW and sets a route to 0.0.0.0/0.
    If NAT, creates an EIP + NAT Gateway + route.
    Returns the subnet_id to be used for EC2 launches.

    For simplicity, we pick a single subnet CIDR and put it in e.g. AZ a.
    """
    # 1) Create Subnet
    subnet_filter_name = f"{ec2_name}-subnet"
    describe_cmd = (
        f"aws ec2 describe-subnets --region {region} "
        f"--filters Name=tag:Name,Values={subnet_filter_name} Name=vpc-id,Values={vpc_id}"
    )
    stdout, _ = run_cmd(describe_cmd, log_callback, check=False)

    subnet_id = None
    if '"SubnetId":' in stdout:
        try:
            data = json.loads(stdout)
            subnet_id = data["Subnets"][0]["SubnetId"]
            log_callback(
                f"[INFO] Reusing existing subnet {subnet_id} ({subnet_filter_name}).\n"
            )
        except Exception:
            pass

    if not subnet_id:
        # For simplicity, let's place this in the first availability zone.
        az_cmd = (
            f"aws ec2 describe-availability-zones --region {region} "
            f"--query 'AvailabilityZones[0].ZoneName' --output text"
        )
        stdout, _ = run_cmd(az_cmd, log_callback)
        zone_name = stdout.strip()

        log_callback(f"[INFO] Creating Subnet: {subnet_filter_name}, AZ={zone_name}\n")
        # We'll use 10.0.1.0/24 for this subnet
        create_subnet_cmd = (
            f"aws ec2 create-subnet --vpc-id {vpc_id} --cidr-block 10.0.1.0/24 "
            f"--availability-zone {zone_name} --region {region} "
            f"--query 'Subnet.SubnetId' --output text"
        )
        stdout, _ = run_cmd(create_subnet_cmd, log_callback)
        subnet_id = stdout.strip()
        # Tag the subnet
        tag_cmd = (
            f"aws ec2 create-tags --resources {subnet_id} --region {region} "
            f"--tags Key=Name,Value={subnet_filter_name}"
        )
        run_cmd(tag_cmd, log_callback)
        log_callback(f"[INFO] Created and tagged subnet: {subnet_id}\n")

    # 2) Create or reuse a Route Table for this subnet
    rtb_filter_name = f"{ec2_name}-rtb"
    describe_rtb = (
        f"aws ec2 describe-route-tables --region {region} "
        f"--filters Name=tag:Name,Values={rtb_filter_name} Name=vpc-id,Values={vpc_id}"
    )
    stdout, _ = run_cmd(describe_rtb, log_callback, check=False)

    rtb_id = None
    if '"RouteTableId":' in stdout:
        try:
            data = json.loads(stdout)
            rtb_id = data["RouteTables"][0]["RouteTableId"]
            log_callback(f"[INFO] Reusing route table {rtb_id} ({rtb_filter_name}).\n")
        except Exception:
            pass

    if not rtb_id:
        log_callback(f"[INFO] Creating new route table: {rtb_filter_name}\n")
        create_rtb_cmd = (
            f"aws ec2 create-route-table --vpc-id {vpc_id} --region {region} "
            f"--query 'RouteTable.RouteTableId' --output text"
        )
        stdout, _ = run_cmd(create_rtb_cmd, log_callback)
        rtb_id = stdout.strip()
        # Tag it
        tag_cmd = (
            f"aws ec2 create-tags --resources {rtb_id} --region {region} "
            f"--tags Key=Name,Value={rtb_filter_name}"
        )
        run_cmd(tag_cmd, log_callback)

    # Associate the route table to our subnet
    assoc_cmd = f"aws ec2 associate-route-table --route-table-id {rtb_id} --subnet-id {subnet_id} --region {region}"
    run_cmd(assoc_cmd, log_callback, check=False)  # if repeated, won't fail

    # 3) If we want a "public" subnet, create or reuse an IGW, attach, route 0.0.0.0/0
    #    If outbound-only, create NAT Gateway.
    if use_public_subnet:
        # IGW
        igw_filter_name = f"{ec2_name}-igw"
        desc_igw_cmd = (
            f"aws ec2 describe-internet-gateways --region {region} "
            f'--filters Name=tag:Name,Values="{igw_filter_name}"'
        )
        stdout, _ = run_cmd(desc_igw_cmd, log_callback, check=False)

        igw_id = None
        if '"InternetGatewayId":' in stdout:
            try:
                data = json.loads(stdout)
                igw_id = data["InternetGateways"][0]["InternetGatewayId"]
                log_callback(f"[INFO] Reusing IGW {igw_id} ({igw_filter_name}).\n")
            except Exception:
                pass

        if not igw_id:
            # Create new
            log_callback(f"[INFO] Creating Internet Gateway: {igw_filter_name}\n")
            create_igw_cmd = (
                f"aws ec2 create-internet-gateway --region {region} "
                f"--query 'InternetGateway.InternetGatewayId' --output text"
            )
            stdout, _ = run_cmd(create_igw_cmd, log_callback)
            igw_id = stdout.strip()
            # Tag it
            tag_cmd = (
                f"aws ec2 create-tags --resources {igw_id} --region {region} "
                f'--tags Key=Name,Value="{igw_filter_name}"'
            )
            run_cmd(tag_cmd, log_callback)

            # Attach to VPC
            attach_cmd = f"aws ec2 attach-internet-gateway --internet-gateway-id {igw_id} --vpc-id {vpc_id} --region {region}"
            run_cmd(attach_cmd, log_callback)

        # Create route to 0.0.0.0/0
        create_route_cmd = (
            f"aws ec2 create-route --route-table-id {rtb_id} "
            f"--destination-cidr-block 0.0.0.0/0 --gateway-id {igw_id} "
            f"--region {region}"
        )
        run_cmd(create_route_cmd, log_callback, check=False)
        # For a public subnet, also ensure auto-assign public IP
        modify_subnet_cmd = (
            f"aws ec2 modify-subnet-attribute --subnet-id {subnet_id} "
            f"--map-public-ip-on-launch --region {region}"
        )
        run_cmd(modify_subnet_cmd, log_callback)
        log_callback("[INFO] Public subnet setup complete.\n")

    else:
        # NAT Gateway
        nat_filter_name = f"{ec2_name}-natgw"
        # We need an EIP for the NAT GW
        log_callback(f"[INFO] Creating EIP for NAT Gateway: {nat_filter_name}\n")
        eip_cmd = f"aws ec2 allocate-address --domain vpc --region {region} --query 'AllocationId' --output text"
        stdout, _ = run_cmd(eip_cmd, log_callback)
        allocation_id = stdout.strip()

        # Create NAT Gateway
        log_callback(f"[INFO] Creating NAT Gateway: {nat_filter_name}\n")
        nat_create_cmd = (
            f"aws ec2 create-nat-gateway --subnet-id {subnet_id} "
            f"--allocation-id {allocation_id} --region {region} "
            f"--query 'NatGateway.NatGatewayId' --output text"
        )
        stdout, _ = run_cmd(nat_create_cmd, log_callback)
        natgw_id = stdout.strip()
        # Tag NAT Gateway
        tag_cmd = (
            f"aws ec2 create-tags --resources {natgw_id} --region {region} "
            f'--tags Key=Name,Value="{nat_filter_name}"'
        )
        run_cmd(tag_cmd, log_callback)

        # Wait until NAT is available
        wait_cmd = f"aws ec2 wait nat-gateway-available --nat-gateway-ids {natgw_id} --region {region}"
        run_cmd(wait_cmd, log_callback)

        # Finally, create a route to 0.0.0.0/0 via NAT
        create_route_cmd = (
            f"aws ec2 create-route --route-table-id {rtb_id} "
            f"--destination-cidr-block 0.0.0.0/0 --nat-gateway-id {natgw_id} "
            f"--region {region}"
        )
        run_cmd(create_route_cmd, log_callback, check=False)

        # We do NOT automatically map public IP on launch,
        # because it’s outbound-only. But your instance can
        # talk out if it needs to do e.g. OS updates, pip installs.
        log_callback("[INFO] Outbound-only subnet setup complete.\n")

    return subnet_id


###############################################################################
# Other Resource Creation
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
    Checks if the given Key Pair exists. If not, creates it locally, moves to ~/.ssh.
    Returns the path to the .pem.
    """
    cmd_check = f"aws ec2 describe-key-pairs --key-names {key_name} --region {region}"
    _, stderr = run_cmd(cmd_check, log_callback=log_callback, check=False)
    if "InvalidKeyPair.NotFound" in stderr:
        log_callback(f"[INFO] Creating Key Pair '{key_name}'...\n")
        cmd_create = (
            f"aws ec2 create-key-pair --key-name {key_name} "
            f"--region {region} --query 'KeyMaterial' --output text"
        )
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
        guessed_path = os.path.join(os.path.expanduser("~"), ".ssh", f"{key_name}.pem")
        return guessed_path


def create_security_group_if_needed(ec2_name, region, vpc_id, log_callback):
    """
    Creates or reuses a Security Group named <ec2_name>-sg. Opens inbound 22,80,443.
    Returns the Security Group ID.
    """
    sg_name = f"{ec2_name}-sg"
    cmd_describe = (
        f"aws ec2 describe-security-groups --filters Name=group-name,Values={sg_name} "
        f"--region {region} --query 'SecurityGroups[*].GroupId' --output text"
    )
    stdout, _ = run_cmd(cmd_describe, log_callback=log_callback, check=False)

    if stdout.strip():
        sg_id = stdout.strip()
        log_callback(f"[INFO] Security Group '{sg_name}' already exists: {sg_id}\n")
        return sg_id

    log_callback(f"[INFO] Creating Security Group '{sg_name}'...\n")
    create_cmd = (
        f"aws ec2 create-security-group --group-name {sg_name} "
        f"--description 'AppSecurityGroup' --vpc-id {vpc_id} --region {region} "
        f"--query 'GroupId' --output text"
    )
    sg_out, _ = run_cmd(create_cmd, log_callback=log_callback)
    sg_id = sg_out.strip()

    # Tag the SG
    tag_cmd = (
        f"aws ec2 create-tags --resources {sg_id} --region {region} "
        f"--tags Key=Name,Value={sg_name}"
    )
    run_cmd(tag_cmd, log_callback)

    # Authorize inbound rules (22,80,443)
    ports = [22, 80, 443]
    for p in ports:
        auth_cmd = (
            f"aws ec2 authorize-security-group-ingress --group-id {sg_id} "
            f"--protocol tcp --port {p} --cidr 0.0.0.0/0 --region {region}"
        )
        run_cmd(auth_cmd, log_callback)

    log_callback(f"[INFO] Security Group created: {sg_id}\n")
    return sg_id


def allocate_elastic_ip(region, log_callback):
    """
    Allocates a new Elastic IP address, returns (allocation_id, public_ip).
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
    Provisions a Postgres RDS (db.t3.micro). Waits until available, returns endpoint.
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
    Writes a cloud-init script for Amazon Linux 2. Installs Python 3.12.8, Git, Apache, Certbot, etc.
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

  # Attempt to get SSL cert
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
    ec2_name, key_name, sg_id, subnet_id, region, user_data_script, log_callback
):
    """
    Launch a t3.micro Amazon Linux 2 instance into the specified subnet.
    Wait until 'running'; return (instance_id, public_dns).
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
        --subnet-id {subnet_id} \
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
      - Check AWS creds
      - Create/reuse VPC, Subnet (public or NAT)
      - Key Pair
      - Security Group
      - EC2 + EIP
      - (Optional) RDS
      - Show SSH instructions
    """
    try:
        region = args.aws_region
        ec2_name = args.ec2_name
        key_name = args.key_name
        domain = args.domain
        repo_url = args.repo_url

        use_public_subnet = args.subnet_type.lower() == "public"
        enable_rds = args.enable_rds.lower() == "yes"
        db_identifier = args.db_identifier
        db_username = args.db_username
        db_password = args.db_password

        # 1) Check AWS credentials
        creds_ok, result_str = check_aws_cli_credentials(log_callback)
        if creds_ok:
            log_callback(f"[INFO] Signed in as account {result_str}\n")
        else:
            log_callback(result_str)
            log_callback("[ERROR] Cannot proceed without valid AWS credentials.\n")
            return

        # 2) Create/Re-use VPC
        vpc_id = create_vpc_if_needed(ec2_name, region, log_callback)

        # 3) Create Subnet (public or NAT)
        subnet_id = create_subnet_and_route(
            ec2_name, region, use_public_subnet, vpc_id, log_callback
        )

        # 4) Create Key Pair if needed
        pem_path = create_key_pair_if_needed(key_name, region, log_callback)

        # 5) Create Security Group
        sg_id = create_security_group_if_needed(ec2_name, region, vpc_id, log_callback)

        # 6) Create user-data script
        user_data_script = create_userdata_script(domain, repo_url)

        # 7) Launch EC2
        instance_id, public_dns = launch_ec2_instance(
            ec2_name, key_name, sg_id, subnet_id, region, user_data_script, log_callback
        )

        # 8) Allocate & associate Elastic IP (so you have a stable IP)
        alloc_id, eip = allocate_elastic_ip(region, log_callback)
        associate_elastic_ip(instance_id, alloc_id, region, log_callback)
        log_callback(f"[INFO] Your static IP is: {eip}\n")

        # Domain reminder
        log_callback("\n--- DNS SETUP STEP ---\n")
        log_callback(
            "[INFO] To enable SSL for your domain, point an A-record for:\n"
            f"   {domain}  -->  {eip}\n"
            "Once that's in place, certbot on the instance can get valid certs.\n"
        )

        # 9) Optional RDS
        if enable_rds:
            endpoint = create_rds_postgres(
                db_identifier, db_username, db_password, region, log_callback
            )
            db_url = f"postgresql://{db_username}:{db_password}@{endpoint}:5432/{db_identifier}"
            log_callback(f"[INFO] DB Connection URL: {db_url}\n")

        # 10) Provide SSH instructions
        ssh_cmd = f"ssh -i {pem_path} ec2-user@{eip}"
        log_callback(f"\n[INFO] To SSH into your instance:\n  {ssh_cmd}\n")

        log_callback("\n[INFO] All steps completed.\n")
        log_callback(
            "[INFO] Wait a few minutes for the user-data script to finish on the EC2 instance.\n"
            f"[INFO] EC2 test URL: http://{eip} (or https://{domain} if you set up DNS).\n"
        )
    except Exception as e:
        log_callback(f"[ERROR] {e}\n")
        sys.exit(1)


###############################################################################
# SIGN OUT HELPER
###############################################################################


def sign_out_aws_credentials(log_callback=None):
    """
    Minimal approach to 'sign out' by unsetting environment variables.
    """
    env_vars = [
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_PROFILE",
    ]
    for var in env_vars:
        if var in os.environ:
            del os.environ[var]
    msg = "[INFO] Environment credentials cleared. If you want to switch accounts, run 'aws configure' again.\n"
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

    Includes:
    - Subnet Type (public or NAT).
    - RDS fields hidden unless "Enable RDS" is "yes."
    """
    root = tk.Tk()
    root.title("AWS Deployment Tool")

    # Check AWS credentials first
    creds_ok, result_str = check_aws_cli_credentials()

    if creds_ok:
        acct_label_text = f"Signed in as account {result_str}"
        acct_label_fg = "blue"
    else:
        acct_label_text = result_str.strip()
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
        "subnet_type": "public",  # or "nat"
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
        "subnet_type": "Subnet Type (public/nat)",
        "enable_rds": "Enable RDS (yes/no)",
        "db_identifier": "RDS DB Identifier",
        "db_username": "RDS Username",
        "db_password": "RDS Password",
    }

    # For storing input variables
    entries = {}

    row = 1
    for field, label_text in labels.items():
        lbl = tk.Label(root, text=label_text)
        lbl.grid(row=row, column=0, padx=5, pady=5, sticky="e")

        var = tk.StringVar(value=defaults.get(field, ""))
        ent = tk.Entry(root, textvariable=var, width=40)
        ent.grid(row=row, column=1, padx=5, pady=5)
        entries[field] = var
        row += 1

    # Our RDS fields are at the bottom (db_identifier, db_username, db_password).
    # We'll hide them if enable_rds = "no."
    # We can do so by hooking a trace on enable_rds.
    def on_enable_rds_change(*_):
        if entries["enable_rds"].get().lower() == "yes":
            # Show the RDS fields
            db_id_label.grid()
            db_id_entry.grid()
            db_user_label.grid()
            db_user_entry.grid()
            db_pass_label.grid()
            db_pass_entry.grid()
        else:
            # Hide the RDS fields
            db_id_label.grid_remove()
            db_id_entry.grid_remove()
            db_user_label.grid_remove()
            db_user_entry.grid_remove()
            db_pass_label.grid_remove()
            db_pass_entry.grid_remove()

    entries["enable_rds"].trace("w", on_enable_rds_change)

    # Move references for the DB labels/entries so we can hide them easily:
    db_id_label = tk.Label(root, text="RDS DB Identifier")
    db_id_label.grid(row=7, column=0, sticky="e", padx=5, pady=5)
    db_id_entry = tk.Entry(root, textvariable=entries["db_identifier"], width=40)
    db_id_entry.grid(row=7, column=1, padx=5, pady=5)

    db_user_label = tk.Label(root, text="RDS Username")
    db_user_label.grid(row=8, column=0, sticky="e", padx=5, pady=5)
    db_user_entry = tk.Entry(root, textvariable=entries["db_username"], width=40)
    db_user_entry.grid(row=8, column=1, padx=5, pady=5)

    db_pass_label = tk.Label(root, text="RDS Password")
    db_pass_label.grid(row=9, column=0, sticky="e", padx=5, pady=5)
    db_pass_entry = tk.Entry(
        root, textvariable=entries["db_password"], width=40, show="*"
    )
    db_pass_entry.grid(row=9, column=1, padx=5, pady=5)

    # Initialize correct visibility on launch
    on_enable_rds_change()

    # Text box for logs
    log_text = tk.Text(root, width=80, height=15)
    log_text.grid(row=10, column=0, columnspan=2, padx=5, pady=5)

    def log_callback(msg):
        log_text.insert(tk.END, msg)
        log_text.see(tk.END)
        root.update()

    def on_deploy():
        if not creds_ok:
            log_callback("[ERROR] AWS CLI not ready or credentials missing.\n")
            return

        gui_args = argparse.Namespace()
        gui_args.aws_region = entries["aws_region"].get().strip()
        gui_args.ec2_name = entries["ec2_name"].get().strip()
        gui_args.key_name = entries["key_name"].get().strip()
        gui_args.domain = entries["domain"].get().strip()
        gui_args.repo_url = entries["repo_url"].get().strip()
        gui_args.subnet_type = entries["subnet_type"].get().strip()
        gui_args.enable_rds = entries["enable_rds"].get().strip()
        gui_args.db_identifier = entries["db_identifier"].get().strip()
        gui_args.db_username = entries["db_username"].get().strip()
        gui_args.db_password = entries["db_password"].get()

        try:
            deploy(gui_args, log_callback)
        except SystemExit as e:
            log_callback(f"[ERROR] {e}\n")

    def on_sign_out():
        sign_out_aws_credentials(log_callback)
        top_label.config(
            text="Signed out (credentials cleared). Re-run 'aws configure' to sign in again.",
            fg="red",
        )

    # Deploy button
    btn_deploy = ttk.Button(root, text="Deploy", command=on_deploy)
    btn_deploy.grid(row=11, column=0, pady=10, sticky="e")

    # Sign Out button
    btn_signout = ttk.Button(root, text="Sign Out", command=on_sign_out)
    btn_signout.grid(row=11, column=1, pady=10, sticky="w")

    root.mainloop()


###############################################################################
# CLI
###############################################################################


def parse_args():
    parser = argparse.ArgumentParser(
        description="Automate AWS provisioning for a FastAPI+Gradio app, with optional RDS."
    )
    parser.add_argument(
        "--aws-region", default=None, help="AWS Region (default us-west-2)"
    )
    parser.add_argument("--ec2-name", default=None, help="Name for the EC2 instance")
    parser.add_argument("--key-name", default=None, help="AWS Key Pair name")
    parser.add_argument("--domain", default=None, help="Domain name (mydomain.com)")
    parser.add_argument("--repo-url", default=None, help="Git repo URL (https://...)")
    parser.add_argument(
        "--subnet-type",
        default="public",
        choices=["public", "nat"],
        help="Subnet type: public (IGW) or nat (outbound-only). Default=public",
    )
    parser.add_argument(
        "--enable-rds",
        default="no",
        choices=["yes", "no"],
        help="Provision Postgres RDS? (yes/no)",
    )
    parser.add_argument("--db-identifier", default=None, help="RDS DB Identifier")
    parser.add_argument("--db-username", default=None, help="RDS Master Username")
    parser.add_argument("--db-password", default=None, help="RDS Master Password")
    parser.add_argument(
        "--no-gui", action="store_true", help="Run CLI-only (skip tkinter GUI)"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    # If user passes no arguments (besides --no-gui), launch GUI.
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
        launch_gui()
    else:
        # CLI usage
        def cli_log(msg):
            print(msg, end="", flush=True)

        # Check credentials
        creds_ok, result_str = check_aws_cli_credentials(cli_log)
        if not creds_ok:
            cli_log(result_str)
            cli_log("[ERROR] Cannot proceed without valid AWS credentials.\n")
            sys.exit(1)
        else:
            cli_log(f"[INFO] Signed in as account {result_str}\n")

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
        # We'll set a default DB identifier that includes the EC2 name for clarity
        default_db = f"{args.ec2_name}-db"
        args.db_identifier = default_val(args.db_identifier, default_db)
        args.db_username = default_val(args.db_username, "admin")
        args.db_password = default_val(args.db_password, "MyDbPassword123")

        deploy(args, cli_log)


if __name__ == "__main__":
    main()
