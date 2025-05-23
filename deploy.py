import os
import shlex
import subprocess
import sys
from tempfile import NamedTemporaryFile
from time import sleep

from tqdm import tqdm

from .aws_cli_utils import check_aws_cli_credentials, run_cmd
from .ec2 import launch_ec2_instance  # confirm its signature in ec2.py
from .ec2 import (
    allocate_elastic_ip,
    associate_elastic_ip,
    create_key_pair_if_needed,
    create_security_group_if_needed,
)
from .networking import create_subnet_and_route, create_vpc_if_needed
from .rds import create_rds_postgres


def log(msg: str):
    """Simple logger function to send all output to the terminal."""
    print(msg, end="", flush=True)


def create_minimal_userdata_script():
    """
    Returns a small #cloud-config that only installs essentials.
    This ensures the instance boots quickly without big compiles.
    """
    return """#cloud-config
runcmd:
  - yum update -y
  - yum install -y python3 git
"""


def deploy(args, log=log, progress_callback=None):
    """
    Deployment flow:
      1) Check AWS creds
      2) Create/reuse VPC
      3) Create subnet & route
      4) Create key pair
      5) Create security group
      6) Allocate EIP
      7) Pause for DNS update (if desired)
      8) Launch EC2 with minimal user-data
      9) Wait for instance to be fully 'running' and pass checks
      10) Associate EIP
      11) Create ~/.ssh/config entry
      12) (If local copy) rsync local files (excluding venv, __pycache__)
      13) SSH into instance to compile Python, install certbot, clone code, etc.
      14) Optional RDS
      15) Done
    """

    # 1) Check AWS credentials
    creds_ok, acct = check_aws_cli_credentials(log)
    if not creds_ok:
        log(f"[ERROR] AWS credentials invalid: {acct}\n")
        sys.exit(1)
    log(f"[INFO] AWS account: {acct}\n")

    steps = [
        "Check AWS creds",
        "Create/reuse VPC",
        "Create subnet & route",
        "Create key pair",
        "Create security group",
        "Allocate EIP",
        "Pause for DNS update",
        "Launch EC2 (minimal user-data)",
        "Wait for instance checks",
        "Associate EIP",
        "Create local SSH config",
        "Optional rsync local files",
        "SSH install steps (prompt user yes/no)",
        "Optional RDS",
        "Finish",
    ]
    total = len(steps)
    current = 0

    # If a callback is not provided, use a TQDM progress bar
    if progress_callback:
        progress_callback(current, total)
    else:
        pbar = tqdm(total=total, desc="Deployment", unit="step")

    def step_complete():
        nonlocal current
        current += 1
        if progress_callback:
            progress_callback(current, total)
        else:
            pbar.update(1)

    # Pull out frequently used args
    ec2_name = args.ec2_name
    key_name = args.key_name
    domain = args.domain
    repo_url = getattr(args, "repo_url", None)
    region = os.getenv("AWS_REGION", "us-west-2")  # fallback if not provided
    source_method = getattr(args, "source_method", "git")
    local_path = getattr(args, "local_path", None)
    # If "enable_rds" was toggled in the GUI, user sets "db_identifier", etc.
    enable_rds = (
        getattr(args, "db_identifier", None)
        and getattr(args, "db_username", None)
        and getattr(args, "db_password", None)
    )

    # STEP 1 complete: creds checked
    step_complete()

    # 2) Create or reuse VPC
    vpc_id = create_vpc_if_needed(ec2_name, region, log)
    step_complete()

    # 3) Create subnet & route
    subnet_id = create_subnet_and_route(ec2_name, region, True, vpc_id, log)
    step_complete()

    # 4) Key pair
    pem_path = create_key_pair_if_needed(key_name, region, log)
    step_complete()

    # 5) Security group
    sg_id = create_security_group_if_needed(ec2_name, region, vpc_id, log)
    step_complete()

    # 6) Allocate EIP
    alloc_id, eip = allocate_elastic_ip(ec2_name, region, log)
    log(f"[INFO] Elastic IP allocated: {eip}\n")
    step_complete()

    # 7) Pause for DNS update
    log(
        f"[ACTION REQUIRED] Please create/verify an A-record in DNS for '{domain}' "
        f"pointing to IP {eip}.\n"
    )
    input("[Press ENTER once DNS is updated or if you want to continue anyway]\n")
    step_complete()

    # 8) Launch EC2 with minimal user-data
    minimal_user_data = create_minimal_userdata_script()
    with NamedTemporaryFile(delete=False, mode="w", suffix=".txt") as tmpfile:
        tmpfile.write(minimal_user_data)
        user_data_file = tmpfile.name

    instance_id, public_dns = launch_ec2_instance(
        ec2_name, key_name, sg_id, subnet_id, region, user_data_file, log
    )
    step_complete()

    # 9) Wait for instance to be fully up + pass status checks
    wait_cmd = (
        f"aws ec2 wait instance-running --region {region} --instance-ids {instance_id}"
    )
    run_cmd(wait_cmd, log)
    log(f"[INFO] Instance {instance_id} is in 'running' state.\n")

    wait_cmd_ok = f"aws ec2 wait instance-status-ok --region {region} --instance-ids {instance_id}"
    run_cmd(wait_cmd_ok, log)
    log(f"[INFO] Instance {instance_id} passed status checks.\n")
    step_complete()

    # 10) Associate EIP now that it's running
    associate_elastic_ip(instance_id, alloc_id, region, log)
    log(f"[INFO] Elastic IP {eip} associated with instance {instance_id}.\n")
    step_complete()

    # 11) Create a local ~/.ssh/config entry
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
        log(f"[INFO] Appended SSH config entry to {ssh_config_path}\n")
    except Exception as ex:
        log(f"[WARNING] Could not write SSH config: {ex}\n")
    step_complete()

    # 12) If using local copy, rsync local files (excluding venv and __pycache__)
    if source_method == "copy":
        if not local_path:
            log("[ERROR] local_path not provided for copy method.\n")
            sys.exit(1)

        log(
            "[WARNING] Using rsync instead of scp. Excluding 'venv' and '__pycache__' directories.\n"
        )

        copy_cmd = f"""rsync -av \
  --exclude='venv' \
  --exclude='__pycache__' \
  -e "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null" \
  {shlex.quote(local_path)} \
  {ec2_name}:/home/ec2-user/
"""
        run_cmd(copy_cmd, log)
        log(
            f"[INFO] Copied local path {local_path} to /home/ec2-user/ (excluding venv & __pycache__).\n"
        )
    else:
        log("[INFO] Skipping local copy step (source_method != copy).\n")
    step_complete()

    # 13) Prompt user before doing SSH-based install steps
    log("\n===== Step 13: SSH-based install steps =====\n")
    answer = (
        input(
            "Type 'yes' to continue automatically installing Python, certbot, etc. "
            "Type 'no' to skip this step and do it manually.\n"
        )
        .strip()
        .lower()
    )

    if answer == "no":
        log("[INFO] Skipping automatic SSH steps. Please perform them manually.\n")
        step_complete()
    else:
        # Proceed with automatic SSH steps
        skip_compile = not ("python_source" in getattr(args, "components", []))
        skip_certbot = not ("certbot" in getattr(args, "components", []))
        # Build script
        install_script = []

        # Optionally compile Python
        if not skip_compile:
            install_script.append(
                """\
cd /tmp
curl -LO https://www.python.org/ftp/python/3.12.8/Python-3.12.8.tgz
tar xzf Python-3.12.8.tgz
cd Python-3.12.8
./configure --enable-optimizations
make -j 2
make altinstall
python3.12 --version
python3.12 -m venv /home/ec2-user/venv
/home/ec2-user/venv/bin/pip install --upgrade pip
"""
            )

        # Optionally install certbot + apache
        if not skip_certbot:
            install_script.append(
                f"""\
yum install -y httpd mod_ssl certbot python3-certbot-apache
systemctl enable httpd
systemctl start httpd

# Step 2: Configure a VirtualHost on port 80 for {domain}
mkdir -p /etc/httpd/conf.d
cat <<EOF >/etc/httpd/conf.d/{domain}.conf
<VirtualHost *:80>
    ServerName {domain}
    DocumentRoot /var/www/html
</VirtualHost>
EOF

systemctl restart httpd

"""
            )
        # # Step 3: Re-run certbot (now that port 80 is serving)
        # certbot --apache --non-interactive --agree-tos -d {domain} -m admin@{domain} || true

        # If using git:
        if source_method == "git" and repo_url:
            install_script.append(
                f"""\
mkdir -p /home/ec2-user/app
cd /home/ec2-user/app
git init
git remote add origin {repo_url}
git pull origin main
chown -R ec2-user:ec2-user /home/ec2-user/app
if [ -f /home/ec2-user/venv/bin/pip ]; then
  /home/ec2-user/venv/bin/pip install fastapi gradio uvicorn supervisor
fi
"""
            )

        final_install_script = "\n".join(install_script).strip()
        if final_install_script:
            script_filename = "post_launch_setup.sh"
            with open(script_filename, "w") as f:
                f.write(final_install_script + "\n")

            scp_script_cmd = f"scp {script_filename} {ec2_name}:/home/ec2-user/"
            run_cmd(scp_script_cmd, log)

            ssh_cmd = f"ssh {ec2_name} 'sudo bash /home/ec2-user/{script_filename}'"
            run_cmd(ssh_cmd, log)
            log("[INFO] Finished post-launch install steps.\n")
        else:
            log("[INFO] No SSH steps needed (all were disabled or empty).\n")

        step_complete()

    # 14) Optional RDS
    if enable_rds:
        db_id = args.db_identifier
        db_user = args.db_username
        db_pass = args.db_password
        endpoint = create_rds_postgres(db_id, db_user, db_pass, region, log)
        log(f"[INFO] RDS endpoint: {endpoint}\n")

    step_complete()

    # 15) Done
    if not progress_callback:
        pbar.close()

    log("\n[INFO] Deployment complete!\n")
    log(f"[INFO] SSH example: ssh {ec2_name}\n")
    log(f"[INFO] Domain: {domain} => {eip}\n")


import textwrap

# One multi-line shell script kept in a single Python string
PYTHON_INSTALL_CMDS = textwrap.dedent(
    """
    # 1) make sure metadata is fresh (quick, no full upgrade)
    sudo dnf -y makecache

    # 2) install Python 3.12 and dev headers from the AL2023 repos
    sudo dnf -y install python3.12 python3.12-devel

    # 3) create a project-level virtual-env in your home dir
    python3.12 -m venv ~/venv312

    # 4) activate and bootstrap pip/wheel/setuptools
    source ~/venv312/bin/activate
    python -m pip install --upgrade pip wheel setuptools
    """
).strip()
