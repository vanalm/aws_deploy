import os
import sys
import subprocess
import shlex
from time import sleep
from tempfile import NamedTemporaryFile

from tqdm import tqdm

from .aws_cli_utils import check_aws_cli_credentials, run_cmd
from .networking import create_vpc_if_needed, create_subnet_and_route
from .ec2 import (
    create_key_pair_if_needed,
    create_security_group_if_needed,
    allocate_elastic_ip,
    associate_elastic_ip,
    launch_ec2_instance,  # <-- confirm its signature in ec2.py
)
from .rds import create_rds_postgres
from .userdata import create_userdata_script  # kept here if needed for other flows


def log(msg: str):
    """Simple logger function."""
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


def deploy(args, log, progress_callback=None):
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
      12) (If local copy) scp local files
      13) SSH into instance to compile Python, install certbot, clone code, etc.
      14) Optional RDS
      15) Done

    `progress_callback(current_step, total_steps)` can be used by a GUI to show progress.
    """
    # 1) Check AWS credentials
    creds_ok, acct = check_aws_cli_credentials(log)
    if not creds_ok:
        log(f"[ERROR] AWS credentials invalid: {acct}\n")
        if progress_callback:
            # Return gracefully if being invoked by a GUI
            return
        else:
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
        "Optional SCP local files",
        "SSH install steps",
        "Optional RDS",
        "Finish",
    ]
    total = len(steps)
    current = 0

    # If the GUI gives us a progress_callback, we use it; else we use a TQDM progress bar in CLI mode
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
    repo_url = args.repo_url
    region = os.getenv("AWS_REGION", "us-west-2")  # fallback if not provided
    source_method = getattr(args, "source_method", "git")
    local_path = getattr(args, "local_path", None)
    enable_rds = (getattr(args, "enable_rds", "no").lower() == "yes")

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
    # We'll write that text to a temporary file, since many AWS calls want a file path
    with NamedTemporaryFile(delete=False, mode="w", suffix=".txt") as tmpfile:
        tmpfile.write(minimal_user_data)
        user_data_file = tmpfile.name

    # Make sure you match the actual signature for launch_ec2_instance in your ec2.py.
    # For example, if it expects (ec2_name, key_name, sg_id, subnet_id, region, user_data_file)
    # plus maybe a final 'log' argument. If it does NOT accept a 'log' keyword, pass it positionally or remove it:
    instance_id, public_dns = launch_ec2_instance(
        ec2_name,
        key_name,
        sg_id,
        subnet_id,
        region,
        user_data_file,
        log  # remove if your function doesn't accept it
    )
    step_complete()

    # 9) Wait for instance to be fully up + pass status checks
    wait_cmd = f"aws ec2 wait instance-running --region {region} --instance-ids {instance_id}"
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

    # 11) Create a local ~/.ssh/config entry for convenience
    ssh_config_path = os.path.expanduser("~/.ssh/config")
    config_lines = [
        f"\n# Auto-added by deploy script for {ec2_name}",
        f"Host {ec2_name}",
        f"  HostName {eip}",
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

    # 12) If using local copy, scp local files
    if source_method == "copy":
        if not local_path:
            log("[ERROR] local_path not provided for copy method.\n")
            if progress_callback:
                return
            else:
                sys.exit(1)
        # copy_cmd = f"scp -r {shlex.quote(local_path)} {ec2_name}:/home/ec2-user/"
        copy_cmd = f"scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -r {local_path} {ec2_name}:/home/ec2-user/"
        run_cmd(copy_cmd, log)
        log(f"[INFO] Copied local path {local_path} to /home/ec2-user/.\n")
    else:
        log("[INFO] Skipping local copy step (source_method != copy).\n")
    step_complete()

    # 13) SSH-based install steps (compile Python, install certbot, clone from git, etc.)
    skip_compile = getattr(args, "skip_compile", False)
    skip_certbot = getattr(args, "skip_certbot", False)

    install_script = []

    # Optionally compile Python from source
    if not skip_compile:
        install_script.append("""\
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
""")

    # Optionally install certbot, run Apache
    if not skip_certbot:
        install_script.append(f"""\
yum install -y httpd mod_ssl certbot python3-certbot-apache
systemctl enable httpd
systemctl start httpd
certbot --apache --non-interactive --agree-tos -d {domain} -m admin@{domain} || true
""")

    # If user selected git
    if source_method == "git":
        install_script.append(f"""\
mkdir -p /home/ec2-user/app
cd /home/ec2-user/app
git init
git remote add origin {repo_url}
git pull origin main
chown -R ec2-user:ec2-user /home/ec2-user/app
# If we built Python 3.12 above, we have a venv:
if [ -f /home/ec2-user/venv/bin/pip ]; then
  /home/ec2-user/venv/bin/pip install fastapi gradio uvicorn supervisor
fi
""")

    # Combine the script
    final_install_script = "\n".join(install_script).strip()

    if final_install_script:
        # Write to a local file, then scp it and run it
        script_filename = "post_launch_setup.sh"
        with open(script_filename, "w") as f:
            f.write(final_install_script + "\n")

        scp_script_cmd = f"scp {script_filename} {ec2_name}:/home/ec2-user/"
        run_cmd(scp_script_cmd, log)

        ssh_cmd = f"ssh {ec2_name} 'sudo bash /home/ec2-user/{script_filename}'"
        run_cmd(ssh_cmd, log)
        log("[INFO] Finished post-launch install steps.\n")
    else:
        log("[INFO] Skipping SSH install steps (both compile and certbot were skipped, or no code to clone).\n")

    step_complete()

    # 14) Optional RDS
    if enable_rds:
        db_id = getattr(args, "db_identifier", f"{ec2_name}-db")
        db_user = getattr(args, "db_username", "admin")
        db_pass = getattr(args, "db_password", None)

        if db_pass is None:
            log("[ERROR] DB password not provided for RDS.\n")
            if progress_callback:
                return
            else:
                sys.exit(1)

        endpoint = create_rds_postgres(db_id, db_user, db_pass, region, log)
        log(f"[INFO] RDS endpoint: {endpoint}\n")

    step_complete()

    # 15) Done
    if not progress_callback:
        pbar.close()

    log("\n[INFO] Deployment complete!\n")
    log(f"[INFO] SSH example: ssh {ec2_name}\n")
    log(f"[INFO] Domain: {domain} => {eip}\n")
    if not skip_certbot:
        log("[INFO] Certbot was run to obtain SSL cert (assuming DNS was in place).\n")
    else:
        log("[INFO] Certbot was skipped.\n")