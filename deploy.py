import os
import sys
import subprocess

from tqdm import tqdm

from .aws_cli_utils import check_aws_cli_credentials, run_cmd
from .networking import create_vpc_if_needed, create_subnet_and_route
from .ec2 import (
    create_key_pair_if_needed,
    create_security_group_if_needed,
    allocate_elastic_ip,
    associate_elastic_ip,
    launch_ec2_instance,
)
from .rds import create_rds_postgres
from .userdata import create_userdata_script


def log(msg: str):
    """Simple logger."""
    print(msg, end="", flush=True)


def deploy(args, log, progress_callback=None):
    # Determine component selections (GUI supplies args.components; CLI supplies args.enable_rds)
    if hasattr(args, "components"):
        components = set(args.components)
    else:
        components = set()
        if getattr(args, "enable_rds", "").lower() == "yes":
            components.add("enable_rds")
    enable_rds = "enable_rds" in components
    userdata_chunks = components - {"enable_rds"}

    ec2_name = args.ec2_name
    key_name = args.key_name
    domain = args.domain
    repo_url = args.repo_url

    # Build deployment steps list
    steps = [
        "Check AWS creds",
        "Create/reuse VPC",
        "Create subnet & route",
        "Create key pair",
        "Create security group",
        "Generate userdata script",
        "Launch EC2",
        "Allocate & associate EIP"
    ]
    if enable_rds:
        steps.append("Optional RDS")
    steps.append("Finish")

    total = len(steps)
    current = 0

    # Initialize progress
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

    # 2.1 Check AWS credentials
    creds_ok, acct = check_aws_cli_credentials(log)
    if not creds_ok:
        log(f"[ERROR] AWS credentials invalid: {acct}\n")
        if progress_callback:
            return
        else:
            sys.exit(1)
    log(f"[INFO] AWS account: {acct}\n")
    step_complete()

    region = os.getenv("AWS_REGION", "us-west-2")

    # 2.2 VPC
    vpc_id = create_vpc_if_needed(ec2_name, region, log)
    step_complete()

    # 2.3 Subnet & route
    subnet_id = create_subnet_and_route(ec2_name, region, True, vpc_id, log)
    step_complete()

    # 2.4 Key pair
    pem_path = create_key_pair_if_needed(key_name, region, log)
    step_complete()

    # 2.5 Security group
    sg_id = create_security_group_if_needed(ec2_name, region, vpc_id, log)
    step_complete()

    # 2.6 User-data script
    user_data_file = create_userdata_script(domain, repo_url, userdata_chunks)
    log(f"[INFO] Wrote user-data to {user_data_file}\n")
    step_complete()

    # 2.7 Launch EC2
    instance_id, public_dns = launch_ec2_instance(
        ec2_name, key_name, sg_id, subnet_id, region, user_data_file, log
    )
    step_complete()

    # 2.8 Elastic IP
    alloc_id, eip = allocate_elastic_ip(ec2_name, region, log)
    associate_elastic_ip(instance_id, alloc_id, region, log)
    log(f"[INFO] Elastic IP: {eip}\n")
    step_complete()

    # 2.9 Optional RDS
    if enable_rds:
        db_id = getattr(args, "db_id", f"{ec2_name}-db")
        db_user = getattr(args, "db_user", "admin")
        db_pass = getattr(args, "db_pass", None)
        if db_pass is None:
            log("[ERROR] DB password not provided for RDS.\n")
            if progress_callback:
                return
            else:
                sys.exit(1)
        endpoint = create_rds_postgres(db_id, db_user, db_pass, region, log)
        log(f"[INFO] RDS endpoint: {endpoint}\n")
        step_complete()

    # 2.10 Finish
    if not progress_callback:
        pbar.close()
    log("\n[INFO] Deployment complete!\n")
    log(f"[INFO] SSH: ssh -i ~/.ssh/{key_name}.pem ec2-user@{eip}\n")
    log(f"[INFO] Point your DNS A-record for {domain} → {eip}\n")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Deploy EC2 and optional RDS")
    parser.add_argument("--ec2_name", required=True)
    parser.add_argument("--key_name", required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--repo_url", required=True)
    parser.add_argument("--enable_rds", default="no")
    parser.add_argument("--db_id", default=None)
    parser.add_argument("--db_user", default=None)
    parser.add_argument("--db_pass", default=None)
    args = parser.parse_args()

    deploy(args, log)