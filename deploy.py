# deploy.py

import sys
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


def deploy(args, log_callback):
    """
    Orchestrates the entire flow:
      - Check AWS creds
      - Create/reuse VPC + Subnet (public or NAT)
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

        # 2) Create or reuse VPC
        vpc_id = create_vpc_if_needed(ec2_name, region, log_callback)

        # 3) Create Subnet (public or NAT)
        subnet_id = create_subnet_and_route(
            ec2_name, region, use_public_subnet, vpc_id, log_callback
        )

        # 4) Create key pair if needed
        pem_path = create_key_pair_if_needed(key_name, region, log_callback)

        # 5) Create security group
        sg_id = create_security_group_if_needed(ec2_name, region, vpc_id, log_callback)

        # 6) Create user-data script
        user_data_script = create_userdata_script(domain, repo_url)

        # 7) Launch EC2
        instance_id, public_dns = launch_ec2_instance(
            ec2_name, key_name, sg_id, subnet_id, region, user_data_script, log_callback
        )

        # 8) EIP
        alloc_id, eip = allocate_elastic_ip(region, log_callback)
        associate_elastic_ip(instance_id, alloc_id, region, log_callback)
        log_callback(f"[INFO] Your static IP is: {eip}\n")

        # Domain reminder
        log_callback("\n--- DNS SETUP STEP ---\n")
        log_callback(
            "[INFO] Please add or update an A-record in your domain registrar's DNS "
            f"so that {domain} points to {eip}.\n"
        )
        log_callback(
            "[INFO] This is required to enable SSL with certbot later. If you'd like "
            "to test without SSL, you can skip this.\n"
        )

        # Prompt user to confirm DNS
        while True:
            user_input = (
                input(
                    "[ACTION] Type 'done' when your DNS A-record is set, or 'skip' to continue without waiting: "
                )
                .strip()
                .lower()
            )
            if user_input in ("done", "skip"):
                break

        if user_input == "done":
            log_callback("[INFO] Great! DNS should now point to your EC2's IP.\n")
        else:
            log_callback(
                "[WARN] Skipping DNS confirmation. SSL setup may fail if DNS is not pointed correctly.\n"
            )

        # 9) Wait for instance status checks to pass (cloud-init and other system checks)
        log_callback(
            "[INFO] Waiting for EC2 to pass status checks (this ensures cloud-init has time to finish)...\n"
        )
        wait_cmd = f"aws ec2 wait instance-status-ok --instance-ids {instance_id} --region {region}"
        run_cmd(wait_cmd, log_callback=log_callback)

        log_callback(
            "[INFO] EC2 instance passed basic status checks. Attempting to retrieve console output...\n"
        )
        get_console_cmd = f"aws ec2 get-console-output --instance-id {instance_id} --region {region} --output text"
        stdout, stderr = run_cmd(
            get_console_cmd, log_callback=log_callback, check=False
        )

        # Optionally parse or save the console output somewhere
        # For example, just log first few lines:
        short_console = "\n".join(stdout.splitlines()[-30:])  # last 30 lines
        log_callback("[INFO] Last 30 lines of console output (for debug):\n")
        log_callback(short_console + "\n")

        # 10) Optional RDS
        if enable_rds:
            endpoint = create_rds_postgres(
                db_identifier, db_username, db_password, region, log_callback
            )
            db_url = f"postgresql://{db_username}:{db_password}@{endpoint}:5432/{db_identifier}"
            log_callback(f"[INFO] DB Connection URL: {db_url}\n")

        # 11) SSH instructions
        ssh_cmd = f"ssh -i {pem_path} ec2-user@{eip}"
        log_callback(f"\n[INFO] To SSH into your instance:\n  {ssh_cmd}\n")

        log_callback("\n[INFO] All steps completed.\n")
        log_callback(
            "[INFO] Wait a few more minutes if needed for any long-running cloud-init processes.\n"
            f"[INFO] Once DNS is configured, you can test: https://{domain}\n"
        )

    except Exception as e:
        log_callback(f"[ERROR] {e}\n")
        sys.exit(1)
