# cli.py

import argparse
import sys
from .aws_cli_utils import check_aws_cli_credentials
from .constants import DEFAULT_REGION
from .deploy import deploy
from .gui import launch_gui


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
        # Launch the GUI
        launch_gui()
    else:
        # CLI usage
        def cli_log(msg):
            print(msg, end="", flush=True)

        creds_ok, result_str = check_aws_cli_credentials(cli_log)
        if not creds_ok:
            cli_log(result_str)
            cli_log("[ERROR] Cannot proceed without valid AWS credentials.\n")
            sys.exit(1)
        else:
            cli_log(f"[INFO] Signed in as account {result_str}\n")

        def default_val(cur, d):
            return cur if cur else d

        args.aws_region = default_val(args.aws_region, DEFAULT_REGION)
        args.ec2_name = default_val(args.ec2_name, "MyEC2Instance")
        args.key_name = default_val(args.key_name, "MyKeyPair")
        args.domain = default_val(args.domain, "mydomain.com")
        args.repo_url = default_val(
            args.repo_url, "https://github.com/youruser/yourrepo.git"
        )
        default_db = f"{args.ec2_name}-db"
        args.db_identifier = default_val(args.db_identifier, default_db)
        args.db_username = default_val(args.db_username, "admin")
        args.db_password = default_val(args.db_password, "MyDbPassword123")

        deploy(args, cli_log)
