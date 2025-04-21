# aws_cli_utils.py

import subprocess
import shlex
import sys
import os


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


def run_cmd(cmd, log_callback=None, check=True):
    """
    Runs a shell command via subprocess. If log_callback is provided,
    redirect stdout/stderr lines to it for a GUI or console.
    """
    if log_callback:
        log_callback(f"[RUN] {cmd}\n")

    import subprocess
    import shlex

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
