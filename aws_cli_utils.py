# aws_cli_utils.py

import subprocess
import shlex
import sys
import os


class AWSCLIService:
    """
    Encapsulates AWS CLI commands in a class-based interface.
    Provides credential checks, command execution, and sign-out.
    """

    def __init__(self, logger=None):
        """
        :param logger: Optional logging function. Defaults to print.
        """
        self.logger = logger if logger else print

    def check_credentials(self):
        """
        Checks if AWS CLI is installed and credentials are configured.
        Returns (True, account_id_str) if valid, else (False, error_message).
        """
        cmd = "aws sts get-caller-identity --query Account --output text"
        self._log(f"[RUN] {cmd}\n")

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

    def run_cmd(self, cmd, check=True):
        """
        Runs a shell command via subprocess. If check=True, raises SystemExit on errors.
        Returns (stdout, stderr).
        """
        self._log(f"[RUN] {cmd}\n")
        process = subprocess.Popen(
            shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        stdout, stderr = process.communicate()

        if stdout:
            self._log(stdout)
        if stderr:
            self._log(stderr)

        if check and process.returncode != 0:
            sys.exit(f"[ERROR] Command failed: {cmd}")

        return stdout, stderr

    def sign_out_credentials(self):
        """
        Minimally sign out by unsetting AWS-related environment variables.
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
        self._log(
            "[INFO] Environment credentials cleared. Run 'aws configure' again to switch accounts.\n"
        )

    def _log(self, msg):
        """Helper to send logs to self.logger."""
        if callable(self.logger):
            self.logger(msg)
        else:
            print(msg, end="")