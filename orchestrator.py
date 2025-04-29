# orchestrator.py

import os
import sys
import shlex
import subprocess
from tempfile import NamedTemporaryFile
from time import sleep

from tqdm import tqdm

from .config import DeploymentConfig

from .networking import create_vpc_if_needed, create_subnet_and_route
from .rds import create_rds_postgres
from .constants import DEFAULT_REGION
from .aws_cli_utils import AWSCLIService
from .ec2 import EC2Service
from .networking import NetworkingService
from .rds import RDSService
from .aws_cli_utils import AWSCLIService
from .ec2 import EC2Service
from .networking import NetworkingService
from .rds import RDSService

# class DeploymentOrchestrator:
#     def __init__(self, config, logger=None):
#         self.logger = logger if logger else print
#         self.config = config

#         # Instantiate the AWSCLIService once (or get from a DI container)
#         self.awscli = AWSCLIService(logger=self.logger)

#         # Pass the same awscli into each service so they share credentials/logging
#         self.ec2_service = EC2Service(awscli=self.awscli, logger=self.logger)
#         self.net_service = NetworkingService(awscli=self.awscli, logger=self.logger)
#         self.rds_service = RDSService(awscli=self.awscli, logger=self.logger)

#     def deploy(self):
#         # Check credentials
#         creds_ok, acct = self.awscli.check_credentials()
#         if not creds_ok:
#             self.logger(f"[ERROR] {acct}")
#             return

#         # Then call service methods:
#         vpc_id = self.net_service.create_vpc_if_needed(self.config.ec2_name, self.config.aws_region)
#         subnet_id = self.net_service.create_subnet_and_route(
#             self.config.ec2_name,
#             self.config.aws_region,
#             (self.config.subnet_type == "public"),
#             vpc_id
#         )

class DeploymentOrchestrator:
    """
    Coordinates the entire deployment workflow, step by step.
    Uses the DeploymentConfig for input parameters and 
    interacts with underlying services (EC2, networking, RDS, etc.).
    """

    def __init__(self, config: DeploymentConfig, logger=None):
        """
        :param config: A DeploymentConfig object containing all user-supplied or default settings.
        :param logger: Optional logging function (defaults to print).
        """
        self.config = config
        self.logger = logger if logger else print

        # For demonstration, we store an internal list of steps:
        self.steps = [
            "Check AWS credentials",
            "Create or reuse VPC",
            "Create Subnet & Route",
            "Create Key Pair",
            "Create Security Group",
            "Allocate Elastic IP",
            "Pause for DNS update",
            "Launch EC2 instance",
            "Wait for instance checks",
            "Associate EIP",
            "Update SSH config",
            "Optional sync local files",
            "Optional SSH-based install steps",
            "Optional create RDS",
            "Done!",
        ]

    def deploy(self):
        """
        Orchestrates the entire deployment. Returns None or raises on fatal errors.
        """
        # We can use a progress bar or track steps manually
        pbar = tqdm(total=len(self.steps), desc="Deployment", unit="step")

        # Step 1 - Check Credentials
        self._log_step_start(pbar, 0)
        creds_ok, acct = check_aws_cli_credentials(self.logger)
        if not creds_ok:
            self.logger(f"[ERROR] AWS credentials invalid: {acct}\n")
            sys.exit(1)

        self.logger(f"[INFO] AWS account: {acct}\n")
        pbar.update(1)

        # Step 2 - Create or reuse VPC
        self._log_step_start(pbar, 1)
        vpc_id = create_vpc_if_needed(self.config.ec2_name, self.config.aws_region, self.logger)
        pbar.update(1)

        # Step 3 - Create Subnet & Route
        self._log_step_start(pbar, 2)
        # pass True if you want 'public' route with IGW, or adapt to config
        is_public = (self.config.subnet_type == "public")
        subnet_id = create_subnet_and_route(
            self.config.ec2_name, self.config.aws_region, is_public, vpc_id, self.logger
        )
        pbar.update(1)

        # Step 4 - Create Key Pair
        self._log_step_start(pbar, 3)
        pem_path = create_key_pair_if_needed(
            self.config.key_name, self.config.aws_region, self.logger
        )
        pbar.update(1)

        # Step 5 - Create Security Group
        self._log_step_start(pbar, 4)
        sg_id = create_security_group_if_needed(
            self.config.ec2_name, self.config.aws_region, vpc_id, self.logger
        )
        pbar.update(1)

        # Step 6 - Allocate EIP
        self._log_step_start(pbar, 5)
        alloc_id, eip = allocate_elastic_ip(self.config.ec2_name, self.config.aws_region, self.logger)
        self.logger(f"[INFO] Elastic IP allocated: {eip}\n")
        pbar.update(1)

        # Step 7 - Pause for DNS update
        self._log_step_start(pbar, 6)
        self.logger(
            f"[ACTION REQUIRED] Please create/verify an A-record in DNS for '{self.config.domain}' "
            f"pointing to IP {eip}.\n"
        )
        input("[Press ENTER once DNS is updated or if you want to continue anyway]\n")
        pbar.update(1)

        # Step 8 - Launch EC2
        self._log_step_start(pbar, 7)
        user_data = self._create_minimal_user_data()
        with NamedTemporaryFile(delete=False, mode="w", suffix=".txt") as tmpfile:
            tmpfile.write(user_data)
            user_data_file = tmpfile.name

        instance_id, public_dns = launch_ec2_instance(
            self.config.ec2_name,
            self.config.key_name,
            sg_id,
            subnet_id,
            self.config.aws_region,
            user_data_file,
            self.logger
        )
        pbar.update(1)

        # Step 9 - Wait for instance to be running
        self._log_step_start(pbar, 8)
        wait_cmd = f"aws ec2 wait instance-running --region {self.config.aws_region} --instance-ids {instance_id}"
        run_cmd(wait_cmd, self.logger)
        self.logger(f"[INFO] Instance {instance_id} is in 'running' state.\n")

        wait_cmd_ok = f"aws ec2 wait instance-status-ok --region {self.config.aws_region} --instance-ids {instance_id}"
        run_cmd(wait_cmd_ok, self.logger)
        self.logger(f"[INFO] Instance {instance_id} passed status checks.\n")
        pbar.update(1)

        # Step 10 - Associate EIP
        self._log_step_start(pbar, 9)
        associate_elastic_ip(instance_id, alloc_id, self.config.aws_region, self.logger)
        self.logger(f"[INFO] Elastic IP {eip} associated with instance {instance_id}.\n")
        pbar.update(1)

        # Step 11 - Update SSH config
        self._log_step_start(pbar, 10)
        self._append_ssh_config(eip)
        pbar.update(1)

        # Step 12 - Optional local copy
        self._log_step_start(pbar, 11)
        if self.config.source_method == "copy" and self.config.local_path:
            self.logger("[WARNING] Using rsync instead of scp. Excluding 'venv' and '__pycache__' directories.\n")
            self._rsync_local_files(eip)
        else:
            self.logger("[INFO] Skipping local copy step (source_method != copy).\n")
        pbar.update(1)

        # Step 13 - SSH-based install steps
        self._log_step_start(pbar, 12)
        self._optional_ssh_install(eip)
        pbar.update(1)

        # Step 14 - Optional RDS
        self._log_step_start(pbar, 13)
        if self.config.enable_rds == "yes" and \
           self.config.db_identifier and self.config.db_username and self.config.db_password:
            endpoint = create_rds_postgres(
                self.config.db_identifier,
                self.config.db_username,
                self.config.db_password,
                self.config.aws_region,
                self.logger
            )
            self.logger(f"[INFO] RDS endpoint: {endpoint}\n")
        pbar.update(1)

        # Step 15 - Done
        pbar.update(1)
        pbar.close()
        self.logger(f"\n[INFO] Deployment complete!\n[INFO] SSH example: ssh {self.config.ec2_name}\n")
        self.logger(f"[INFO] Domain: {self.config.domain} => {eip}\n")

    def _create_minimal_user_data(self) -> str:
        """
        Create the minimal user-data script that ensures the instance boots
        with python3 and git installed, but avoids big compilation overhead.
        """
        return """#cloud-config
runcmd:
  - yum update -y
  - yum install -y python3 git
"""

    def _append_ssh_config(self, eip: str):
        """
        Append a host entry in the local ~/.ssh/config.
        """
        ssh_config_path = os.path.expanduser("~/.ssh/config")
        config_lines = [
            f"\n# Auto-added for {self.config.ec2_name}",
            f"Host {self.config.ec2_name}",
            f"  HostName ec2-{eip.replace('.', '-')}.{self.config.aws_region}.compute.amazonaws.com",
            "  User ec2-user",
            f"  IdentityFile ~/.ssh/{self.config.key_name}.pem",
        ]
        try:
            with open(ssh_config_path, "a") as cfg:
                cfg.write("\n".join(config_lines) + "\n")
            self.logger(f"[INFO] Appended SSH config entry to {ssh_config_path}\n")
        except Exception as ex:
            self.logger(f"[WARNING] Could not write SSH config: {ex}\n")

    def _rsync_local_files(self, eip: str):
        """
        Uses rsync to copy local files to the remote instance, excluding venv/__pycache__.
        """
        copy_cmd = f"""rsync -av \
  --exclude='venv' \
  --exclude='__pycache__' \
  -e "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null" \
  {shlex.quote(self.config.local_path)} \
  {self.config.ec2_name}:/home/ec2-user/
"""
        run_cmd(copy_cmd, self.logger)
        self.logger(
            f"[INFO] Copied local path {self.config.local_path} to /home/ec2-user/ (excluding venv & __pycache__).\n"
        )

    def _optional_ssh_install(self, eip: str):
        """
        Optionally run custom post-launch installation steps
        (like compiling Python from source, installing certbot, Git clone, etc.).
        Prompts the user to continue or skip for manual steps.
        """
        self.logger("\n===== Step 13: SSH-based install steps =====\n")
        answer = input(
            "Type 'yes' to continue automatically installing Python, certbot, etc.\n"
            "Type 'no' to skip this step and do it manually.\n"
        ).strip().lower()

        if answer == "no":
            self.logger("[INFO] Skipping automatic SSH steps. Please perform them manually.\n")
            return

        # Build a script of commands based on skip_compile and skip_certbot flags
        install_script = []

        # Python compile
        if not self.config.skip_compile:
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

        # Certbot / SSL
        if not self.config.skip_certbot:
            install_script.append(f"""\
yum install -y httpd mod_ssl certbot python3-certbot-apache
systemctl enable httpd
systemctl start httpd

# Basic VirtualHost
mkdir -p /etc/httpd/conf.d
cat <<EOF >/etc/httpd/conf.d/{self.config.domain}.conf
<VirtualHost *:80>
    ServerName {self.config.domain}
    DocumentRoot /var/www/html
</VirtualHost>
EOF

systemctl restart httpd
""")

        # If using git, do a clone
        if self.config.source_method == "git" and self.config.repo_url:
            install_script.append(f"""\
mkdir -p /home/ec2-user/app
cd /home/ec2-user/app
git init
git remote add origin {self.config.repo_url}
git pull origin main
chown -R ec2-user:ec2-user /home/ec2-user/app
if [ -f /home/ec2-user/venv/bin/pip ]; then
  /home/ec2-user/venv/bin/pip install fastapi gradio uvicorn supervisor
fi
""")

        final_script = "\n".join(install_script).strip()
        if not final_script:
            self.logger("[INFO] No SSH steps needed (all were disabled or empty).\n")
            return

        # Write the script locally
        script_filename = "post_launch_setup.sh"
        with open(script_filename, "w") as f:
            f.write(final_script + "\n")

        # scp the script
        scp_cmd = f"scp {script_filename} {self.config.ec2_name}:/home/ec2-user/"
        run_cmd(scp_cmd, self.logger)

        # ssh and run the script
        ssh_cmd = f"ssh {self.config.ec2_name} 'sudo bash /home/ec2-user/{script_filename}'"
        run_cmd(ssh_cmd, self.logger)
        self.logger("[INFO] Finished post-launch install steps.\n")

    def _log_step_start(self, pbar, step_index):
        """
        Helper for printing a step banner.
        """
        if step_index < len(self.steps):
            self.logger(f"\n=== Step {step_index+1}/{len(self.steps)}: {self.steps[step_index]} ===\n")
        else:
            self.logger("\n=== Next Step ===\n")
        # (We don't move the pbar here; we only do that after each step finishes)
