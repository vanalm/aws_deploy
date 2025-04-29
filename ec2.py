# ec2.py

import os
import shutil
from .aws_cli_utils import AWSCLIService
from .constants import DEFAULT_AMI


class EC2Service:
    """
    Encapsulates EC2-related functionality (key pairs, security groups, EIP, launching).
    Depends on an AWSCLIService to run AWS commands and a logger for logs.
    """

    def __init__(self, awscli: AWSCLIService = None, logger=None):
        """
        :param awscli: An instance of AWSCLIService. If None, creates a new one.
        :param logger: Optional logging function, defaults to print.
        """
        self.logger = logger if logger else print
        self.awscli = awscli if awscli else AWSCLIService(logger=self.logger)

    def create_key_pair_if_needed(self, key_name, region):
        """
        Checks if the key pair exists; if not, create it and save locally (.pem).
        Returns the path to the .pem file (in ~/.ssh).
        """
        cmd_check = f"aws ec2 describe-key-pairs --key-names {key_name} --region {region}"
        _, stderr = self.awscli.run_cmd(cmd_check, check=False)
        if "InvalidKeyPair.NotFound" in stderr:
            self._log(f"[INFO] Creating Key Pair '{key_name}'...\n")
            cmd_create = (
                f"aws ec2 create-key-pair --key-name {key_name} "
                f"--region {region} --query 'KeyMaterial' --output text"
            )
            stdout, _ = self.awscli.run_cmd(cmd_create)
            pem_file = f"{key_name}.pem"
            with open(pem_file, "w") as f:
                f.write(stdout)
            os.chmod(pem_file, 0o400)
            self._log(f"[INFO] Key Pair created locally: {pem_file} (chmod 400).\n")
            return self._move_pem_to_ssh_directory(pem_file)
        else:
            self._log(f"[INFO] Key Pair '{key_name}' already exists.\n")
            guessed_path = os.path.join(os.path.expanduser("~"), ".ssh", f"{key_name}.pem")
            return guessed_path

    def create_security_group_if_needed(self, ec2_name, region, vpc_id):
        """
        Creates (or reuses) a security group for the given VPC, opening common ports: 22, 80, 443.
        Returns the SG ID.
        """
        sg_name = f"{ec2_name}-sg"
        cmd_describe = (
            f"aws ec2 describe-security-groups --filters Name=group-name,Values={sg_name} "
            f"--region {region} --query 'SecurityGroups[*].GroupId' --output text"
        )
        stdout, _ = self.awscli.run_cmd(cmd_describe, check=False)
        if stdout.strip():
            sg_id = stdout.strip()
            self._log(f"[INFO] Security Group '{sg_name}' already exists: {sg_id}\n")
            return sg_id

        self._log(f"[INFO] Creating Security Group '{sg_name}'...\n")
        create_cmd = (
            f"aws ec2 create-security-group --group-name {sg_name} "
            f"--description 'AppSecurityGroup' --vpc-id {vpc_id} --region {region} "
            f"--query 'GroupId' --output text"
        )
        sg_out, _ = self.awscli.run_cmd(create_cmd)
        sg_id = sg_out.strip()

        # Tag the SG
        tag_cmd = (
            f"aws ec2 create-tags --resources {sg_id} --region {region} "
            f"--tags Key=Name,Value={sg_name}"
        )
        self.awscli.run_cmd(tag_cmd)

        # Authorize inbound rules (22,80,443)
        for port in [22, 80, 443]:
            auth_cmd = (
                f"aws ec2 authorize-security-group-ingress --group-id {sg_id} "
                f"--protocol tcp --port {port} --cidr 0.0.0.0/0 --region {region}"
            )
            self.awscli.run_cmd(auth_cmd)

        self._log(f"[INFO] Security Group created: {sg_id}\n")
        return sg_id

    def allocate_elastic_ip(self, ec2_name, region):
        """
        Allocates an Elastic IP (EIP) in the given region, tags it, and returns (allocation_id, public_ip).
        """
        cmd = (
            f"aws ec2 allocate-address --domain vpc --region {region} "
            f"--query '[AllocationId,PublicIp]' --output text"
        )
        stdout, _ = self.awscli.run_cmd(cmd)
        alloc_id, public_ip = stdout.split()

        # Tag the EIP
        tag_cmd = (
            f"aws ec2 create-tags --resources {alloc_id} "
            f"--tags Key=Name,Value={ec2_name}_EIP --region {region}"
        )
        self.awscli.run_cmd(tag_cmd)

        self._log(f"[INFO] Allocated Elastic IP: {public_ip} (AllocationId: {alloc_id})\n")
        return alloc_id, public_ip

    def associate_elastic_ip(self, instance_id, alloc_id, region):
        """
        Associates an existing EIP with an EC2 instance.
        """
        cmd = (
            f"aws ec2 associate-address --instance-id {instance_id} "
            f"--allocation-id {alloc_id} --region {region}"
        )
        self.awscli.run_cmd(cmd)
        self._log("[INFO] Elastic IP associated with instance.\n")

    def launch_ec2_instance(
        self, ec2_name, key_name, sg_id, subnet_id, region, user_data_script
    ):
        """
        Launches a t3.micro EC2 instance using the given parameters, user-data script, etc.
        Returns (instance_id, public_dns).
        """
        self._log(
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
        self._log(f"[DEBUG] Executing EC2 run-instances:\n{cmd_launch}\n")
        stdout, _ = self.awscli.run_cmd(cmd_launch)
        instance_id = stdout.strip()
        self._log(f"[INFO] Instance launched: {instance_id}\n")

        # Wait until running
        wait_cmd = (
            f"aws ec2 wait instance-running --instance-ids {instance_id} --region {region}"
        )
        self._log(f"[DEBUG] Waiting for instance running:\n{wait_cmd}\n")
        self.awscli.run_cmd(wait_cmd)
        self._log("[INFO] EC2 instance is now running.\n")

        # Retrieve public DNS
        dns_cmd = (
            f"aws ec2 describe-instances --instance-ids {instance_id} --region {region} "
            f"--query 'Reservations[0].Instances[0].PublicDnsName' --output text"
        )
        self._log(f"[DEBUG] Retrieving public DNS:\n{dns_cmd}\n")
        dns_out, _ = self.awscli.run_cmd(dns_cmd)
        public_dns = dns_out.strip()
        self._log(f"[INFO] Instance Public DNS: {public_dns}\n")

        return instance_id, public_dns

    def _move_pem_to_ssh_directory(self, pem_file_name):
        """
        Moves the .pem file to ~/.ssh with correct permissions (400).
        Returns the new path, or the original if something fails.
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
            self._log(f"[INFO] Moved {pem_file_name} to {dest} (chmod 400).\n")
            return dest
        except Exception as e:
            self._log(f"[WARN] Could not move {pem_file_name} to {dest}: {e}\n")
            return pem_file_name

    def _log(self, msg):
        """Helper method to log to self.logger."""
        if callable(self.logger):
            self.logger(msg)
        else:
            print(msg, end="")