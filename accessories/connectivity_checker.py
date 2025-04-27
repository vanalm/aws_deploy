#!/usr/bin/env python3

"""
connectivity_checker.py

Checks the network connectivity settings of a given EC2 instance in AWS.
Demonstrates:
- Retrieving instance details (public IP, security groups)
- Inspecting security group inbound rules for open ports
- (Optional) testing SSH connectivity using Paramiko
- (Optional) probing if ports are actually open via socket connections

Dependencies:
  - boto3  (pip install boto3)
  - paramiko (optional, pip install paramiko) for SSH check
"""

import argparse
import socket
import sys

try:
    import boto3
except ImportError:
    print("[ERROR] boto3 is required. Install with 'pip install boto3'.", file=sys.stderr)
    sys.exit(1)

# Paramiko is optional (for SSH connectivity testing). We'll handle gracefully if missing.
try:
    import paramiko
    HAVE_PARAMIKO = True
except ImportError:
    HAVE_PARAMIKO = False


class SecurityGroupDetails:
    """
    Holds inbound rule information for a single Security Group:
      - group_id
      - group_name
      - a list of rules, each rule is a dict with:
          {
            "ip_protocol": str,
            "port_range": (start, end),
            "cidr_list": [list_of_cidrs],
          }
    """
    def __init__(self, group_id, group_name, inbound_rules):
        self.group_id = group_id
        self.group_name = group_name
        self.inbound_rules = inbound_rules

    def __str__(self):
        line = f"SecurityGroup {self.group_name} ({self.group_id}):\n"
        for r in self.inbound_rules:
            proto = r["ip_protocol"]
            pstart, pend = r["port_range"]
            cidrs = ", ".join(r["cidr_list"])
            line += f"   Protocol: {proto}, Ports: {pstart}-{pend}, CIDRs: {cidrs}\n"
        return line


class ConnectivityChecker:
    """
    OOP class that inspects network settings (public IP, security groups, inbound rules)
    and optionally attempts real connectivity checks (TCP, SSH).
    """

    def __init__(self, instance_id, region_name="us-west-2", logger=print):
        """
        :param instance_id: ID of the target EC2 instance (e.g., 'i-0123456789abcdef0')
        :param region_name: AWS region name, default 'us-west-2'
        :param logger: function or callable for output (defaults to print)
        """
        self.instance_id = instance_id
        self.region_name = region_name
        self.logger = logger

        self.ec2_client = boto3.client("ec2", region_name=self.region_name)
        self.sts_client = boto3.client("sts", region_name=self.region_name)

        # Populated by gather_instance_data():
        self.public_ip = None
        self.private_ip = None
        self.security_groups = []    # list of SecurityGroupDetails
        self.account_id = None

    def gather_instance_data(self):
        """
        Retrieves information about the instance: Public IP, Private IP,
        Security Groups and their inbound rules, plus the current AWS account ID.
        """
        # Get AWS account ID from STS
        try:
            identity = self.sts_client.get_caller_identity()
            self.account_id = identity["Account"]
        except Exception as ex:
            self.logger(f"[ERROR] Unable to retrieve AWS account info: {ex}")

        # Query the EC2 instance
        try:
            response = self.ec2_client.describe_instances(InstanceIds=[self.instance_id])
            reservations = response.get("Reservations", [])
            if not reservations:
                raise ValueError("No reservations found for given Instance ID.")
            instance_data = reservations[0]["Instances"][0]

            self.public_ip = instance_data.get("PublicIpAddress")
            self.private_ip = instance_data.get("PrivateIpAddress")

            # Retrieve SecurityGroups info
            sg_list = instance_data.get("SecurityGroups", [])
            self.security_groups = self._get_security_group_details([sg["GroupId"] for sg in sg_list])

        except Exception as ex:
            self.logger(f"[ERROR] Error retrieving instance data: {ex}")
            raise

    def _get_security_group_details(self, group_ids):
        """
        Returns a list of SecurityGroupDetails for the given list of SG IDs.
        """
        details_list = []
        try:
            sg_response = self.ec2_client.describe_security_groups(GroupIds=group_ids)
            for sg_info in sg_response["SecurityGroups"]:
                inbound_rules = []
                for perm in sg_info.get("IpPermissions", []):
                    ip_protocol = perm["IpProtocol"]
                    from_port = perm.get("FromPort")
                    to_port = perm.get("ToPort")

                    # If port range is not present (e.g. -1 for all?), handle that
                    if from_port is None:
                        from_port = -1
                    if to_port is None:
                        to_port = -1

                    cidr_list = []
                    for ip_range in perm.get("IpRanges", []):
                        cidr_list.append(ip_range.get("CidrIp", ""))
                    inbound_rules.append({
                        "ip_protocol": ip_protocol,
                        "port_range": (from_port, to_port),
                        "cidr_list": cidr_list
                    })
                sg_obj = SecurityGroupDetails(
                    group_id=sg_info["GroupId"],
                    group_name=sg_info["GroupName"],
                    inbound_rules=inbound_rules
                )
                details_list.append(sg_obj)
        except Exception as ex:
            self.logger(f"[ERROR] Error retrieving SG details: {ex}")
            raise
        return details_list

    def check_port_open(self, host, port, timeout=3):
        """
        Attempts a TCP connection to (host, port) to see if it's open.
        Returns True if a connection is established, False otherwise.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
            sock.close()
            return True
        except (socket.timeout, socket.error):
            return False

    def check_ssh_connectivity(self, host, username, key_path, port=22, timeout=5):
        """
        Attempts to SSH into the remote host using Paramiko.
        Return True if SSH connection is successful, otherwise False.

        :param host: public IP or hostname
        :param username: e.g., 'ec2-user'
        :param key_path: path to your private key (.pem)
        :param port: SSH port (default 22)
        :param timeout: seconds to wait before giving up
        """
        if not HAVE_PARAMIKO:
            self.logger("[WARNING] Paramiko not installed. Skipping SSH check.")
            return False

        try:
            key = paramiko.RSAKey.from_private_key_file(key_path)
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(
                hostname=host,
                port=port,
                username=username,
                pkey=key,
                timeout=timeout,
                banner_timeout=timeout
            )
            ssh_client.close()
            return True
        except Exception as ex:
            self.logger(f"[WARNING] SSH check failed: {ex}")
            return False

    def generate_report(self, ports_to_test=None, ssh_username=None, ssh_key_path=None):
        """
        Generate a text summary describing:
          - Public IP
          - Open inbound ports (i.e., with inbound rule 0.0.0.0/0)
          - Optional TCP port reachability tests
          - Optional SSH connectivity test
        Returns a multi-line string.
        """
        if ports_to_test is None:
            ports_to_test = [22, 80, 443]

        lines = []
        lines.append(f"AWS Account: {self.account_id}")
        lines.append(f"Instance ID: {self.instance_id}")
        lines.append(f"Region: {self.region_name}")
        lines.append(f"Public IP: {self.public_ip}")
        lines.append(f"Private IP: {self.private_ip}")
        lines.append("")

        if not self.public_ip:
            lines.append("[WARNING] No public IP found. Connectivity from the open Internet is unlikely.")
            lines.append("Check if the instance is in a public subnet and has an Elastic IP or Public IP assigned.")
        lines.append("")

        lines.append("Security Groups and Inbound Rules:")
        for sg in self.security_groups:
            lines.append(str(sg))
        lines.append("")

        # Check for inbound rules that expose ports to 0.0.0.0/0
        open_ports_world = []
        for sg in self.security_groups:
            for rule in sg.inbound_rules:
                if any(cidr == "0.0.0.0/0" for cidr in rule["cidr_list"]):
                    # If from_port==to_port, it's a single port
                    (fp, tp) = rule["port_range"]
                    if fp == tp and fp != -1:
                        open_ports_world.append(fp)
                    elif fp == -1 and tp == -1:
                        lines.append("Detected an inbound rule: ALL PORTS open to 0.0.0.0/0")
                    else:
                        # A range
                        lines.append(
                            f"Detected inbound rule range: {fp}-{tp} open to 0.0.0.0/0"
                        )

        if open_ports_world:
            lines.append(f"The following individual ports are explicitly open to the entire internet: {open_ports_world}")
        lines.append("")

        # If we have a public IP, optionally do port checks
        if self.public_ip:
            lines.append("TCP Port Reachability Tests:")
            for port in ports_to_test:
                is_open = self.check_port_open(self.public_ip, port)
                result_str = "OPEN" if is_open else "CLOSED"
                lines.append(f" - Port {port}: {result_str}")
            lines.append("")

            # If user provided SSH info, attempt SSH
            if ssh_username and ssh_key_path:
                success = self.check_ssh_connectivity(
                    host=self.public_ip,
                    username=ssh_username,
                    key_path=ssh_key_path
                )
                if success:
                    lines.append("[SSH Test] Connection succeeded!")
                else:
                    lines.append("[SSH Test] Connection failed or Paramiko not installed.")
            else:
                lines.append("(No SSH check performed: missing username/key_path or Paramiko.)")

        return "\n".join(lines)


def main():
    import logging
    logger = logging.getLogger("connectivity_checker")
    logger.setLevel(logging.INFO)
    parser = argparse.ArgumentParser(
        description="Check the network connectivity of an EC2 instance."
    )
    parser.add_argument("--instance-id", help="EC2 Instance ID", default="i-0a8e9009096d79ada")
    parser.add_argument("--region", default="us-west-2", help="AWS region")
    parser.add_argument("--ssh-username", help="Username for SSH test (e.g., ec2-user)", default="ec2-user")
    parser.add_argument("--ssh-key-path", help="Path to .pem private key for SSH test", default="/Users/jacobvanalmelo/.ssh/mauibuilder_keypair.pem")
    parser.add_argument(
        "--ports",
        nargs="+",
        type=int,
        default=[22, 80, 443],
        help="List of ports to test with a TCP socket connection"
    )
    args = parser.parse_args()
    logger.info(f"Checking connectivity for instance {args.instance_id} in region {args.region}")
    logger.info(f"Ports to test: {args.ports}")
    logger.info(f"SSH username: {args.ssh_username}")
    logger.info(f"SSH key path: {args.ssh_key_path}")
    logger.info(f"SSH key path: {args.ssh_key_path}")
    checker = ConnectivityChecker(
        instance_id=args.instance_id,
        region_name=args.region
    )
    checker.gather_instance_data()
    report = checker.generate_report(
        ports_to_test=args.ports,
        ssh_username=args.ssh_username,
        ssh_key_path=args.ssh_key_path
    )
    print(report)


if __name__ == "__main__":
    main()

