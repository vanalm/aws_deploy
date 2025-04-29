# networking.py

import json
from .aws_cli_utils import AWSCLIService


class NetworkingService:
    """
    Encapsulates VPC, subnet, routing (IGW or NAT) creation logic.
    Uses AWSCLIService to execute commands.
    """

    def __init__(self, awscli: AWSCLIService = None, logger=None):
        """
        :param awscli: An instance of AWSCLIService. If None, creates a new one.
        :param logger: Optional logging function, defaults to print.
        """
        self.logger = logger if logger else print
        self.awscli = awscli if awscli else AWSCLIService(logger=self.logger)

    def create_vpc_if_needed(self, ec2_name, region):
        """
        Creates or reuses a VPC with a 10.0.0.0/16 CIDR block, tagged with `ec2_name`.
        Returns vpc_id.
        """
        filter_name = f"{ec2_name}-vpc"
        describe_cmd = (
            f"aws ec2 describe-vpcs --region {region} "
            f"--filters Name=tag:Name,Values={filter_name}"
        )
        stdout, _ = self.awscli.run_cmd(describe_cmd, check=False)

        vpc_id = None
        if '"VpcId":' in stdout:
            try:
                data = json.loads(stdout)
                vpc_id = data["Vpcs"][0]["VpcId"]
                self._log(f"[INFO] Reusing existing VPC {vpc_id} ({filter_name}).\n")
            except Exception:
                pass

        if not vpc_id:
            self._log(f"[INFO] Creating new VPC: {filter_name}\n")
            cidr_block = "10.0.0.0/16"
            create_cmd = (
                f"aws ec2 create-vpc --cidr-block {cidr_block} --region {region} "
                f"--query 'Vpc.VpcId' --output text"
            )
            stdout, _ = self.awscli.run_cmd(create_cmd)
            vpc_id = stdout.strip()
            # Tag the VPC
            tag_cmd = (
                f"aws ec2 create-tags --resources {vpc_id} "
                f"--tags Key=Name,Value={filter_name} --region {region}"
            )
            self.awscli.run_cmd(tag_cmd)
            self._log(f"[INFO] Created and tagged VPC: {vpc_id}\n")

            # Enable DNS hostname support
            modify_cmd = (
                f"aws ec2 modify-vpc-attribute --vpc-id {vpc_id} "
                f"--enable-dns-hostnames --region {region}"
            )
            self.awscli.run_cmd(modify_cmd)

        return vpc_id

    def create_subnet_and_route(self, ec2_name, region, use_public_subnet, vpc_id):
        """
        Creates a single subnet (public or NAT) in the given VPC, plus a route table,
        plus IGW or NAT as needed. Returns subnet_id.
        """
        subnet_filter_name = f"{ec2_name}-subnet"
        describe_cmd = (
            f"aws ec2 describe-subnets --region {region} "
            f"--filters Name=tag:Name,Values={subnet_filter_name} Name=vpc-id,Values={vpc_id}"
        )
        stdout, _ = self.awscli.run_cmd(describe_cmd, check=False)

        subnet_id = None
        if '"SubnetId":' in stdout:
            try:
                data = json.loads(stdout)
                subnet_id = data["Subnets"][0]["SubnetId"]
                self._log(
                    f"[INFO] Reusing existing subnet {subnet_id} ({subnet_filter_name}).\n"
                )
            except Exception:
                pass

        if not subnet_id:
            # Create a new subnet
            az_cmd = (
                f"aws ec2 describe-availability-zones --region {region} "
                f"--query 'AvailabilityZones[0].ZoneName' --output text"
            )
            stdout, _ = self.awscli.run_cmd(az_cmd)
            zone_name = stdout.strip()

            self._log(f"[INFO] Creating Subnet: {subnet_filter_name}, AZ={zone_name}\n")
            create_subnet_cmd = (
                f"aws ec2 create-subnet --vpc-id {vpc_id} --cidr-block 10.0.1.0/24 "
                f"--availability-zone {zone_name} --region {region} "
                f"--query 'Subnet.SubnetId' --output text"
            )
            stdout, _ = self.awscli.run_cmd(create_subnet_cmd)
            subnet_id = stdout.strip()

            # Tag
            tag_cmd = (
                f"aws ec2 create-tags --resources {subnet_id} --region {region} "
                f"--tags Key=Name,Value={subnet_filter_name}"
            )
            self.awscli.run_cmd(tag_cmd)
            self._log(f"[INFO] Created and tagged subnet: {subnet_id}\n")

        # Route Table
        rtb_filter_name = f"{ec2_name}-rtb"
        describe_rtb = (
            f"aws ec2 describe-route-tables --region {region} "
            f"--filters Name=tag:Name,Values={rtb_filter_name} Name=vpc-id,Values={vpc_id}"
        )
        stdout, _ = self.awscli.run_cmd(describe_rtb, check=False)

        rtb_id = None
        if '"RouteTableId":' in stdout:
            try:
                data = json.loads(stdout)
                rtb_id = data["RouteTables"][0]["RouteTableId"]
                self._log(f"[INFO] Reusing route table {rtb_id} ({rtb_filter_name}).\n")
            except Exception:
                pass

        if not rtb_id:
            self._log(f"[INFO] Creating new route table: {rtb_filter_name}\n")
            create_rtb_cmd = (
                f"aws ec2 create-route-table --vpc-id {vpc_id} --region {region} "
                f"--query 'RouteTable.RouteTableId' --output text"
            )
            stdout, _ = self.awscli.run_cmd(create_rtb_cmd)
            rtb_id = stdout.strip()
            # Tag it
            tag_cmd = (
                f"aws ec2 create-tags --resources {rtb_id} --region {region} "
                f"--tags Key=Name,Value={rtb_filter_name}"
            )
            self.awscli.run_cmd(tag_cmd)

        assoc_cmd = (
            f"aws ec2 associate-route-table --route-table-id {rtb_id} "
            f"--subnet-id {subnet_id} --region {region}"
        )
        self.awscli.run_cmd(assoc_cmd, check=False)

        # Internet gateway or NAT gateway
        if use_public_subnet:
            self._setup_internet_gateway(ec2_name, region, vpc_id, rtb_id, subnet_id)
        else:
            self._setup_nat_gateway(ec2_name, region, subnet_id, rtb_id)

        return subnet_id

    def _setup_internet_gateway(self, ec2_name, region, vpc_id, rtb_id, subnet_id):
        """
        Internal helper to attach (or reuse) an internet gateway and create a default route.
        """
        igw_filter_name = f"{ec2_name}-igw"
        desc_igw_cmd = (
            f"aws ec2 describe-internet-gateways --region {region} "
            f'--filters Name=tag:Name,Values="{igw_filter_name}"'
        )
        stdout, _ = self.awscli.run_cmd(desc_igw_cmd, check=False)

        igw_id = None
        if '"InternetGatewayId":' in stdout:
            try:
                data = json.loads(stdout)
                igw_id = data["InternetGateways"][0]["InternetGatewayId"]
                self._log(f"[INFO] Reusing IGW {igw_id} ({igw_filter_name}).\n")
            except Exception:
                pass

        if not igw_id:
            self._log(f"[INFO] Creating Internet Gateway: {igw_filter_name}\n")
            create_igw_cmd = (
                f"aws ec2 create-internet-gateway --region {region} "
                f"--query 'InternetGateway.InternetGatewayId' --output text"
            )
            stdout, _ = self.awscli.run_cmd(create_igw_cmd)
            igw_id = stdout.strip()

            # Tag
            tag_cmd = (
                f"aws ec2 create-tags --resources {igw_id} --region {region} "
                f'--tags Key=Name,Value="{igw_filter_name}"'
            )
            self.awscli.run_cmd(tag_cmd)

            attach_cmd = (
                f"aws ec2 attach-internet-gateway "
                f"--internet-gateway-id {igw_id} --vpc-id {vpc_id} --region {region}"
            )
            self.awscli.run_cmd(attach_cmd)

        create_route_cmd = (
            f"aws ec2 create-route --route-table-id {rtb_id} "
            f"--destination-cidr-block 0.0.0.0/0 --gateway-id {igw_id} --region {region}"
        )
        self.awscli.run_cmd(create_route_cmd, check=False)

        # Auto-assign public IP
        modify_subnet_cmd = (
            f"aws ec2 modify-subnet-attribute --subnet-id {subnet_id} "
            f"--map-public-ip-on-launch --region {region}"
        )
        self.awscli.run_cmd(modify_subnet_cmd)
        self._log("[INFO] Public subnet setup complete.\n")

    def _setup_nat_gateway(self, ec2_name, region, subnet_id, rtb_id):
        """
        Internal helper to create a NAT Gateway and a route for outbound-only internet.
        """
        nat_filter_name = f"{ec2_name}-natgw"
        self._log(f"[INFO] Creating EIP for NAT Gateway: {nat_filter_name}\n")
        eip_cmd = (
            f"aws ec2 allocate-address --domain vpc --region {region} "
            f"--query 'AllocationId' --output text"
        )
        stdout, _ = self.awscli.run_cmd(eip_cmd)
        allocation_id = stdout.strip()

        self._log(f"[INFO] Creating NAT Gateway: {nat_filter_name}\n")
        nat_create_cmd = (
            f"aws ec2 create-nat-gateway --subnet-id {subnet_id} "
            f"--allocation-id {allocation_id} --region {region} "
            f"--query 'NatGateway.NatGatewayId' --output text"
        )
        stdout, _ = self.awscli.run_cmd(nat_create_cmd)
        natgw_id = stdout.strip()

        tag_cmd = (
            f"aws ec2 create-tags --resources {natgw_id} --region {region} "
            f'--tags Key=Name,Value="{nat_filter_name}"'
        )
        self.awscli.run_cmd(tag_cmd)

        wait_cmd = (
            f"aws ec2 wait nat-gateway-available --nat-gateway-ids {natgw_id} "
            f"--region {region}"
        )
        self.awscli.run_cmd(wait_cmd)

        create_route_cmd = (
            f"aws ec2 create-route --route-table-id {rtb_id} "
            f"--destination-cidr-block 0.0.0.0/0 --nat-gateway-id {natgw_id} "
            f"--region {region}"
        )
        self.awscli.run_cmd(create_route_cmd, check=False)

        self._log("[INFO] Outbound-only subnet setup complete.\n")

    def _log(self, msg):
        """Helper method to log to self.logger."""
        if callable(self.logger):
            self.logger(msg)
        else:
            print(msg, end="")