# config.py

from .constants import DEFAULT_REGION

class DeploymentConfig:
    """
    Holds all configuration data for a deployment.
    Each attribute directly reflects a user-supplied or default parameter.
    """

    def __init__(
        self,
        aws_region: str = DEFAULT_REGION,
        ec2_name: str = "MyEC2Instance",
        key_name: str = "MyKeyPair",
        domain: str = "mydomain.com",
        repo_url: str = None,
        local_path: str = None,
        subnet_type: str = "public",      # or "nat"
        enable_rds: str = "no",           # "yes" or "no"
        db_identifier: str = None,
        db_username: str = None,
        db_password: str = None,
        source_method: str = "git",       # "git" or "copy"
        skip_compile: bool = False,
        skip_certbot: bool = False,
        # Additional fields can be added as needed
    ):
        self.aws_region = aws_region
        self.ec2_name = ec2_name
        self.key_name = key_name
        self.domain = domain
        self.repo_url = repo_url
        self.local_path = local_path
        self.subnet_type = subnet_type
        self.enable_rds = enable_rds
        self.db_identifier = db_identifier
        self.db_username = db_username
        self.db_password = db_password
        self.source_method = source_method
        self.skip_compile = skip_compile
        self.skip_certbot = skip_certbot

    def __repr__(self):
        return (
            f"DeploymentConfig("
            f"region={self.aws_region!r}, ec2_name={self.ec2_name!r}, "
            f"key_name={self.key_name!r}, domain={self.domain!r}, repo_url={self.repo_url!r}, "
            f"local_path={self.local_path!r}, subnet_type={self.subnet_type!r}, "
            f"enable_rds={self.enable_rds!r}, db_identifier={self.db_identifier!r}, "
            f"db_username={self.db_username!r}, db_password=<hidden>, source_method={self.source_method!r}, "
            f"skip_compile={self.skip_compile}, skip_certbot={self.skip_certbot}"
            f")"
        )
