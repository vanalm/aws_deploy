# rds.py

from .aws_cli_utils import AWSCLIService


class RDSService:
    """
    Encapsulates logic for provisioning and waiting on an RDS Postgres instance.
    """

    def __init__(self, awscli: AWSCLIService = None, logger=None):
        """
        :param awscli: An instance of AWSCLIService. If None, creates a new one.
        :param logger: Optional logging function, defaults to print.
        """
        self.logger = logger if logger else print
        self.awscli = awscli if awscli else AWSCLIService(logger=self.logger)

    def create_rds_postgres(self, db_identifier, db_username, db_password, region):
        """
        Creates a single Postgres RDS instance (db.t3.micro) with minimal specs.
        Waits until it's available, then returns the endpoint.
        """
        self._log(f"[INFO] Creating RDS Postgres '{db_identifier}'...\n")

        cmd_create = f"""aws rds create-db-instance \
            --db-instance-identifier {db_identifier} \
            --db-instance-class db.t3.micro \
            --engine postgres \
            --allocated-storage 20 \
            --no-multi-az \
            --publicly-accessible \
            --master-username {db_username} \
            --master-user-password {db_password} \
            --backup-retention-period 1 \
            --db-name {db_identifier} \
            --engine-version 14 \
            --region {region} \
            --query 'DBInstance.DBInstanceIdentifier' \
            --output text
        """
        self.awscli.run_cmd(cmd_create)

        # Wait until available
        wait_cmd = (
            f"aws rds wait db-instance-available --db-instance-identifier {db_identifier} "
            f"--region {region}"
        )
        self.awscli.run_cmd(wait_cmd)
        self._log("[INFO] RDS Postgres is now available.\n")

        # Get endpoint
        ep_cmd = (
            f"aws rds describe-db-instances --db-instance-identifier {db_identifier} "
            f"--region {region} --query 'DBInstances[0].Endpoint.Address' --output text"
        )
        stdout, _ = self.awscli.run_cmd(ep_cmd)
        endpoint = stdout.strip()
        self._log(f"[INFO] RDS Endpoint: {endpoint}\n")
        return endpoint

    def _log(self, msg):
        """Helper method to log to self.logger."""
        if callable(self.logger):
            self.logger(msg)
        else:
            print(msg, end="")