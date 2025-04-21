# rds.py

from .aws_cli_utils import run_cmd


def create_rds_postgres(db_identifier, db_username, db_password, region, log_callback):
    log_callback(f"[INFO] Creating RDS Postgres '{db_identifier}'...\n")
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
    run_cmd(cmd_create, log_callback=log_callback)

    # Wait until available
    wait_cmd = (
        f"aws rds wait db-instance-available --db-instance-identifier {db_identifier} "
        f"--region {region}"
    )
    run_cmd(wait_cmd, log_callback=log_callback)
    log_callback("[INFO] RDS Postgres is now available.\n")

    # Get endpoint
    ep_cmd = (
        f"aws rds describe-db-instances --db-instance-identifier {db_identifier} "
        f"--region {region} --query 'DBInstances[0].Endpoint.Address' --output text"
    )
    stdout, _ = run_cmd(ep_cmd, log_callback=log_callback)
    endpoint = stdout.strip()
    log_callback(f"[INFO] RDS Endpoint: {endpoint}\n")
    return endpoint
