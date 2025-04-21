# ec2.py

import os
import shutil
from .aws_cli_utils import run_cmd
from .constants import DEFAULT_AMI


def move_pem_to_ssh_directory(pem_file_name, log_callback=None):
    home = os.path.expanduser("~")
    ssh_dir = os.path.join(home, ".ssh")
    if not os.path.exists(ssh_dir):
        os.makedirs(ssh_dir, exist_ok=True)

    src = pem_file_name
    dest = os.path.join(ssh_dir, os.path.basename(pem_file_name))
    try:
        shutil.move(src, dest)
        os.chmod(dest, 0o400)
        if log_callback:
            log_callback(f"[INFO] Moved {pem_file_name} to {dest} (chmod 400).\n")
        return dest
    except Exception as e:
        if log_callback:
            log_callback(f"[WARN] Could not move {pem_file_name} to {dest}: {e}\n")
        return pem_file_name


def create_key_pair_if_needed(key_name, region, log_callback):
    cmd_check = f"aws ec2 describe-key-pairs --key-names {key_name} --region {region}"
    _, stderr = run_cmd(cmd_check, log_callback=log_callback, check=False)
    if "InvalidKeyPair.NotFound" in stderr:
        log_callback(f"[INFO] Creating Key Pair '{key_name}'...\n")
        cmd_create = (
            f"aws ec2 create-key-pair --key-name {key_name} "
            f"--region {region} --query 'KeyMaterial' --output text"
        )
        stdout, _ = run_cmd(cmd_create, log_callback=log_callback)
        pem_file = f"{key_name}.pem"
        with open(pem_file, "w") as f:
            f.write(stdout)
        os.chmod(pem_file, 0o400)
        log_callback(f"[INFO] Key Pair created locally: {pem_file} (chmod 400).\n")
        return move_pem_to_ssh_directory(pem_file, log_callback)
    else:
        log_callback(f"[INFO] Key Pair '{key_name}' already exists.\n")
        guessed_path = os.path.join(os.path.expanduser("~"), ".ssh", f"{key_name}.pem")
        return guessed_path


def create_security_group_if_needed(ec2_name, region, vpc_id, log_callback):
    sg_name = f"{ec2_name}-sg"
    cmd_describe = (
        f"aws ec2 describe-security-groups --filters Name=group-name,Values={sg_name} "
        f"--region {region} --query 'SecurityGroups[*].GroupId' --output text"
    )
    stdout, _ = run_cmd(cmd_describe, log_callback=log_callback, check=False)

    if stdout.strip():
        sg_id = stdout.strip()
        log_callback(f"[INFO] Security Group '{sg_name}' already exists: {sg_id}\n")
        return sg_id

    log_callback(f"[INFO] Creating Security Group '{sg_name}'...\n")
    create_cmd = (
        f"aws ec2 create-security-group --group-name {sg_name} "
        f"--description 'AppSecurityGroup' --vpc-id {vpc_id} --region {region} "
        f"--query 'GroupId' --output text"
    )
    sg_out, _ = run_cmd(create_cmd, log_callback=log_callback)
    sg_id = sg_out.strip()

    # Tag
    tag_cmd = (
        f"aws ec2 create-tags --resources {sg_id} --region {region} "
        f"--tags Key=Name,Value={sg_name}"
    )
    run_cmd(tag_cmd, log_callback)

    # Authorize inbound rules (22,80,443)
    for port in [22, 80, 443]:
        auth_cmd = (
            f"aws ec2 authorize-security-group-ingress --group-id {sg_id} "
            f"--protocol tcp --port {port} --cidr 0.0.0.0/0 --region {region}"
        )
        run_cmd(auth_cmd, log_callback)

    log_callback(f"[INFO] Security Group created: {sg_id}\n")
    return sg_id


def allocate_elastic_ip(region, log_callback):
    cmd = (
        f"aws ec2 allocate-address --domain vpc --region {region} "
        f"--query '[AllocationId,PublicIp]' --output text"
    )
    stdout, _ = run_cmd(cmd, log_callback=log_callback)
    alloc_id, public_ip = stdout.split()
    log_callback(
        f"[INFO] Allocated Elastic IP: {public_ip} (AllocationId: {alloc_id})\n"
    )
    return alloc_id, public_ip


def associate_elastic_ip(instance_id, alloc_id, region, log_callback):
    cmd = (
        f"aws ec2 associate-address --instance-id {instance_id} "
        f"--allocation-id {alloc_id} --region {region}"
    )
    run_cmd(cmd, log_callback=log_callback)
    log_callback("[INFO] Elastic IP associated with instance.\n")


def launch_ec2_instance(
    ec2_name, key_name, sg_id, subnet_id, region, user_data_script, log_callback
):
    log_callback(
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
    stdout, _ = run_cmd(cmd_launch, log_callback=log_callback)
    instance_id = stdout.strip()

    log_callback(f"[INFO] Instance launched: {instance_id}\n")

    # Wait until running
    wait_cmd = (
        f"aws ec2 wait instance-running --instance-ids {instance_id} --region {region}"
    )
    run_cmd(wait_cmd, log_callback=log_callback)
    log_callback("[INFO] EC2 instance is now running.\n")

    # Grab public DNS
    dns_cmd = (
        f"aws ec2 describe-instances --instance-ids {instance_id} --region {region} "
        f"--query 'Reservations[0].Instances[0].PublicDnsName' --output text"
    )
    dns_out, _ = run_cmd(dns_cmd, log_callback=log_callback)
    public_dns = dns_out.strip()
    log_callback(f"[INFO] Instance Public DNS: {public_dns}\n")

    return instance_id, public_dns
