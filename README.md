## Overview
This tool, aws_deploy_tool.py, automates provisioning of AWS resources for a Python web application (e.g., FastAPI+Gradio) with an Amazon Linux EC2 and an optional Postgres RDS instance. It sets up:

- Key Pair (if not found)

- Security Group with inbound rules (22, 80, 443)

- EC2 t3.micro instance (Amazon Linux 2)

- Elastic IP (static IP)

- Apache reverse proxy and Let’s Encrypt for SSL

- (Optional) RDS Postgres (Free Tier)

The script can run in two modes:

1. GUI Mode (tkinter): If you run the script without CLI arguments, it shows a simple GUI form for collecting inputs.

2. CLI Mode: Provide the required arguments (or rely on defaults), and it runs automatically—no GUI.

## Prerequisites
1. AWS CLI must be installed and configured locally:
```bash
aws configure
```
2. Python 3 is needed locally to run the script.

3. Domain Name: If you want SSL to work immediately, you should have a domain name that you can point to the EC2’s Elastic IP.

4. GitHub Repo: The script will git pull from your specified repository URL. Ensure it’s public or your EC2 can clone it (if private, you’ll need a different approach for SSH keys).

## Installation
1. Place `aws_deploy_tool.py` in a directory on your local machine.
2. Make it executable (options):
`chmod +x aws_deploy_tool.py`
3. Ensure you have the AWS CLI installed.

## Usage
Run: 
```bash
python aws_deploy_tool.py
```

No arguments → the tkinter GUI appears. You can:
- Modify the default region, EC2 name, domain, etc.
- Click Deploy to start the provisioning process.
- Watch logs in the text box.

When asked about DNS, point your domain’s A-record to the allocated Elastic IP if you want Let’s Encrypt to succeed immediately.

2. CLI Mode
Provide CLI arguments for a fully automated run. Example:
```bash 
python aws_deploy_tool.py \
  --aws-region us-west-2 \
  --ec2-name MyEC2Instance \
  --key-name MyKeyPair \
  --domain mydomain.com \
  --repo-url https://github.com/youruser/yourrepo.git \
  --enable-rds yes \
  --db-identifier myDB \
  --db-username admin \
  --db-password MyDbPassword123
```

The script will output logs to the console.

### Available arguments:

- --aws-region: (e.g. us-west-2)

- --ec2-name: Name tag for the EC2 instance

- --key-name: AWS Key Pair name

- --domain: Your domain (point an A-record to the allocated EIP)

- --repo-url: The Git repo to clone (main branch assumed)

- --enable-rds: yes or no (default no)

- --db-identifier: DB name/identifier for RDS

- --db-username: Postgres master username

- --db-password: Postgres master password

- --no-gui: Force CLI mode even if no arguments are given

## Flow
1. Key Pair: Checks if `--key-name` exists. If missing, creates it and saves locally as `KeyName.pem`.

2. Security Group: Opens ports 22 (SSH), 80 (HTTP), 443 (HTTPS).

3. EC2: Launches a `t3.micro` with Amazon Linux 2 in `us-west-2` (change AMI if you want a different region/OS).

4. Elastic IP: Allocates and associates to the EC2—your instance has a static IP.

5. DNS Prompt: The script will pause after EIP association, instructing you to point your domain’s DNS A-record to this IP.

    - Type `done` if DNS is set (Let’s Encrypt might succeed).

    - Type `skip` if you want to continue anyway (you’ll need to re-run certbot later).

6. RDS (Optional): If `--enable-rds yes`, it creates a Postgres DB instance. On completion, it prints a DB connection URL you can copy (like `postgresql://admin:pass@endpoint:5432/myDB`).

7. User-Data: On first boot, the EC2 runs a cloud-init script that:

    - Builds Python 3.12.8 from source

    - Installs Git, Apache, Let’s Encrypt, etc.

    - Clones your specified repo

    - Installs your Python dependencies (`fastapi`, `gradio`, `uvicorn`, `supervisor`)

    - Configures Apache as a reverse proxy on `443` → `127.0.0.1:8000`

    - Attempts to acquire an SSL cert from Let’s Encrypt (if DNS is set up)

    - Launches `uvicorn main:app` via Supervisor

## Tips and Customization
1. AMI ID: The default `ami-09e67e426f25ce0d7` is for Amazon Linux 2 in `us-west-2` (x86_64). If you use another region or architecture, find the appropriate AMI ID and update `DEFAULT_AMI`.

2. t3.micro: Adjust to a larger instance if building Python 3.12.8 is too slow or you need more resources.

3. User-Data: Modify the commands in `create_userdata_script()` if you have a different setup (e.g., you don’t need custom building of Python).

4. Private Git Repo: For private repos, the script does a simple `git pull`. You’d need to add credentials (SSH key, etc.) or another approach if your repo is not public.

5. Production Hardening:

    - Consider a process manager like Systemd or Docker-based deployment instead of Supervisor.

    - Add logging, monitoring (CloudWatch), and backups.

    - For large loads, consider an ALB + Auto Scaling Group.

## Troubleshooting
- AWS CLI not found: Ensure `aws --version` works on your machine.

- Credentials: If you see “unable to locate credentials,” run aws configure again.

- AMI not found: Make sure your region is correct.

- DNS: If Let’s Encrypt fails to verify domain, confirm your domain A-record points to the allocated EIP.

- Exiting: If any command fails, the script sys.exits with an error message in logs.

