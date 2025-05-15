# AWS Deployment Tool

A Python-based, modular toolkit for provisioning AWS infrastructure and deploying a FastAPI+Gradio (or similar) app on Amazon Linux EC2 (t3.micro). Supports:

- VPC & Subnet (public or NAT) setup
- Security Group and Key Pair management
- EC2 instance launch with cloud-init user-data
- Elastic IP allocation and association
- Optional RDS Postgres provisioning
- Tkinter GUI and CLI interfaces

---
## TODO
[] install dependencies
[] monitor cpu usage from cli, show widget of cpu status from cli 
[] deploy app based on template structure

## Table of Contents
1. [Features](#features)
2. [Architecture & Modules](#architecture--modules)
3. [Prerequisites](#prerequisites)
4. [Installation](#installation)
5. [Usage](#usage)
   - [CLI Mode](#cli-mode)
   - [GUI Mode](#gui-mode)
6. [Configuration & Customization](#configuration--customization)
7. [Step-by-Step Walkthrough](#step-by-step-walkthrough)
8. [Troubleshooting & Adjustments](#troubleshooting--adjustments)
9. [Contributing](#contributing)
10. [License](#license)

---

## Features

- **Modular design**: Clean separation of networking, EC2, RDS, user-data, GUI, and CLI logic
- **Flexible subnet**: Public (IGW) or outbound-only (NAT) subnets
- **Idempotent**: Reuses existing VPCs, subnets, route tables, IGWs, NATs, key pairs, SGs
- **Optional RDS**: Create a PostgreSQL instance with a single flag
- **Automated deployment**: Launch instances with built-in cloud-init to install dependencies, clone your repo, and configure Apache + Uvicorn
- **Dual interface**: Run via command line or a simple Tkinter GUI

---

## Architecture & Modules

| Module                | Responsibility                                     |
|-----------------------|----------------------------------------------------|
| `aws_cli_utils.py`    | AWS CLI credential checks, shell command wrapper   |
| `constants.py`        | Global constants (AMI IDs, default region, etc.)   |
| `networking.py`       | VPC, subnet, route table, IGW/NAT provisioning     |
| `ec2.py`              | Key pairs, security groups, instance launch, EIP   |
| `rds.py`              | RDS Postgres provisioning                          |
| `userdata.py`         | Generates cloud-init scripts                       |
| `deploy.py`           | Orchestrates end-to-end deployment                 |
| `cli.py`              | Command-line parsing and runner                    |
| `gui.py`              | Tkinter-based GUI                                  |
| `main.py`             | Entry point (`python -m aws_deploy_tool.main`)     |

---

## Prerequisites

- Python 3.8+ installed locally
- AWS CLI v2 installed and configured (`aws configure`)
- Your AWS credentials and permissions to create VPCs, EC2, RDS, etc.
- Git access to your application repository

---

## Installation

1. Clone this repo:
   ```bash
   git clone https://github.com/youruser/aws_deploy_tool.git
   cd aws_deploy_tool
   ```
2. (Optional) Create a virtual environment and install dependencies:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt  # if you add any Python deps
   ```

---

## Usage

### CLI Mode

Run with flags to skip GUI:
```bash
python -m aws_deploy_tool.main \
  --aws-region us-west-2 \
  --ec2-name MyAppInstance \
  --key-name MyKeyPair \
  --domain example.com \
  --repo-url https://github.com/youruser/yourrepo.git \
  --subnet-type public \
  --enable-rds yes \
  --db-identifier myapp-db \
  --db-username admin \
  --db-password SecretPass123 \
  --no-gui
```

### GUI Mode

Simply run without args:
```bash
python -m aws_deploy_tool.main
```
A Tkinter window will appear. Fill in fields and click **Deploy**.

---

## Configuration & Customization

- **Existing VPC/Subnet**: Edit `networking.py` to accept `--vpc-id` or `--subnet-id` flags and bypass creation logic.
- **AMI Version**: Update `DEFAULT_AMI` in `constants.py`.
- **User-Data**: Modify `create_userdata_script()` in `userdata.py` to install extra packages or change boot tasks.
- **Security Rules**: Adjust port rules in `create_security_group_if_needed()` in `ec2.py`.
- **RDS Settings**: Tweak instance class, storage, or engine version in `rds.py`.

---

## Step-by-Step Walkthrough

1. **Initialize & Credential Check**
   - The tool starts by verifying that the AWS CLI is installed and credentials are configured (`check_aws_cli_credentials`).
   - If missing, it aborts and prompts you to run `aws configure`.

2. **VPC Discovery/Creation**
   - It looks for a VPC tagged `<EC2_NAME>-vpc` via `describe-vpcs`.
   - If not found, creates a new VPC (`create-vpc --cidr-block 10.0.0.0/16`), tags it, and enables DNS hostnames.

3. **Subnet & Routing**
   - Searches for a subnet named `<EC2_NAME>-subnet`. If absent, it creates `10.0.1.0/24` in the first AZ.
   - A route table `<EC2_NAME>-rtb` is found or created, then associated with the subnet.
   - **Public Subnet (IGW)**: If `--subnet-type public`, the script finds or creates `<EC2_NAME>-igw`, attaches it to the VPC, and routes `0.0.0.0/0` to it. The subnet is set to auto-assign public IPs.
   - **Outbound-only (NAT)**: If `--subnet-type nat`, it allocates an Elastic IP, creates `<EC2_NAME>-natgw`, waits for it, and routes `0.0.0.0/0` through the NAT gateway.

4. **Key Pair Management**
   - Checks for an existing key named `--key-name`.
   - If missing, uses `create-key-pair` to generate one, saves the `.pem`, sets `chmod 400`, and moves it to `~/.ssh`.

5. **Security Group**
   - Looks for a group `<EC2_NAME>-sg`. If not present, creates it in the VPC and opens ports **22**, **80**, and **443**.

6. **User-Data & Application Setup**
   - Builds a `userdata_deploy.txt` cloud-init script:
     - Updates packages and installs Git, Apache, Certbot, AWS CLI, etc.
     - Builds Python 3.12.8 from source and creates a virtualenv.
     - Clones your Git repo via HTTPS into `/home/ec2-user/app`.
     - Installs required Python packages (`fastapi`, `gradio`, `uvicorn`, `supervisor`).
     - Configures Apache as a reverse proxy and requests a Let’s Encrypt certificate for your domain.

7. **EC2 Launch**
   - Runs `aws ec2 run-instances` with the chosen AMI, instance type, key, SG, subnet, and tags the instance `Name=<EC2_NAME>`.
   - Waits for the instance to become `running`.
   - Retrieves its Public DNS.

8. **Elastic IP for EC2**
   - Allocates a fresh Elastic IP and associates it with the launched instance, giving you a static address.

9. **Optional RDS Provisioning**
   - If `--enable-rds yes`, uses `create-db-instance` to spin up a `db.t3.micro` PostgreSQL.
   - Waits for availability, then fetches its endpoint and prints a connection URL.

10. **Final Output**
   - Prints instructions to SSH into the instance:
     ```bash
     ssh -i ~/.ssh/<key-name>.pem ec2-user@<Elastic IP>
     ```
   - Reminds you to point your DNS A-record to the EIP so that **Apache + Certbot** will serve your domain securely.

---

## Troubleshooting & Adjustments

- **Credentials Errors**: Run `aws configure` or ensure env vars `AWS_ACCESS_KEY_ID` etc. are set.
- **Resource Already Exists**: If a resource name conflicts, either delete it in the AWS Console or change your `ec2_name` to avoid collision.
- **Timeouts**: For large environments, AWS `wait` commands may take several minutes—be patient or increase CLI timeouts.
- **Incomplete User-Data**: Inspect `/var/log/cloud-init-output.log` on the EC2 instance for errors.
- **Repo Folder Not Found**:
  - By default, your repository is cloned via cloud-init into `/home/ec2-user/app` on the instance.
  - Verify the directory exists:
    ```bash
    ssh -i ~/.ssh/<key-name>.pem ec2-user@<Elastic IP>
    ls -l /home/ec2-user/app
    ```
  - If the folder is missing or empty, check cloud-init logs:
    ```bash
    sudo cat /var/log/cloud-init-output.log | grep git
    ```
  - Ensure your `repo_url` is correct and publicly accessible (or adjust for private repos using a token or SSH key in `userdata.py`).
  - **Rerunning the Build**: Cloud-init runs only once on first launch. If you need to re-clone or reapply user-data:

1. **Destroy and re-launch** the EC2 instance using the tool so cloud-init executes again.
2. Or manually re-run cloud-init on your existing instance:
   ```bash
   # Re-initialize cloud-init
   sudo cloud-init init

   # Re-configure: processes data sources, modules in 'config' stage
   sudo cloud-init modules --mode=config

   # Final stage: executes 'runcmd' and other final modules
   sudo cloud-init modules --mode=final
   ```

   - `cloud-init init` re-initializes the instance's cloud-init run stages, clearing any status cache and starting from scratch.
   - `cloud-init modules --mode=config` processes configuration modules, pulling in metadata and writing files like `userdata_deploy.txt`.
   - `cloud-init modules --mode=final` executes the final modules, including the `runcmd` section in your user-data, which contains the git clone, package installs, and service configuration.

   Running these three commands simulates the first-boot sequence without recreating the instance, effectively reapplying your cloud-init user-data.

   **Note**: Some modules only run once by default; you may need to clear `/var/lib/cloud/instances` if re-running fails.
```

---

