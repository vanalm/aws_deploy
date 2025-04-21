#!/usr/bin/env python3

import tkinter as tk
from tkinter import scrolledtext
import subprocess
import sys
import traceback


def run_aws_commands():
    """
    Collect input data from GUI, build AWS CLI commands, run them, and show output in text widget.
    """
    try:
        output_box.delete(1.0, tk.END)
        output_box.insert(tk.END, "Running AWS commands...\n\n")

        region = region_var.get().strip()
        instance_id = instance_id_var.get().strip()
        security_group_id = sg_id_var.get().strip()
        vpc_id = vpc_id_var.get().strip()
        subnet_id = subnet_id_var.get().strip()

        # For debugging, let's run a simple echo first to see if we can capture output
        test_command = "echo 'Test: Subprocess is running successfully...'"
        test_result = subprocess.run(
            test_command, shell=True, capture_output=True, text=True
        )
        output_box.insert(tk.END, test_result.stdout + "\n")

        # Build the AWS CLI commands
        commands = []

        # 1) Describe basic instance details
        commands.append(
            f"""
echo "=== EC2 Instance Details (basic) ==="
aws ec2 describe-instances \\
  --instance-id {instance_id} \\
  --region {region} \\
  --query 'Reservations[].Instances[].{{State: State.Name, KeyName: KeyName, PublicIP: PublicIpAddress, PublicDNS: PublicDnsName, SecurityGroups: SecurityGroups}}' \\
  --output table
""".strip()
        )

        # 2) Full instance JSON
        commands.append(
            f"""
echo
echo "=== EC2 Instance Full JSON ==="
aws ec2 describe-instances \\
  --instance-id {instance_id} \\
  --region {region}
""".strip()
        )

        # 3) Describe security group inbound rules
        commands.append(
            f"""
echo
echo "=== Security Group Inbound Rules (SSH) ==="
aws ec2 describe-security-groups \\
  --group-ids {security_group_id} \\
  --region {region} \\
  --query 'SecurityGroups[].IpPermissions[]' \\
  --output table
""".strip()
        )

        # 4) Show VPC and subnet
        commands.append(
            f"""
echo
echo "=== VPC / Subnet for the Instance ==="
aws ec2 describe-instances \\
  --instance-id {instance_id} \\
  --region {region} \\
  --query 'Reservations[].Instances[].{{VPC:VpcId,Subnet:SubnetId}}' \\
  --output table
""".strip()
        )

        # 5) Show the route tables for the VPC
        commands.append(
            f"""
echo
echo "=== Route Tables for VPC {vpc_id} ==="
aws ec2 describe-route-tables \\
  --filters "Name=vpc-id,Values={vpc_id}" \\
  --region {region}
""".strip()
        )

        # 6) Show the network ACLs for the VPC (or specifically the subnet)
        commands.append(
            f"""
echo
echo "=== Network ACLs for Subnet {subnet_id} ==="
aws ec2 describe-network-acls \\
  --filters "Name=vpc-id,Values={vpc_id}" \\
  --region {region}

echo
echo "=== Done! ==="
""".strip()
        )

        # Combine everything into one script so we get the same output order
        full_script = "\n\n".join(commands)

        # Execute the combined script
        completed_process = subprocess.run(
            full_script, shell=True, capture_output=True, text=True
        )

        # Show stdout and stderr
        if completed_process.stdout:
            output_box.insert(tk.END, completed_process.stdout)
        if completed_process.stderr:
            output_box.insert(tk.END, "\n[stderr]\n" + completed_process.stderr)

    except Exception as e:
        # If an unexpected exception occurs, print the traceback in the output box
        output_box.insert(tk.END, "An error occurred:\n")
        output_box.insert(tk.END, str(e) + "\n\n")
        output_box.insert(tk.END, traceback.format_exc())


# -----------------------------
# Create Tkinter window
# -----------------------------
root = tk.Tk()
root.title("AWS EC2 Info Viewer (Debug Mode)")

# Instruction label
instruction_label = tk.Label(root, text="Enter AWS details below, then click 'Run'.")
instruction_label.pack(pady=5)

# Frame for inputs
input_frame = tk.Frame(root)
input_frame.pack(padx=10, pady=10, fill="x")

# Region
tk.Label(input_frame, text="AWS Region:").grid(row=0, column=0, sticky="e")
region_var = tk.StringVar(value="us-west-2")
tk.Entry(input_frame, textvariable=region_var, width=20).grid(
    row=0, column=1, padx=5, pady=5
)

# Instance ID
tk.Label(input_frame, text="EC2 Instance ID:").grid(row=1, column=0, sticky="e")
instance_id_var = tk.StringVar(value="i-062b04c06de204687")
tk.Entry(input_frame, textvariable=instance_id_var, width=20).grid(
    row=1, column=1, padx=5, pady=5
)

# Security Group ID
tk.Label(input_frame, text="Security Group ID:").grid(row=2, column=0, sticky="e")
sg_id_var = tk.StringVar(value="sg-03e2a120bea027f02")
tk.Entry(input_frame, textvariable=sg_id_var, width=20).grid(
    row=2, column=1, padx=5, pady=5
)

# VPC ID
tk.Label(input_frame, text="VPC ID:").grid(row=3, column=0, sticky="e")
vpc_id_var = tk.StringVar(value="vpc-08b0b5b1f3f1dc014")
tk.Entry(input_frame, textvariable=vpc_id_var, width=20).grid(
    row=3, column=1, padx=5, pady=5
)

# Subnet ID
tk.Label(input_frame, text="Subnet ID:").grid(row=4, column=0, sticky="e")
subnet_id_var = tk.StringVar(value="subnet-07992b469429c12ba")
tk.Entry(input_frame, textvariable=subnet_id_var, width=20).grid(
    row=4, column=1, padx=5, pady=5
)

# Run button
run_button = tk.Button(input_frame, text="Run", command=run_aws_commands)
run_button.grid(row=5, column=0, columnspan=2, pady=10)

# ScrolledText for output
output_box = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=100, height=30)
output_box.pack(padx=10, pady=10)

# Final instructions
final_label = tk.Label(root, text="Press 'Run' to execute AWS CLI commands.")
final_label.pack(pady=(0, 10))

root.mainloop()
