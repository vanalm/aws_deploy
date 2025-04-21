# gui.py

import tkinter as tk
from tkinter import ttk
import argparse
from .aws_cli_utils import check_aws_cli_credentials, sign_out_aws_credentials
from .deploy import deploy
from .constants import DEFAULT_REGION


def launch_gui():
    """
    Simple tkinter GUI for collecting arguments and deploying.
    Hides RDS fields unless "enable_rds" is yes.
    """
    root = tk.Tk()
    root.title("AWS Deployment Tool")

    creds_ok, result_str = check_aws_cli_credentials()

    if creds_ok:
        acct_label_text = f"Signed in as account {result_str}"
        acct_label_fg = "blue"
    else:
        acct_label_text = result_str.strip()
        acct_label_fg = "red"

    top_label = tk.Label(root, text=acct_label_text, fg=acct_label_fg)
    top_label.grid(row=0, column=0, columnspan=2, padx=5, pady=5)

    defaults = {
        "aws_region": DEFAULT_REGION,
        "ec2_name": "MyEC2Instance",
        "key_name": "MyKeyPair",
        "domain": "mydomain.com",
        "repo_url": "https://github.com/youruser/yourrepo.git",
        "subnet_type": "public",
        "enable_rds": "no",
        "db_identifier": "myDB",
        "db_username": "admin",
        "db_password": "MyDbPassword123",
    }

    labels = {
        "aws_region": "AWS Region",
        "ec2_name": "EC2 Name",
        "key_name": "Key Pair Name",
        "domain": "Domain Name",
        "repo_url": "Git Repo URL",
        "subnet_type": "Subnet Type (public/nat)",
        "enable_rds": "Enable RDS (yes/no)",
        "db_identifier": "RDS DB Identifier",
        "db_username": "RDS Username",
        "db_password": "RDS Password",
    }

    entries = {}
    row = 1
    for field, label_text in labels.items():
        lbl = tk.Label(root, text=label_text)
        lbl.grid(row=row, column=0, padx=5, pady=5, sticky="e")

        var = tk.StringVar(value=defaults.get(field, ""))
        ent = tk.Entry(root, textvariable=var, width=40)
        ent.grid(row=row, column=1, padx=5, pady=5)
        entries[field] = var
        row += 1

    # RDS fields at bottom; we hide them initially if enable_rds="no"
    def on_enable_rds_change(*_):
        if entries["enable_rds"].get().lower() == "yes":
            db_id_label.grid()
            db_id_entry.grid()
            db_user_label.grid()
            db_user_entry.grid()
            db_pass_label.grid()
            db_pass_entry.grid()
        else:
            db_id_label.grid_remove()
            db_id_entry.grid_remove()
            db_user_label.grid_remove()
            db_user_entry.grid_remove()
            db_pass_label.grid_remove()
            db_pass_entry.grid_remove()

    entries["enable_rds"].trace_add("write", on_enable_rds_change)

    db_id_label = tk.Label(root, text="RDS DB Identifier")
    db_id_label.grid(row=7, column=0, sticky="e", padx=5, pady=5)
    db_id_entry = tk.Entry(root, textvariable=entries["db_identifier"], width=40)
    db_id_entry.grid(row=7, column=1, padx=5, pady=5)

    db_user_label = tk.Label(root, text="RDS Username")
    db_user_label.grid(row=8, column=0, sticky="e", padx=5, pady=5)
    db_user_entry = tk.Entry(root, textvariable=entries["db_username"], width=40)
    db_user_entry.grid(row=8, column=1, padx=5, pady=5)

    db_pass_label = tk.Label(root, text="RDS Password")
    db_pass_label.grid(row=9, column=0, sticky="e", padx=5, pady=5)
    db_pass_entry = tk.Entry(
        root, textvariable=entries["db_password"], width=40, show="*"
    )
    db_pass_entry.grid(row=9, column=1, padx=5, pady=5)

    on_enable_rds_change()  # init state

    log_text = tk.Text(root, width=80, height=15)
    log_text.grid(row=10, column=0, columnspan=2, padx=5, pady=5)

    def log_callback(msg):
        log_text.insert(tk.END, msg)
        log_text.see(tk.END)
        root.update()

    def on_deploy():
        if not creds_ok:
            log_callback("[ERROR] AWS CLI not ready or credentials missing.\n")
            return

        gui_args = argparse.Namespace()
        gui_args.aws_region = entries["aws_region"].get().strip()
        gui_args.ec2_name = entries["ec2_name"].get().strip()
        gui_args.key_name = entries["key_name"].get().strip()
        gui_args.domain = entries["domain"].get().strip()
        gui_args.repo_url = entries["repo_url"].get().strip()
        gui_args.subnet_type = entries["subnet_type"].get().strip()
        gui_args.enable_rds = entries["enable_rds"].get().strip()
        gui_args.db_identifier = entries["db_identifier"].get().strip()
        gui_args.db_username = entries["db_username"].get().strip()
        gui_args.db_password = entries["db_password"].get()

        try:
            deploy(gui_args, log_callback)
        except SystemExit as e:
            log_callback(f"[ERROR] {e}\n")

    def on_sign_out():
        sign_out_aws_credentials(log_callback)
        top_label.config(
            text="Signed out (credentials cleared). Re-run 'aws configure' to sign in again.",
            fg="red",
        )

    btn_deploy = ttk.Button(root, text="Deploy", command=on_deploy)
    btn_deploy.grid(row=11, column=0, pady=10, sticky="e")

    btn_signout = ttk.Button(root, text="Sign Out", command=on_sign_out)
    btn_signout.grid(row=11, column=1, pady=10, sticky="w")

    root.mainloop()
