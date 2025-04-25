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

    # Components checkbuttons
    component_frame = tk.LabelFrame(root, text="Components to enable")
    component_frame.grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky="ew")
    component_vars = {}
    comps = [
        ("Build Python from source", "python_source"),
        ("Configure Apache proxy",    "apache"),
        ("Run Supervisor for app",     "supervisor"),
        ("Obtain SSL via Certbot",     "certbot"),
        ("Enable RDS",                 "enable_rds"),
    ]
    for idx, (label_text, key) in enumerate(comps):
        var = tk.BooleanVar(value=False)
        cb = tk.Checkbutton(component_frame, text=label_text, variable=var)
        cb.grid(row=0, column=idx, padx=5, pady=5)
        component_vars[key] = var

    # RDS fields at bottom; we hide them initially if enable_rds is not checked
    def on_enable_rds_change(*_):
        if component_vars["enable_rds"].get():
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

    # Attach trace to enable_rds BooleanVar
    component_vars["enable_rds"].trace_add("write", on_enable_rds_change)

    # Place RDS fields starting at row after entries
    rds_row_start = row
    db_id_label = tk.Label(root, text="RDS DB Identifier")
    db_id_label.grid(row=rds_row_start, column=0, sticky="e", padx=5, pady=5)
    db_id_entry = tk.Entry(root, textvariable=entries["db_identifier"], width=40)
    db_id_entry.grid(row=rds_row_start, column=1, padx=5, pady=5)

    db_user_label = tk.Label(root, text="RDS Username")
    db_user_label.grid(row=rds_row_start + 1, column=0, sticky="e", padx=5, pady=5)
    db_user_entry = tk.Entry(root, textvariable=entries["db_username"], width=40)
    db_user_entry.grid(row=rds_row_start + 1, column=1, padx=5, pady=5)

    db_pass_label = tk.Label(root, text="RDS Password")
    db_pass_label.grid(row=rds_row_start + 2, column=0, sticky="e", padx=5, pady=5)
    db_pass_entry = tk.Entry(
        root, textvariable=entries["db_password"], width=40, show="*"
    )
    db_pass_entry.grid(row=rds_row_start + 2, column=1, padx=5, pady=5)

    on_enable_rds_change()  # init state

    # Add Code source frame with Radiobuttons
    source_frame = tk.LabelFrame(root, text="Code source")
    source_frame.grid(row=rds_row_start + 3, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
    source_var = tk.StringVar(value="git")
    rb1 = tk.Radiobutton(source_frame, text="Git Clone", variable=source_var, value="git")
    rb2 = tk.Radiobutton(source_frame, text="Local Copy", variable=source_var, value="copy")
    rb1.grid(row=0, column=0, padx=5)
    rb2.grid(row=0, column=1, padx=5)

    # Add local path entry, hidden initially
    lp_var = tk.StringVar()
    lp_label = tk.Label(root, text="Local Path")
    lp_entry = tk.Entry(root, textvariable=lp_var, width=40)

    def on_source_var_change(*_):
        if source_var.get() == "copy":
            lp_label.grid(row=rds_row_start + 4, column=0, sticky="e", padx=5, pady=5)
            lp_entry.grid(row=rds_row_start + 4, column=1, padx=5, pady=5)
        else:
            lp_label.grid_remove()
            lp_entry.grid_remove()

    source_var.trace_add("write", on_source_var_change)
    on_source_var_change()  # init state

    log_text = tk.Text(root, width=80, height=15)
    log_text.grid(row=rds_row_start + 5, column=0, columnspan=2, padx=5, pady=5)

    # Progress bar below log text
    progress_bar = ttk.Progressbar(root, orient='horizontal', length=400, mode='determinate')
    progress_bar.grid(row=rds_row_start + 6, column=0, columnspan=2, padx=5, pady=5)

    def log_callback(msg):
        log_text.insert(tk.END, msg)
        log_text.see(tk.END)
        root.update()

    def progress_callback(current, total):
        progress_bar['maximum'] = total
        progress_bar['value'] = current
        root.update_idletasks()

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
        gui_args.components = [k for k, v in component_vars.items() if v.get()]

        gui_args.db_identifier = entries["db_identifier"].get().strip()
        gui_args.db_username = entries["db_username"].get().strip()
        gui_args.db_password = entries["db_password"].get()

        gui_args.source_method = source_var.get()
        gui_args.local_path = lp_entry.get().strip()

        try:
            deploy(gui_args, log_callback, progress_callback)
        except SystemExit as e:
            log_callback(f"[ERROR] {e}\n")

    def on_sign_out():
        sign_out_aws_credentials(log_callback)
        top_label.config(
            text="Signed out (credentials cleared). Re-run 'aws configure' to sign in again.",
            fg="red",
        )

    btn_deploy = ttk.Button(root, text="Deploy", command=on_deploy)
    btn_deploy.grid(row=rds_row_start + 7, column=0, pady=10, sticky="e")

    btn_signout = ttk.Button(root, text="Sign Out", command=on_sign_out)
    btn_signout.grid(row=rds_row_start + 7, column=1, pady=10, sticky="w")

    root.mainloop()
