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
    Uses radio buttons for RDS choice (No/Yes) and code source (Git/Local).
    Certain fields (DB credentials or repo URL) show only when relevant.
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

    # Default values for input fields
    defaults = {
        "aws_region": DEFAULT_REGION,
        "ec2_name": "mauibuilder",
        "key_name": "mauibuilder_keypair",
        "domain": "mauibuilder.ai",
        "subnet_type": "public",
        # Keep RDS & repo defaults for convenience even though they're hidden in the main form
        "db_identifier": "myDB",
        "db_username": "admin",
        "db_password": "MyDbPassword123",
        "repo_url": "https://github.com/youruser/yourrepo.git",
        "local_path": "/Users/jacobvanalmelo/code/mauibuilder",
    }

    # We only keep certain fields in the main label/entry form now
    labels = {
        "aws_region": "AWS Region",
        "ec2_name":  "EC2 Name",
        "key_name":  "Key Pair Name",
        "domain":    "Domain Name",
        "subnet_type": "Subnet Type (public/nat)",
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

    # Comment out the "Supervisor" checkbox and remove "enable_rds" entirely
    component_frame = tk.LabelFrame(root, text="Components to enable")
    component_frame.grid(row=row, column=0, columnspan=2, padx=5, pady=5, sticky="ew")
    row += 1

    component_vars = {}
    comps = [
        ("Build Python from source", "python_source"),
        ("Configure Apache proxy",   "apache"),
        # ("Run Supervisor for app",    "supervisor"),  # <--- COMMENTED OUT
        ("Obtain SSL via Certbot",   "certbot"),
    ]
    for idx, (label_text, key) in enumerate(comps):
        var = tk.BooleanVar(value=False)
        cb = tk.Checkbutton(component_frame, text=label_text, variable=var)
        cb.grid(row=0, column=idx, padx=5, pady=5)
        component_vars[key] = var

    # Separate frame for RDS radio buttons
    rds_frame = tk.LabelFrame(root, text="RDS Option")
    rds_frame.grid(row=row, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
    row += 1

    rds_var = tk.StringVar(value="no")
    r1 = tk.Radiobutton(rds_frame, text="No RDS", variable=rds_var, value="no")
    r2 = tk.Radiobutton(rds_frame, text="Yes RDS", variable=rds_var, value="yes")
    r1.grid(row=0, column=0, padx=5, pady=5)
    r2.grid(row=0, column=1, padx=5, pady=5)

    # RDS credential fields (hidden unless "Yes RDS")
    db_id_var = tk.StringVar(value=defaults["db_identifier"])
    db_user_var = tk.StringVar(value=defaults["db_username"])
    db_pass_var = tk.StringVar(value=defaults["db_password"])

    db_id_label = tk.Label(rds_frame, text="RDS DB Identifier")
    db_id_entry = tk.Entry(rds_frame, textvariable=db_id_var, width=40)
    db_user_label = tk.Label(rds_frame, text="RDS Username")
    db_user_entry = tk.Entry(rds_frame, textvariable=db_user_var, width=40)
    db_pass_label = tk.Label(rds_frame, text="RDS Password")
    db_pass_entry = tk.Entry(rds_frame, textvariable=db_pass_var, width=40, show="*")

    def on_rds_var_change(*_):
        if rds_var.get() == "yes":
            db_id_label.grid(row=1, column=0, padx=5, pady=5, sticky="e")
            db_id_entry.grid(row=1, column=1, padx=5, pady=5)
            db_user_label.grid(row=2, column=0, padx=5, pady=5, sticky="e")
            db_user_entry.grid(row=2, column=1, padx=5, pady=5)
            db_pass_label.grid(row=3, column=0, padx=5, pady=5, sticky="e")
            db_pass_entry.grid(row=3, column=1, padx=5, pady=5)
        else:
            db_id_label.grid_remove()
            db_id_entry.grid_remove()
            db_user_label.grid_remove()
            db_user_entry.grid_remove()
            db_pass_label.grid_remove()
            db_pass_entry.grid_remove()

    rds_var.trace_add("write", on_rds_var_change)
    on_rds_var_change()  # initialize hidden state

    # Code source frame (radio buttons for Git vs Local Copy)
    source_frame = tk.LabelFrame(root, text="Code Source")
    source_frame.grid(row=row, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
    row += 1

    source_var = tk.StringVar(value="copy")
    rb1 = tk.Radiobutton(source_frame, text="Git Clone", variable=source_var, value="git")
    rb2 = tk.Radiobutton(source_frame, text="Local Copy", variable=source_var, value="copy")
    rb1.grid(row=0, column=0, padx=5, pady=5)
    rb2.grid(row=0, column=1, padx=5, pady=5)

    # Git repo URL (shown only if "git" is chosen)
    repo_url_var = tk.StringVar(value=defaults["repo_url"])
    repo_label = tk.Label(source_frame, text="Git Repo URL")
    repo_entry = tk.Entry(source_frame, textvariable=repo_url_var, width=40)

    # Local path entry (shown only if "copy" is chosen)
    lp_var = tk.StringVar(value=defaults["local_path"])
    lp_label = tk.Label(source_frame, text="Local Path")
    lp_entry = tk.Entry(source_frame, textvariable=lp_var, width=40)

    def on_source_var_change(*_):
        if source_var.get() == "git":
            repo_label.grid(row=1, column=0, sticky="e", padx=5, pady=5)
            repo_entry.grid(row=1, column=1, padx=5, pady=5)
            lp_label.grid_remove()
            lp_entry.grid_remove()
        else:
            repo_label.grid_remove()
            repo_entry.grid_remove()
            lp_label.grid(row=1, column=0, sticky="e", padx=5, pady=5)
            lp_entry.grid(row=1, column=1, padx=5, pady=5)

    source_var.trace_add("write", on_source_var_change)
    on_source_var_change()  # initialize

    log_text = tk.Text(root, width=80, height=15)
    log_text.grid(row=row, column=0, columnspan=2, padx=5, pady=5)
    row += 1

    # Progress bar
    progress_bar = ttk.Progressbar(root, orient='horizontal', length=400, mode='determinate')
    progress_bar.grid(row=row, column=0, columnspan=2, padx=5, pady=5)
    row += 1

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
        gui_args.subnet_type = entries["subnet_type"].get().strip()

        # Collect user-chosen components (excluding Supervisor)
        gui_args.components = []
        for k, var in component_vars.items():
            if var.get():
                gui_args.components.append(k)

        # RDS selection
        if rds_var.get() == "yes":
            gui_args.components.append("enable_rds")
            gui_args.db_identifier = db_id_var.get().strip()
            gui_args.db_username = db_user_var.get().strip()
            gui_args.db_password = db_pass_var.get()
        else:
            gui_args.db_identifier = None
            gui_args.db_username = None
            gui_args.db_password = None

        # Code source
        gui_args.source_method = source_var.get()
        if gui_args.source_method == "git":
            gui_args.repo_url = repo_url_var.get().strip()
            gui_args.local_path = None
        else:
            gui_args.repo_url = None
            gui_args.local_path = lp_var.get().strip()

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
    btn_deploy.grid(row=row, column=0, pady=10, sticky="e")

    btn_signout = ttk.Button(root, text="Sign Out", command=on_sign_out)
    btn_signout.grid(row=row, column=1, pady=10, sticky="w")

    root.mainloop()