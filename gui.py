import tkinter as tk
import argparse

from .aws_cli_utils import check_aws_cli_credentials, sign_out_aws_credentials
from .deploy import deploy
from .constants import DEFAULT_REGION

def launch_gui():
    """
    Minimal tkinter GUI that simply collects input fields and then closes.
    All logs and prompts happen in the terminal.
    """
    root = tk.Tk()
    root.title("AWS Deployment Tool")

    # Check credentials once at start
    creds_ok, result_str = check_aws_cli_credentials()
    acct_label = tk.Label(root, text="", fg="blue")
    acct_label.grid(row=0, column=0, columnspan=2, padx=5, pady=5)

    if creds_ok:
        acct_label.config(text=f"Signed in as account {result_str}")
    else:
        acct_label.config(text=result_str.strip(), fg="red")

    # Default values
    defaults = {
        "aws_region": DEFAULT_REGION,
        "ec2_name": "mauibuilder",
        "key_name": "mauibuilder_keypair",
        "domain": "mauibuilder.ai",
        "local_path": "/Users/jacobvanalmelo/code/mauibuilder",
        "repo_url": "https://github.com/youruser/yourrepo.git",
        "db_identifier": "myDB",
        "db_username": "admin",
        "db_password": "MyDbPassword123",
    }

    labels = {
        "aws_region": "AWS Region",
        "ec2_name":  "EC2 Name",
        "key_name":  "Key Pair Name",
        "domain":    "Domain Name",
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

    # Checkboxes for optional components
    component_frame = tk.LabelFrame(root, text="Components")
    component_frame.grid(row=row, column=0, columnspan=2, padx=5, pady=5, sticky="ew")
    row += 1

    component_vars = {}
    comp_defs = [
        ("Compile Python from source", "python_source"),
        ("Obtain SSL via Certbot", "certbot"),
    ]
    for idx, (label_text, key) in enumerate(comp_defs):
        var = tk.BooleanVar(value=False)
        cb = tk.Checkbutton(component_frame, text=label_text, variable=var)
        cb.grid(row=0, column=idx, padx=5, pady=5)
        component_vars[key] = var

    # RDS radio
    rds_frame = tk.LabelFrame(root, text="RDS Option")
    rds_frame.grid(row=row, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
    row += 1

    rds_var = tk.StringVar(value="no")
    r1 = tk.Radiobutton(rds_frame, text="No RDS", variable=rds_var, value="no")
    r2 = tk.Radiobutton(rds_frame, text="Yes RDS", variable=rds_var, value="yes")
    r1.grid(row=0, column=0, padx=5, pady=5)
    r2.grid(row=0, column=1, padx=5, pady=5)

    db_id_var = tk.StringVar(value=defaults["db_identifier"])
    db_user_var = tk.StringVar(value=defaults["db_username"])
    db_pass_var = tk.StringVar(value=defaults["db_password"])

    db_id_label = tk.Label(rds_frame, text="RDS DB Identifier")
    db_id_entry = tk.Entry(rds_frame, textvariable=db_id_var, width=25)
    db_user_label = tk.Label(rds_frame, text="RDS Username")
    db_user_entry = tk.Entry(rds_frame, textvariable=db_user_var, width=25)
    db_pass_label = tk.Label(rds_frame, text="RDS Password")
    db_pass_entry = tk.Entry(rds_frame, textvariable=db_pass_var, width=25, show="*")

    def on_rds_change(*_):
        if rds_var.get() == "yes":
            db_id_label.grid(row=1, column=0, padx=5, pady=2, sticky="e")
            db_id_entry.grid(row=1, column=1, padx=5, pady=2)
            db_user_label.grid(row=2, column=0, padx=5, pady=2, sticky="e")
            db_user_entry.grid(row=2, column=1, padx=5, pady=2)
            db_pass_label.grid(row=3, column=0, padx=5, pady=2, sticky="e")
            db_pass_entry.grid(row=3, column=1, padx=5, pady=2)
        else:
            db_id_label.grid_remove()
            db_id_entry.grid_remove()
            db_user_label.grid_remove()
            db_user_entry.grid_remove()
            db_pass_label.grid_remove()
            db_pass_entry.grid_remove()

    rds_var.trace_add("write", on_rds_change)
    on_rds_change()

    # Source frame
    source_frame = tk.LabelFrame(root, text="Code Source")
    source_frame.grid(row=row, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
    row += 1

    source_var = tk.StringVar(value="copy")
    rb_git = tk.Radiobutton(source_frame, text="Git Clone", variable=source_var, value="git")
    rb_copy = tk.Radiobutton(source_frame, text="Local Copy", variable=source_var, value="copy")
    rb_git.grid(row=0, column=0, padx=5, pady=5)
    rb_copy.grid(row=0, column=1, padx=5, pady=5)

    repo_var = tk.StringVar(value=defaults["repo_url"])
    local_var = tk.StringVar(value=defaults["local_path"])

    repo_label = tk.Label(source_frame, text="Git Repo URL")
    repo_entry = tk.Entry(source_frame, textvariable=repo_var, width=40)

    local_label = tk.Label(source_frame, text="Local Path")
    local_entry = tk.Entry(source_frame, textvariable=local_var, width=40)

    def on_source_change(*_):
        if source_var.get() == "git":
            repo_label.grid(row=1, column=0, sticky="e", padx=5, pady=2)
            repo_entry.grid(row=1, column=1, padx=5, pady=2)
            local_label.grid_remove()
            local_entry.grid_remove()
        else:
            repo_label.grid_remove()
            repo_entry.grid_remove()
            local_label.grid(row=1, column=0, sticky="e", padx=5, pady=2)
            local_entry.grid(row=1, column=1, padx=5, pady=2)

    source_var.trace_add("write", on_source_change)
    on_source_change()

    def on_deploy():
        """
        Gather all fields, close the GUI, then run deployment in the terminal.
        """
        if not creds_ok:
            print("[ERROR] AWS CLI not ready or credentials missing.")
            root.destroy()
            return

        gui_args = argparse.Namespace()
        gui_args.aws_region = entries["aws_region"].get().strip()
        gui_args.ec2_name = entries["ec2_name"].get().strip()
        gui_args.key_name = entries["key_name"].get().strip()
        gui_args.domain = entries["domain"].get().strip()

        # Which components (compile Python, certbot, etc)
        gui_args.components = []
        for k, var in component_vars.items():
            if var.get():
                gui_args.components.append(k)

        # RDS
        if rds_var.get() == "yes":
            gui_args.db_identifier = db_id_var.get().strip()
            gui_args.db_username = db_user_var.get().strip()
            gui_args.db_password = db_pass_var.get()
        else:
            gui_args.db_identifier = None
            gui_args.db_username = None
            gui_args.db_password = None

        # Source
        gui_args.source_method = source_var.get()
        if source_var.get() == "git":
            gui_args.repo_url = repo_var.get().strip()
            gui_args.local_path = None
        else:
            gui_args.repo_url = None
            gui_args.local_path = local_var.get().strip()

        # Close GUI immediately
        root.destroy()

        # All logs and prompts happen in the terminal:
        deploy(gui_args)

    btn_deploy = tk.Button(root, text="Deploy", command=on_deploy)
    btn_deploy.grid(row=row, column=0, pady=10, sticky="e")

    def on_sign_out():
        sign_out_aws_credentials()
        acct_label.config(
            text="Signed out (credentials cleared). Re-run 'aws configure' to sign in again.",
            fg="red",
        )

    btn_signout = tk.Button(root, text="Sign Out", command=on_sign_out)
    btn_signout.grid(row=row, column=1, pady=10, sticky="w")

    root.mainloop()
