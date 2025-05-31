import argparse
import tkinter as tk

from .aws_cli_utils import check_aws_cli_credentials, sign_out_aws_credentials
from .constants import DEFAULT_REGION
from .deploy import deploy


def launch_gui():
    """
    Minimal tkinter GUI to collect input fields, then runs deploy().
    All logs/prompts happen in the terminal.
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
        "ec2_name": "my_ec2",
        "key_name": "my_keypair",
        "domain": "example.com",
        "local_path": "/path/to/local/code",
        "repo_url": "https://github.com/youruser/yourrepo.git",
    }

    labels = {
        "aws_region": "AWS Region",
        "ec2_name": "EC2 Name",
        "key_name": "Key Pair Name",
        "domain": "Domain Name",
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

    # Certbot checkbox
    component_frame = tk.LabelFrame(root, text="Components")
    component_frame.grid(row=row, column=0, columnspan=2, padx=5, pady=5, sticky="ew")
    row += 1

    certbot_var = tk.BooleanVar(value=False)
    cb_certbot = tk.Checkbutton(
        component_frame, text="Obtain SSL via Certbot", variable=certbot_var
    )
    cb_certbot.grid(row=0, column=0, padx=5, pady=5)

    # Source frame: Git or local copy
    source_frame = tk.LabelFrame(root, text="Code Source")
    source_frame.grid(row=row, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
    row += 1

    source_var = tk.StringVar(value="copy")
    rb_git = tk.Radiobutton(
        source_frame, text="Git Clone", variable=source_var, value="git"
    )
    rb_copy = tk.Radiobutton(
        source_frame, text="Local Copy", variable=source_var, value="copy"
    )
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
        if not creds_ok:
            print("[ERROR] AWS CLI not ready or credentials missing.")
            root.destroy()
            return

        gui_args = argparse.Namespace()
        gui_args.aws_region = entries["aws_region"].get().strip()
        gui_args.ec2_name = entries["ec2_name"].get().strip()
        gui_args.key_name = entries["key_name"].get().strip()
        gui_args.domain = entries["domain"].get().strip()

        # Which components (certbot or not)
        gui_args.components = []
        if certbot_var.get():
            gui_args.components.append("certbot")

        # Source
        gui_args.source_method = source_var.get()
        if source_var.get() == "git":
            gui_args.repo_url = repo_var.get().strip()
            gui_args.local_path = None
        else:
            gui_args.repo_url = None
            gui_args.local_path = local_var.get().strip()

        # Close GUI
        root.destroy()
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
