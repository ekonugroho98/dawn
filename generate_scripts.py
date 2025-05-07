# generate_scripts.py
import os
import glob
import json
import shutil

def create_account_structure(config_file):
    # Extract account number from config file (e.g., config_2.json -> account_2)
    base_name = os.path.basename(config_file)
    if base_name == "config_4.json":
        account_name = "account_4"
    else:
        account_number = base_name.replace("config_", "").replace(".json", "")
        account_name = f"account_{account_number}"

    # Define paths
    account_dir = os.path.join(os.getcwd(), account_name)
    point_dir = os.path.join(account_dir, "point")
    captcha_dir = os.path.join(account_dir, "captcha")
    log_error_file = os.path.join(account_dir, "log-error.txt")
    captcha_errors_file = os.path.join(account_dir, "captcha_errors.txt")
    total_point_file = os.path.join(account_dir, "total_point.txt")
    not_referral_file = os.path.join(account_dir, "not_referral.txt")
    account_script = os.path.join(account_dir, f"{account_name}.py")
    main_script = os.path.join(account_dir, f"main_{account_name.split('_')[1]}.py")

    # Create directories
    os.makedirs(account_dir, exist_ok=True)
    os.makedirs(point_dir, exist_ok=True)
    os.makedirs(captcha_dir, exist_ok=True)

    # Create empty log files if they don't exist
    for log_file in [log_error_file, captcha_errors_file, total_point_file, not_referral_file]:
        if not os.path.exists(log_file):
            with open(log_file, "w") as f:
                pass

    # Generate account_*.py script (for core_get_point.py)
    account_script_content = f"""# {account_name}.py
import asyncio
import sys
import os

# Tambahkan direktori parent ke sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core_get_point import run_get_points

if __name__ == "__main__":
    config_file = "/app/{base_name}"
    point_log_dir = "point"
    log_error_file = "log-error.txt"
    total_point_log = "total_point.txt"
    not_referral_log = "not_referral.txt"
    
    try:
        asyncio.run(run_get_points(config_file, point_log_dir, log_error_file, total_point_log, not_referral_log))
    except KeyboardInterrupt:
        print("Script stopped by user.")
    except Exception as e:
        print(f"Unexpected error: {{e}}")
    """

    with open(account_script, "w") as f:
        f.write(account_script_content)

    # Generate main_*.py script (for core_keep_alive.py)
    main_script_content = f"""# main_{account_name.split('_')[1]}.py
import asyncio
import sys
import os

# Tambahkan direktori parent ke sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core_keep_alive import run_keep_alive

if __name__ == "__main__":
    config_file = "../{base_name}"
    log_error_file = "log-error.txt"
    
    try:
        asyncio.run(run_keep_alive(config_file, log_error_file))
    except KeyboardInterrupt:
        print("Script stopped by user.")
    except Exception as e:
        print(f"Unexpected error: {{e}}")
    """

    with open(main_script, "w") as f:
        f.write(main_script_content)

    print(f"Generated structure for {account_name}")

def main():
    # Find all config*.json files
    config_files = glob.glob("config*.json")
    
    if not config_files:
        print("No config files found.")
        return

    for config_file in config_files:
        create_account_structure(config_file)

if __name__ == "__main__":
    main()