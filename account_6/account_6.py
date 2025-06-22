# account_6.py
import asyncio
import sys
import os

# Tambahkan direktori parent ke sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core_get_point import run_get_points

if __name__ == "__main__":
    config_file = "/app/config_6.json"
    point_log_dir = "point"
    log_error_file = "log-error.txt"
    total_point_log = "total_point.txt"
    not_referral_log = "not_referral.txt"
    
    try:
        asyncio.run(run_get_points(config_file, point_log_dir, log_error_file, total_point_log, not_referral_log))
    except KeyboardInterrupt:
        print("Script stopped by user.")
    except Exception as e:
        print(f"Unexpected error: {e}")
    