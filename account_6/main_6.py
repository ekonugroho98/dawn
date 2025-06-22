# main_6.py
import asyncio
import sys
import os

# Tambahkan direktori parent ke sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core_keep_alive import run_keep_alive

if __name__ == "__main__":
    config_file = "app/config_6.json"
    log_error_file = "log-error.txt"
    
    try:
        asyncio.run(run_keep_alive(config_file, log_error_file))
    except KeyboardInterrupt:
        print("Script stopped by user.")
    except Exception as e:
        print(f"Unexpected error: {e}")
    