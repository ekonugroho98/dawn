# core_get_point.py
import requests
import json
import logging
import time
import asyncio
import telegram
from urllib.parse import urlparse
import colorlog
import urllib3
from asyncio import Queue
# from multiprocessing import Pool  # Removed - using synchronous processing
from datetime import datetime
from fake_useragent import UserAgent
import base64
from anticaptchaofficial.imagecaptcha import *
import os
from itertools import islice
from filelock import FileLock

# Nonaktifkan Warning SSL dari urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Nonaktifkan log warning dari urllib3 jika masih muncul
logging.getLogger("urllib3").setLevel(logging.CRITICAL)
logging.getLogger("urllib3").propagate = False


# Initialize UserAgent for random User-Agent generation
ua = UserAgent()

# Setup logging with color
log_colors = {
    'DEBUG': 'cyan',
    'INFO': 'white',
    'WARNING': 'yellow',
    'ERROR': 'red',
    'SUCCESS': 'green'
}

formatter = colorlog.ColoredFormatter(
    "%(log_color)s%(asctime)s - %(levelname)s - %(message)s",
    log_colors=log_colors
)

handler = logging.StreamHandler()
handler.setFormatter(formatter)

logger = logging.getLogger()
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Adding a custom SUCCESS level
SUCCESS_LEVEL = 25
logging.addLevelName(SUCCESS_LEVEL, "SUCCESS")

def read_last_points(last_points_file):
    import json
    lock = FileLock(f"{last_points_file}.lock")
    try:
        with lock:
            with open(last_points_file, "r") as f:
                return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def write_last_points(last_points_file, last_points_data):
    import json
    lock = FileLock(f"{last_points_file}.lock")
    try:
        with lock:
            with open(last_points_file, "w") as f:
                json.dump(last_points_data, f, indent=2)
    except Exception as e:
        import logging
        logging.error(f"Failed to write last_points file: {e}")
        
def log_success(message, *args, **kwargs):
    if logger.isEnabledFor(SUCCESS_LEVEL):
        logger._log(SUCCESS_LEVEL, message, args, **kwargs)

logging.success = log_success

def read_config(config_file):
    try:
        with open(config_file, 'r') as file:
            config = json.load(file)
        return config
    except FileNotFoundError:
        logging.error(f"Configuration file '{config_file}' not found.")
        return {}
    except json.JSONDecodeError:
        logging.error(f"Invalid JSON format in '{config_file}'.")
        return {}

def update_config_with_token(login_response, config_data, email, config_file, is_failed_login=None):
    logging.info(f"Attempting to update token for {email}")

    try:
        # Always read the latest config data
        try:
            with open(config_file, 'r') as f:
                config_data = json.load(f)
            logging.info(f"Successfully read config file for {email}")
        except Exception as e:
            logging.error(f"Failed to read config file for {email}: {e}")
            return config_data

        if "accounts" not in config_data:
            config_data["accounts"] = []
            logging.info(f"Created accounts list for {email}")

        updated = False
        for account in config_data["accounts"]:
            if account.get("email") == email:
                if login_response and login_response.get("status"):
                    token = login_response["data"].get("token")
                    if token:
                        old_token = account.get("token", "")
                        account["token"] = token
                        # Set is_login_failed to false when token is successfully updated
                        account["is_login_failed"] = False
                        logging.info(f"Token updated for {email}. Old token: {old_token[:20]}... New token: {token[:20]}...")
                else:
                    account["token"] = ""  # Kosongkan token jika login gagal
                    if is_failed_login is not None:
                        account["is_login_failed"] = is_failed_login
                    logging.info(f"Token cleared for {email} due to failed login")
                updated = True
                break

        if updated:
            try:
                with open(config_file, "w") as f:
                    json.dump(config_data, f, indent=2)
                logging.info(f"Config file successfully updated for {email}")
            except Exception as e:
                logging.error(f"Failed to write config file for {email}: {e}")
        else:
            logging.warning(f"Account {email} not found in config file")

    except Exception as e:
        logging.error(f"Error in update_config_with_token for {email}: {e}")

    return config_data

def update_config_with_success(email, config_data, config_file):
    if "accounts" not in config_data:
        config_data["accounts"] = []

    updated = False
    for account in config_data["accounts"]:
        if account["email"] == email:
            account["last_success"] = datetime.now().isoformat()
            updated = True
            break

    if updated:
        try:
            with open(config_file, "w") as f:
                json.dump(config_data, f, indent=2)
            logging.info(f"Last success timestamp updated for {email}")
        except Exception as e:
            logging.error(f"Failed to update config for {email}: {e}")
    else:
        logging.warning(f"Last success not updated for {email}, account not found.")

def log_total_points(total_points, successful_accounts, total_accounts, total_point_log):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} - Cycle Total Points: {total_points} - Successful Accounts: {successful_accounts}/{total_accounts}\n"
    try:
        with open(total_point_log, "a") as f:
            f.write(log_entry)
        logging.info(f"Logged total points ({total_points}) to {total_point_log}")
    except Exception as e:
        logging.error(f"Failed to log total points to {total_point_log}: {e}")

def log_not_referred(email, referred_by, not_referral_log):
            logging.error(f"Failed to log not referred to {not_referral_log} for {email}, referredBy: {referred_by}")

def parse_proxy(proxy):
    proxy_url = urlparse(proxy)
    if proxy_url.scheme in ['http', 'https', 'socks5']:
        if proxy_url.username and proxy_url.password:
            return {
                'http': f"{proxy_url.scheme}://{proxy_url.username}:{proxy_url.password}@{proxy_url.hostname}:{proxy_url.port}",
                'https': f"{proxy_url.scheme}://{proxy_url.username}:{proxy_url.password}@{proxy_url.hostname}:{proxy_url.port}",
            }
        else:
            return {
                'http': f"{proxy_url.scheme}://{proxy_url.hostname}:{proxy_url.port}",
                'https': f"{proxy_url.scheme}://{proxy_url.hostname}:{proxy_url.port}",
            }
    return {}

def check_proxy(proxy):
    proxies = parse_proxy(proxy)
    test_url = "http://httpbin.org/ip"
    try:
        response = requests.get(test_url, proxies=proxies, timeout=30)
        return response.status_code == 200
    except requests.RequestException:
        return False

def create_session(proxy=None):
    session = requests.Session()
    session.verify = False 
    if proxy:
        proxies = parse_proxy(proxy)
        logging.info(f"Configuring session with proxy: {proxy}")
        session.proxies.update(proxies)
    return session

def log_points(email, points, status_message, point_log_dir):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} - Points: {points} - Status: {status_message}"
    logging.info(f"Points for {email}: {log_entry}")

def get_puzzle_id(session, appid):
    url = f"https://ext-api.dawninternet.com/chromeapi/dawn/v1/puzzle/get-puzzle?appid={appid}"
    headers_base = {
        'accept': '*/*',
        'accept-language': 'en-US,en;q=0.9',
        'origin': 'chrome-extension://fpdkjdnhkakefebpekbdhillbhonfjjp',
        'priority': 'u=1, i',
        'sec-ch-ua': '"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"macOS"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'cross-site',
        'User-Agent': ua.random
    }
    try:
        response = session.get(url, headers=headers_base)
        response.raise_for_status()
        data = response.json()
        if data.get("success") and "puzzle_id" in data:
            return data["puzzle_id"]
        logging.error(f"Failed to get puzzle_id for appid {appid}: {data}")
        return None
    except requests.RequestException as e:
        logging.error(f"Error requesting puzzle_id for appid {appid}: {e}")
        return None

def get_captcha_image(session, puzzle_id, appid, email, captcha_dir):
    safe_email = email.replace('@', '_').replace('.', '_')
    output_file = os.path.join(captcha_dir, f"{safe_email}.png")
    url = f"https://ext-api.dawninternet.com/chromeapi/dawn/v1/puzzle/get-puzzle-image?puzzle_id={puzzle_id}&appid={appid}"
    headers_base = {
        'accept': '*/*',
        'accept-language': 'en-US,en;q=0.9',
        'origin': 'chrome-extension://fpdkjdnhkakefebpekbdhillbhonfjjp',
        'priority': 'u=1, i',
        'sec-ch-ua': '"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"macOS"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'cross-site',
        'User-Agent': ua.random
    }
    try:
        response = session.get(url, headers=headers_base)
        response.raise_for_status()
        data = response.json()
        if data.get("success") and "imgBase64" in data:
            with open(output_file, "wb") as f:
                f.write(base64.b64decode(data["imgBase64"]))
            logging.info(f"Captcha image saved as '{output_file}' for {email}")
            return output_file
        logging.error(f"Failed to get captcha image for {email}: {data}")
        return None
    except requests.RequestException as e:
        logging.error(f"Error requesting captcha image for {email}: {e}")
        return None

def solve_captcha(image_path):
    solver = imagecaptcha()
    solver.set_verbose(1)
    
    # Get API key from environment variable
    api_key = os.getenv("ANTICAPTCHA_API_KEY")
    if not api_key:
        logging.error("ANTICAPTCHA_API_KEY environment variable not set")
        return None
    
    solver.set_key(api_key)
    solver.set_soft_id(0)
    captcha_text = solver.solve_and_return_solution(image_path)
    if captcha_text:
        logging.info(f"Captcha solved for {image_path}: {captcha_text}")
        return captcha_text
    logging.error(f"Captcha solving failed for {image_path}: {solver.error_code}")
    return None

def perform_login(session, puzzle_id, captcha_solution, email, password, appid):
    url = f"https://ext-api.dawninternet.com/chromeapi/dawn/v1/user/login/v2?appid={appid}"
    headers_login = {
        'accept': '*/*',
        'accept-language': 'en-US,en;q=0.9',
        'content-type': 'application/json',
        'origin': 'chrome-extension://fpdkjdnhkakefebpekbdhillbhonfjjp',
        'priority': 'u=1, i',
        'sec-ch-ua': '"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"macOS"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'cross-site',
        'User-Agent': ua.random
    }
    payload = {
        "username": email,
        "password": password,
        "logindata": {
            "_v": {"version": "1.1.4"},
            "datetime": datetime.utcnow().isoformat() + "Z"
        },
        "puzzle_id": puzzle_id,
        "ans": captcha_solution,
        "appid": appid
    }
    try:
        response = session.post(url, headers=headers_login, data=json.dumps(payload))
        response.raise_for_status()
        data = response.json()
        logging.info(f"Login response for {email}: {json.dumps(data, indent=2)}")
        return data
    except requests.RequestException as e:
        error_details = {
            "exception": str(e),
            "status_code": getattr(e.response, "status_code", "No response"),
            "content": getattr(e.response, "text", "No content") if hasattr(e, "response") else "No response"
        }
        logging.error(f"Login error for {email}: {json.dumps(error_details, indent=2)}")
        return error_details

def re_login(email, password, appid, proxy=None, config_file=None, max_retries=10):
    session = None
    captcha_file = None
    try:
        session = create_session(proxy)
        for attempt in range(max_retries):
            try:
                logging.info(f"Captcha attempt {attempt + 1}/{max_retries} for {email}")
                
                puzzle_id = get_puzzle_id(session, appid)
                if not puzzle_id:
                    logging.error(f"Failed to get puzzle_id for {email} (attempt {attempt + 1})")
                    time.sleep(5)
                    continue

                captcha_file = get_captcha_image(session, puzzle_id, appid, email, os.path.dirname(config_file))
                if not captcha_file:
                    logging.error(f"Failed to get captcha image for {email} (attempt {attempt + 1})")
                    time.sleep(5)
                    continue

                captcha_solution = solve_captcha(captcha_file)
                if not captcha_solution:
                    logging.error(f"Failed to solve captcha for {email} (attempt {attempt + 1})")
                    time.sleep(5)
                    continue

                login_response = perform_login(session, puzzle_id, captcha_solution, email, password, appid)
                if login_response and login_response.get("status"):
                    logging.info(f"Re-login successful for {email} after {attempt + 1} attempts")
                    log_activity_to_file(email, "RE-LOGIN_SUCCESS", f"Re-login successful with proxy {proxy if proxy else 'No proxy'} after {attempt + 1} attempts")

                    # Selalu gunakan update_config_with_token untuk menyimpan token
                    config_data = read_config(config_file)
                    update_config_with_token(login_response, config_data, email, config_file, is_failed_login=False)
                    
                    # Update last_success timestamp after successful re-login
                    config_data = read_config(config_file)
                    update_config_with_success(email, config_data, config_file)
                    
                    # Verifikasi token telah diupdate
                    config_data = read_config(config_file)
                    for account in config_data.get("accounts", []):
                        if account.get("email") == email:
                            new_token = account.get("token", "")
                            if new_token:
                                logging.info(f"Token successfully updated in config for {email}")
                                return new_token
                            else:
                                logging.error(f"Token not found in config after update for {email}")
                    
                    logging.error(f"Account not found in config after update for {email}")
                    return None

                logging.error(f"Re-login failed for {email}: {login_response}")
                log_activity_to_file(email, "RE-LOGIN_FAILED", f"Re-login failed: {login_response}")
                time.sleep(5)

            except Exception as e:
                logging.error(f"Error during re-login attempt {attempt + 1} for {email}: {str(e)}")
                time.sleep(5)

        # Jika semua retry gagal
        logging.error(f"Re-login failed for {email} after {max_retries} captcha attempts")
        log_activity_to_file(email, "RE-LOGIN_FAILED_ALL_ATTEMPTS", f"Re-login failed after {max_retries} captcha attempts")
        config_data = read_config(config_file)
        update_config_with_token(None, config_data, email, config_file, is_failed_login=True)
        return None

    finally:
        if session:
            session.close()
        if captcha_file and os.path.exists(captcha_file):
            try:
                os.remove(captcha_file)
                logging.info(f"Captcha file '{captcha_file}' deleted.")
            except Exception as e:
                logging.warning(f"Failed to delete captcha file '{captcha_file}': {e}")

def log_to_file(filename, message):
    with open(filename, "a") as f:
        f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")

def log_activity_to_file(email, activity, details, log_file="log.txt"):
    """Log all activities to log.txt file"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {activity} - {email} - {details}\n"
    try:
        with open(log_file, "a") as f:
            f.write(log_entry)
    except Exception as e:
        logging.error(f"Failed to write to {log_file}: {e}")

def get_account_name_from_config(config_file):
    """Extract account name from config file path"""
    config_name = os.path.basename(config_file)
    if config_name == "config.json":
        return "account_1"
    elif config_name.startswith("config_") and config_name.endswith(".json"):
        account_number = config_name.replace("config_", "").replace(".json", "")
        return f"account_{account_number}"
    else:
        return "unknown_account"

def generate_points_summary(results, config_file, point_log_dir):
    """Generate points summary for the current account group"""
    account_name = get_account_name_from_config(config_file)
    last_points_file = os.path.join(point_log_dir, "last_points.json")
    last_points_data = read_last_points(last_points_file)
    
    successful_accounts = 0
    failed_accounts = 0
    total_points = 0
    account_details = []
    
    for email_result, success, message, _, _ in results:
        points = last_points_data.get(email_result, 0)  # Always get points from last_points
        if success:
            successful_accounts += 1
            total_points += points
            status_emoji = "✅"
        else:
            failed_accounts += 1
            status_emoji = "❌"
            
        account_details.append({
            "email": email_result,
            "points": points,
            "status": status_emoji,
            "success": success
        })
    
    # Sort by points descending
    account_details.sort(key=lambda x: x["points"], reverse=True)
    
    # Create summary message
    summary_message = f"📊 *{account_name.upper()} CYCLE SUMMARY* 📊\n\n"
    summary_message += f"🎯 *Total Accounts:* {len(results)}\n"
    summary_message += f"✅ *Successful:* {successful_accounts}\n"
    summary_message += f"❌ *Failed:* {failed_accounts}\n"
    summary_message += f"💰 *Total Points:* {total_points:,}\n"
    summary_message += f"📈 *Success Rate:* {(successful_accounts/len(results)*100):.1f}%\n\n"
    
    summary_message += "*📋 TOP ACCOUNTS:*\n"
    for i, account in enumerate(account_details[:8], 1):  # Show top 8 accounts
        # Truncate email for better display
        display_email = account['email'][:20] + "..." if len(account['email']) > 23 else account['email']
        summary_message += f"{i}. {account['status']} `{display_email}` - {account['points']:,} pts\n"
    
    if len(account_details) > 8:
        summary_message += f"... and {len(account_details) - 8} more accounts\n"
    
    summary_message += f"\n⏰ *Completed:* {datetime.now().strftime('%H:%M:%S')}"
    
    return summary_message

def total_points(headers, session, appid, email, password, proxy, config_file, point_log_dir):
    referral_message = None
    url = f"https://ext-api.dawninternet.com/api/atom/v1/userreferral/getpoint?appid={appid}"
    try:
        response = session.get(url, headers=headers, verify=False, timeout=30)
        response.raise_for_status()

        json_response = response.json()
        if json_response.get("status") or json_response.get("success"):
            reward_point_data = json_response["data"]["rewardPoint"]
            referral_point_data = json_response["data"]["referralPoint"]
            points = (
                reward_point_data.get("points", 0) +
                reward_point_data.get("registerpoints", 0) +
                reward_point_data.get("signinpoints", 0) +
                reward_point_data.get("twitter_x_id_points", 0) +
                reward_point_data.get("discordid_points", 0) +
                reward_point_data.get("telegramid_points", 0) +
                reward_point_data.get("bonus_points", 0) +
                referral_point_data.get("commission", 0)
            )
            
            # Cek referral
            if referral_point_data.get("referredBy", 0) not in ["4j1r2lic", "ero8ii2k", "p3g4fq15", "c5fovgjs"]:
                log_not_referred(email, referral_point_data.get("referredBy", 0), "")
                referral_message = f"⚠️ *Invalid Referral Alert* ⚠️\n\n👤 Account: {email}\n❌ Invalid Referral: {referral_point_data.get('referredBy', 0)}"
            
            log_points(email, points, "Points retrieved successfully", point_log_dir)
            return True, points, "Points retrieved successfully", referral_message
        else:
            message = json_response.get("message", "Unknown error")
            if message == "Your app session expired, Please login again.":
                logging.info(f"Session expired for {email}. Attempting re-login")
                new_token = re_login(email, password, appid, proxy, config_file)
                if new_token:
                    headers["Authorization"] = f"Bearer {new_token}"
                    return True, 0, "Session expired, re-login successful", referral_message
                return False, 0, "Session expired, re-login failed", referral_message
            return False, 0, f"API status false: {message}", referral_message
    except requests.exceptions.RequestException as e:
        error_message = str(e)
        if hasattr(e, 'response') and e.response is not None:
            try:
                json_response = e.response.json()
                message = json_response.get("message", error_message)
                if message == "Your app session expired, Please login again.":
                    logging.info(f"Session expired for {email}. Attempting re-login")
                    new_token = re_login(email, password, appid, proxy, config_file)
                    if new_token:
                        headers["Authorization"] = f"Bearer {new_token}"
                        return True, 0, "Session expired, re-login successful", referral_message
                    return False, 0, "Session expired, re-login failed", referral_message
            except (ValueError, json.JSONDecodeError):
                message = error_message
        else:
            message = error_message
        return False, 0, f"Request error: {message}", referral_message
    except Exception as e:
        return False, 0, f"Unexpected error: {str(e)}", referral_message

def log_curl_to_file(email, headers, url, payload, proxy, reason, log_error_file, response_content=None):
    curl_command = f"curl"
    if proxy:
        curl_command += f" --proxy '{proxy}'"
    curl_command += f" '{url}'"
    for key, value in headers.items():
        curl_command += f" -H '{key}: {value}'"
    if payload:
        curl_command += f" --data-raw '{json.dumps(payload)}'"

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = (
        f"[{timestamp}] Error for {email}\n"
        f"Reason: {reason}\n"
        f"cURL Command: {curl_command}\n"
    )
    if response_content:
        log_entry += f"Response Content: {response_content}\n"
    log_entry += f"---------------------------------------\n"

    with open(log_error_file, "a") as f:
        f.write(log_entry)

# Queue for Telegram messages
message_queue = asyncio.Queue()

async def telegram_message(bot_token, chat_id, message):
    if bot_token and chat_id:
        try:
            logging.info(f"Attempting to send Telegram message to chat {chat_id}")
            bot = telegram.Bot(token=bot_token)
            await bot.send_message(chat_id=chat_id, text=message, parse_mode="Markdown")
            logging.info(f"Successfully sent Telegram message: {message[:100]}...")
            log_activity_to_file("TELEGRAM", "MESSAGE_SENT", f"Message sent to chat {chat_id}: {message[:50]}...")
            await asyncio.sleep(1)
        except Exception as e:
            logging.error(f"Error sending Telegram message: {str(e)}")
            logging.error(f"Bot token: {bot_token[:10]}...")
            logging.error(f"Chat ID: {chat_id}")
            logging.error(f"Message: {message[:100]}...")

async def telegram_worker(bot_token, chat_id):
    global message_queue
    logging.info(f"Starting Telegram worker with chat ID: {chat_id}")
    while True:
        try:
            message = await message_queue.get()
            if message:  # Only send if message is not None
                logging.info(f"Processing message from queue: {message[:100]}...")
                if isinstance(message, list):
                    for msg in message:
                        await telegram_message(bot_token, chat_id, msg)
                else:
                    await telegram_message(bot_token, chat_id, message)
            message_queue.task_done()
        except Exception as e:
            logging.error(f"Error in telegram worker: {str(e)}")
            await asyncio.sleep(1)

def should_process_account(account, success_delay):
    return True

def process_get_points(account, config_file, point_log_dir, log_error_file, total_point_log, not_referral_log, use_proxy, bot_token=None, chat_id=None, max_retries=3, retry_delay=5, success_delay=86400):
    email = account["email"]
    token = account.get("token")
    appid = account["appid"]
    password = account.get("password")
    proxy = account.get("proxy") if use_proxy else None
    last_points_file = os.path.join(point_log_dir, "last_points.json")

    # Get source account from config file name
    source_account = os.path.basename(config_file).replace("config_", "").replace(".json", "")

    session = None
    try:
        session = create_session(proxy)
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

        if not token:
            logging.warning(f"No valid token for {email}. Attempting re-login...")
            new_token = re_login(email, password, appid, proxy, config_file)
            if new_token:
                token = new_token
                headers["Authorization"] = f"Bearer {new_token}"
                logging.info(f"Re-login successful for {email}, got new token")
            else:
                logging.error(f"Re-login failed for {email}. Skipping...")
                return email, False, None, bot_token, chat_id

        # Ambil last_points sebelumnya dari file
        last_points_data = read_last_points(last_points_file)
        last_points = last_points_data.get(email, 0)

        attempt = 0
        while attempt < max_retries:
            attempt += 1
            try:
                result = total_points(headers, session, appid, email, password, proxy, config_file, point_log_dir)
                if isinstance(result, tuple) and len(result) >= 2:
                    success, points, status_message, referral_message = result
                    if success and points is not None:
                        # Hitung selisih point
                        point_diff = points - last_points

                        # Update last_points untuk email ini di last_points.json
                        last_points_data[email] = points
                        write_last_points(last_points_file, last_points_data)

                        # Removed individual message creation - only summary will be sent
                        logging.success(f"Success get points for {email} with proxy {proxy if proxy else 'No proxy'}. Points: {points}")
                        log_activity_to_file(email, "GET_POINTS_SUCCESS", f"Points: {points}, Change: {point_diff:+}, Proxy: {proxy if proxy else 'No proxy'}")
                        return email, True, None, bot_token, chat_id
                    else:
                        logging.error(f"Attempt {attempt}/{max_retries}: Failed get points for {email} with proxy {proxy if proxy else 'No proxy'} and appid {appid}. Reason: {status_message}")
                        if attempt == max_retries:
                            log_activity_to_file(email, "GET_POINTS_FAILED", f"Failed after {max_retries} attempts. Reason: {status_message}")
                            return email, False, None, bot_token, chat_id
                        else:
                            logging.info(f"Retrying after {retry_delay} seconds...")
                            time.sleep(retry_delay)
                            continue
                else:
                    logging.error(f"Invalid result format from total_points for {email}")
                    if attempt == max_retries:
                        return email, False, None, bot_token, chat_id
                    else:
                        logging.info(f"Retrying after {retry_delay} seconds...")
                        time.sleep(retry_delay)
                        continue
            except Exception as e:
                logging.error(f"Attempt {attempt}/{max_retries}: Error for {email}: {str(e)}")
                if attempt == max_retries:
                    return email, False, None, bot_token, chat_id
                else:
                    logging.info(f"Retrying after {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    continue
    except Exception as e:
        logging.error(f"Error processing account {email}: {str(e)}")
        return email, False, None, bot_token, chat_id
    finally:
        if session:
            session.close()

async def run_get_points(config_file, point_log_dir, log_error_file, total_point_log, not_referral_log, get_points_interval=3600, batch_size=1):
    config = read_config(config_file)
    bot_token = config.get("telegram_bot_token")
    chat_id = config.get("telegram_chat_id")
    use_proxy = config.get("use_proxy", False)
    use_telegram = config.get("use_telegram", True)

    logging.info(f"Telegram settings - use_telegram: {use_telegram}, bot_token: {bool(bot_token)}, chat_id: {chat_id}")

    if use_telegram and (not bot_token or not chat_id):
        logging.error("Missing 'bot_token' or 'chat_id' in config.")
        return

    # Create message queue and telegram worker ONCE outside the loop
    global message_queue
    message_queue = asyncio.Queue()

    telegram_task = None
    if use_telegram:
        telegram_task = asyncio.create_task(telegram_worker(bot_token, chat_id))
        logging.info("Telegram worker task created")

    while True:
        try:
            # Read accounts fresh every cycle in case config changes
            accounts = read_config(config_file).get("accounts", [])
            logging.info(f"🚀 SYNCHRONOUS MODE: Processing {len(accounts)} accounts sequentially")
            logging.info(f"🔄 Max captcha retry per re-login: 10 attempts")
            logging.info("🔄 Starting SYNCHRONOUS processing of all accounts...")
            results = []
            
            for i, account in enumerate(accounts, 1):
                email = account.get("email", "unknown")
                logging.info(f"📋 Processing account {i}/{len(accounts)}: {email}")
                
                try:
                    result = process_get_points(
                        account, config_file, point_log_dir, log_error_file, 
                        total_point_log, not_referral_log, use_proxy, bot_token, chat_id
                    )
                    results.append(result)
                    
                    # Removed individual telegram message sending - only summary will be sent
                    email_result, success, _, _, _ = result
                    logging.info(f"✅ Account {i}/{len(accounts)} ({email_result}) completed: {'success' if success else 'failed'}")
                    
                    # Add small delay between accounts to avoid rate limiting
                    if i < len(accounts):  # Don't sleep after last account
                        logging.info("⏳ Waiting 2 seconds before next account...")
                        await asyncio.sleep(2)
                        
                except Exception as e:
                    logging.error(f"❌ Error processing account {email}: {e}")
                    results.append((email, False, None, bot_token, chat_id))
                    continue

            # Cycle summary
            successful_accounts = sum(1 for _, success, _, _, _ in results if success)
            failed_accounts = len(results) - successful_accounts
            logging.info(f"📊 CYCLE SUMMARY: {successful_accounts} successful, {failed_accounts} failed out of {len(accounts)} total accounts")
            
            # Generate and send points summary to Telegram
            if use_telegram and bot_token and chat_id:
                try:
                    account_name = get_account_name_from_config(config_file)
                    summary_message = generate_points_summary(results, config_file, point_log_dir)
                    logging.info(f"📤 Sending cycle summary to Telegram for {account_name}")
                    logging.info(f"📊 Summary contains {len(results)} accounts, {successful_accounts} successful")
                    await message_queue.put(summary_message)
                    logging.info(f"✅ Cycle summary queued for Telegram - {account_name}")
                    log_activity_to_file("CYCLE_SUMMARY", "TELEGRAM_QUEUED", f"{account_name} - {successful_accounts}/{len(results)} successful")
                except Exception as e:
                    logging.error(f"❌ Failed to generate/send cycle summary: {e}")
            
            logging.info(f"⏰ Get points cycle completed. Waiting {get_points_interval} seconds (1 hour) for next cycle.")
            await asyncio.sleep(get_points_interval)
        except Exception as e:
            logging.error(f"Error in main loop: {e}")
            await asyncio.sleep(10)
            continue

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 6:
        print("Usage: core_get_point.py <config_file> <point_log_dir> <log_error_file> <total_point_log> <not_referral_log>")
        sys.exit(1)
    asyncio.run(run_get_points(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]))