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
from multiprocessing import Pool
from datetime import datetime
from fake_useragent import UserAgent
import base64
from anticaptchaofficial.imagecaptcha import *
import os
from itertools import islice
from filelock import FileLock

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

def update_config_with_token(login_response, config_data, email, config_file):
    logging.info(f"Before update, config_data: {json.dumps(config_data, indent=2)}")
    lock = FileLock(f"{config_file}.lock")
    with lock:
        if not login_response or not login_response.get("status"):
            logging.error(f"No valid login data to update config for {email}.")
            return config_data

        token = login_response["data"]["token"]
        if "accounts" not in config_data:
            config_data["accounts"] = []

        for account in config_data["accounts"]:
            if account["email"] == email:
                account["token"] = token
                break

        try:
            with open(config_file, "w") as f:
                json.dump(config_data, f, indent=2)
            logging.info(f"Token for {email} updated in {config_file}")
        except Exception as e:
            logging.error(f"Failed to update config for {email}: {e}")
        return config_data

def update_config_with_success(email, config_data, config_file):
    lock = FileLock(f"{config_file}.lock")
    with lock:
        if "accounts" not in config_data:
            config_data["accounts"] = []

        for account in config_data["accounts"]:
            if account["email"] == email:
                account["last_success"] = datetime.now().isoformat()
                break

        try:
            with open(config_file, "w") as f:
                json.dump(config_data, f, indent=2)
            logging.info(f"Last success timestamp updated for {email}")
        except Exception as e:
            logging.error(f"Failed to update config for {email}: {e}")
        return config_data

def log_total_points(total_points, successful_accounts, total_accounts, total_point_log):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} - Cycle Total Points: {total_points} - Successful Accounts: {successful_accounts}/{total_accounts}\n"
    lock = FileLock(f"{total_point_log}.lock")
    with lock:
        try:
            with open(total_point_log, "a") as f:
                f.write(log_entry)
            logging.info(f"Logged total points ({total_points}) to {total_point_log}")
        except Exception as e:
            logging.error(f"Failed to log total points to {total_point_log}: {e}")

def log_not_referred(email, referred_by, not_referral_log):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} - Email: {email} - referredBy: {referred_by}\n"
    lock = FileLock(f"{not_referral_log}.lock")
    with lock:
        try:
            with open(not_referral_log, "a") as f:
                f.write(log_entry)
            logging.info(f"Logged non-referred email {email} with referredBy {referred_by} to {not_referral_log}")
        except Exception as e:
            logging.error(f"Failed to log to {not_referral_log} for {email}: {e}")

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
    if proxy:
        proxies = parse_proxy(proxy)
        logging.info(f"Configuring session with proxy: {proxy}")
        session.proxies.update(proxies)
    return session

def log_points(email, points, status_message, point_log_dir):
    safe_email = email.replace('@', '_').replace('.', '_')
    log_file = os.path.join(point_log_dir, f"{safe_email}.txt")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} - Points: {points} - Status: {status_message}\n"
    try:
        with open(log_file, "a") as f:
            f.write(log_entry)
        logging.info(f"Logged points for {email} to {log_file}")
    except Exception as e:
        logging.error(f"Failed to log points for {email} to {log_file}: {e}")

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
    solver.set_key("377c52bebe64c59195ad7cdfd3a994fe")  # Replace with your AntiCaptcha API key
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

def re_login(email, password, appid, proxy=None, config_file=None, max_retries=1):
    session = create_session(proxy)
    try:
        for attempt in range(max_retries):
            puzzle_id = get_puzzle_id(session, appid)
            if not puzzle_id:
                logging.error(f"Failed to get puzzle_id for {email}")
                time.sleep(5)
                continue

            captcha_file = get_captcha_image(session, puzzle_id, appid, email, os.path.dirname(config_file))
            if not captcha_file:
                logging.error(f"Failed to get captcha image for {email}")
                time.sleep(5)
                continue

            captcha_solution = solve_captcha(captcha_file)
            if not captcha_solution:
                logging.error(f"Failed to solve captcha for {email}")
                time.sleep(5)
                continue

            login_response = perform_login(session, puzzle_id, captcha_solution, email, password, appid)
            if login_response and isinstance(login_response, dict) and login_response.get("status"):
                logging.info(f"Re-login successful for {email}")
                config_data = read_config(config_file)
                update_config_with_token(login_response, config_data, email, config_file)
                return login_response["data"]["token"]
            elif login_response and isinstance(login_response, dict) and login_response.get("message") == "Incorrect answer. Try again!":
                logging.info(f"Incorrect captcha for {email}. Retry {attempt + 1}/{max_retries}")
                log_to_file(os.path.join(os.path.dirname(config_file), "captcha_errors.txt"), 
                            f"ERROR: Incorrect answer - Email: {email} | Captcha: {captcha_solution} | Proxy: {proxy if proxy else 'No Proxy'} | Retry: {attempt + 1}/{max_retries}")
                time.sleep(5)
                continue
            else:
                logging.error(f"Re-login failed for {email}: {login_response}")
                time.sleep(5)
                continue
        logging.error(f"Re-login failed for {email} after {max_retries} attempts")
        return None
    finally:
        session.close()

def log_to_file(filename, message):
    with open(filename, "a") as f:
        f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")

def total_points(headers, session, appid, email, password, proxy, config_file, point_log_dir, max_login_attempts=2):
    url = f"https://ext-api.dawninternet.com/api/atom/v1/userreferral/getpoint?appid={appid}"
    login_attempts = 0

    while login_attempts <= max_login_attempts:
        headers["User-Agent"] = ua.random
        try:
            response = session.get(url, headers=headers, verify=False, timeout=30)
            response.raise_for_status()

            json_response = response.json()
            if json_response.get("status"):
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
                log_points(email, points, "Points retrieved successfully", point_log_dir)
                config_data = read_config(config_file)
                update_config_with_success(email, config_data, config_file)
                return True, points, "Points retrieved successfully"
            else:
                message = json_response.get("message", "Unknown error")
                if message == "Your app session expired, Please login again.":
                    logging.info(f"Session expired for {email}. Attempting re-login")
                    new_token = re_login(email, password, appid, proxy, config_file)
                    if new_token:
                        headers["Authorization"] = f"Bearer {new_token}"
                        login_attempts += 1
                        time.sleep(5)
                        continue
                    return False, 0, "Session expired, re-login failed"
                return False, 0, f"API status false: {json_response}"
        except (requests.exceptions.RequestException, ValueError, KeyError) as e:
            response_content = getattr(e.response, 'text', "No response content")
            try:
                json_response = json.loads(response_content)
                message = json_response.get("message", str(e))
                if message == "Your app session expired, Please login again.":
                    logging.info(f"Session expired for {email}. Attempting re-login")
                    new_token = re_login(email, password, appid, proxy, config_file)
                    if new_token:
                        headers["Authorization"] = f"Bearer {new_token}"
                        login_attempts += 1
                        time.sleep(5)
                        continue
                    return False, 0, "Session expired, re-login failed"
            except json.JSONDecodeError:
                message = str(e)
            return False, 0, f"Error fetching points: {message}, Response: {response_content}"

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

async def telegram_message(bot, chat_id, message):
    if bot:
        try:
            await bot.send_message(chat_id=chat_id, text=message, parse_mode="Markdown")
            await asyncio.sleep(1)
        except Exception as e:
            logging.error(f"Error sending Telegram message: {e}")

def should_process_account(account, success_delay):
    return True

def process_get_points(account, config_file, point_log_dir, log_error_file, total_point_log, not_referral_log, use_proxy, bot=None, chat_id=None, max_retries=3, retry_delay=5, success_delay=86400):
    email = account["email"]
    token = account.get("token")
    appid = account["appid"]
    password = account.get("password")
    proxy = account.get("proxy") if use_proxy else None

    if not should_process_account(account, success_delay):
        message = (
            "ℹ️ *Get Points Skipped Notification* ℹ️\n\n"
            f"👤 *Account:* {email}\n\n"
            "⏭️ *Status:* Skipped (recent success)\n\n"
            f"🛠️ *Proxy Used:* {proxy if proxy else 'No proxy'}\n\n"
            "⚙️ *Reason:* Last success within 24 hours\n\n"
            "🤖 *Bot made by https://t.me/AirdropInsiderID*"
        )
        return email, False, 0, message

    session = None
    try:
        if proxy and not check_proxy(proxy):
            logging.error(f"Proxy {proxy} for {email} is not active.")
            message = (
                "⚠️ *Get Points Failure Notification* ⚠️\n\n"
                f"👤 *Account:* {email}\n\n"
                "❌ *Status:* Proxy Not Active\n\n"
                f"🛠️ *Proxy:* {proxy}\n\n"
                "⚙️ *Action Required:* Please check proxy status.\n\n"
                "🤖 *Bot made by https://t.me/AirdropInsiderID*"
            )
            return email, False, 0, message

        session = create_session(proxy)
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

        if token != "":
            logging.info(f"Using existing valid token for {email}")
        else:
            logging.info(f"No valid token for {email}. Attempting login...")
            new_token = re_login(email, password, appid, proxy, config_file)
            if not new_token:
                message = (
                    "⚠️ *Get Points Failure Notification* ⚠️\n\n"
                    f"👤 *Account:* {email}\n\n"
                    "❌ *Status:* Login Failed\n\n"
                    f"🛠️ *Proxy Used:* {proxy if proxy else 'No proxy'}\n\n"
                    "⚙️ *Action Required:* Check credentials or CAPTCHA solver.\n\n"
                    "🤖 *Bot made by https://t.me/AirdropInsiderID*"
                )
                return email, False, 0, message
            token = new_token
            headers["Authorization"] = f"Bearer {token}"

        attempt = 0
        while attempt < max_retries:
            attempt += 1
            try:
                logging.debug(f"Calling total_points for {email}, attempt {attempt}/{max_retries}")
                success, points, status_message = total_points(headers, session, appid, email, password, proxy, config_file, point_log_dir)
                if success:
                    message = (
                        "✅ *🌟 Get Points Success Notification 🌟* ✅\n\n"
                        f"👤 *Account:* {email}\n\n"
                        f"💰 *Points Earned:* {points}\n\n"
                        f"📢 *Message:* {status_message}\n\n"
                        f"🛠️ *Proxy Used:* {proxy if proxy else 'No proxy'}\n\n"
                        "🤖 *Bot made by https://t.me/AirdropInsiderID*"
                    )
                    logging.success(f"Success get points for {email}: {points} points")
                    return email, True, points, message
                else:
                    logging.error(f"Attempt {attempt}/{max_retries}: Failed get points for {email}. Reason: {status_message}")
                    log_curl_to_file(email, headers, f"https://ext-api.dawninternet.com/api/atom/v1/userreferral/getpoint?appid={appid}", None, proxy, status_message, log_error_file)
                    if attempt == max_retries:
                        message = (
                            "⚠️ *Get Points Failure Notification* ⚠️\n\n"
                            f"👤 *Account:* {email}\n\n"
                            "❌ *Status:* Get Points Failed\n\n"
                            f"📢 *Reason:* {status_message}\n\n"
                            f"🛠️ *Proxy Used:* {proxy if proxy else 'No proxy'}\n\n"
                            f"🔄 *Attempts:* {max_retries}/{max_retries}\n\n"
                            "⚙️ *Action Required:* Check account or proxy status.\n\n"
                            "🤖 *Bot made by https://t.me/AirdropInsiderID*"
                        )
                        return email, False, 0, message
                    logging.info(f"Retrying after {retry_delay} seconds...")
                    time.sleep(retry_delay)
            except Exception as e:
                error_message = str(e)
                response_content = getattr(e.response, 'text', 'No response content') if hasattr(e, 'response') else "No response"
                logging.error(f"Attempt {attempt}/{max_retries}: Error for {email}: {error_message}, Response: {response_content}")
                log_curl_to_file(email, headers, f"https://ext-api.dawninternet.com/api/atom/v1/userreferral/getpoint?appid={appid}", None, proxy, error_message, log_error_file, response_content)
                if attempt == max_retries:
                    message = (
                        "⚠️ *Get Points Failure Notification* ⚠️\n\n"
                        f"👤 *Account:* {email}\n\n"
                        "❌ *Status:* Error\n\n"
                        f"📢 *Reason:* {error_message}\n\n"
                        f"🛠️ *Proxy Used:* {proxy if proxy else 'No proxy'}\n\n"
                        f"🔄 *Attempts:* {max_retries}/{max_retries}\n\n"
                        "⚙️ *Action Required:* Check logs for details.\n\n"
                        "🤖 *Bot made by https://t.me/AirdropInsiderID*"
                    )
                    return email, False, 0, message
                logging.info(f"Retrying after {retry_delay} seconds...")
                time.sleep(retry_delay)
    finally:
        if session:
            session.close()

async def run_get_points(config_file, point_log_dir, log_error_file, total_point_log, not_referral_log, get_points_interval=3600, batch_size=10):
    config = read_config(config_file)
    bot_token = config.get("telegram_bot_token")
    chat_id = config.get("telegram_chat_id")
    use_proxy = config.get("use_proxy", False)
    use_telegram = config.get("use_telegram", False)
    success_delay = 86400  # 24 hours

    if use_telegram and (not bot_token or not chat_id):
        logging.error("Missing 'bot_token' or 'chat_id' in config.")
        return

    bot = telegram.Bot(token=bot_token) if use_telegram else None
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    message_queue = Queue()

    async def telegram_worker():
        while True:
            message = await message_queue.get()
            await telegram_message(bot, chat_id, message)
            message_queue.task_done()

    accounts = config.get("accounts", [])
    logging.info(f"Starting get points cycle for {len(accounts)} accounts every 1 hour")

    telegram_task = asyncio.create_task(telegram_worker()) if use_telegram else None

    while True:
        try:
            eligible_accounts = [acc for acc in accounts if should_process_account(acc, success_delay)]
            logging.info(f"Eligible accounts for this cycle: {len(eligible_accounts)}/{len(accounts)}")

            total_cycle_points = 0
            successful_accounts = 0

            for i in range(0, len(eligible_accounts), batch_size):
                batch = list(islice(eligible_accounts, i, i + batch_size))
                logging.info(f"Processing batch of {len(batch)} accounts (accounts {i+1} to {i+len(batch)})")
                pool = None
                try:
                    pool = Pool(processes=batch_size)
                    results = pool.starmap(process_get_points, [
                        (account, config_file, point_log_dir, log_error_file, total_point_log, not_referral_log, use_proxy, bot, chat_id)
                        for account in batch
                    ])

                    for email, success, points, message in results:
                        if use_telegram:
                            await message_queue.put(message)
                        logging.info(f"Get points for {email} completed with status: {'success' if success else 'failed'}, points: {points}")
                        if success:
                            total_cycle_points += points
                            successful_accounts += 1
                except Exception as e:
                    logging.error(f"Error in batch processing: {e}")
                    continue
                finally:
                    if pool:
                        pool.close()
                        pool.join()
                        logging.debug("Pool closed for batch")

            log_total_points(total_cycle_points, successful_accounts, len(accounts), total_point_log)
            logging.info(f"Get points cycle completed. Waiting {get_points_interval} seconds for next cycle.")
        except Exception as e:
            logging.error(f"Error in get points cycle: {e}")
            continue

        await asyncio.sleep(get_points_interval)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 6:
        print("Usage: core_get_point.py <config_file> <point_log_dir> <log_error_file> <total_point_log> <not_referral_log>")
        sys.exit(1)
    asyncio.run(run_get_points(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]))