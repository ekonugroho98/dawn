# core_keep_alive.py
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
import os
import re

# Inisialisasi UserAgent untuk menghasilkan User-Agent acak
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

# Adding a custom SUCCESS level between INFO and WARNING
SUCCESS_LEVEL = 25
logging.addLevelName(SUCCESS_LEVEL, "SUCCESS")

def log_success(message, *args, **kwargs):
    if logger.isEnabledFor(SUCCESS_LEVEL):
        logger._log(SUCCESS_LEVEL, message, args, **kwargs)

logging.success = log_success

def read_config(filename):
    try:
        with open(filename, 'r') as file:
            config = json.load(file)
        return config
    except FileNotFoundError:
        logging.error(f"Configuration file '{filename}' not found.")
        return {}
    except json.JSONDecodeError:
        logging.error(f"Invalid JSON format in '{filename}'.")
        return {}

def parse_proxy(proxy):
    """Parse proxy string into format for requests."""
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
    return True  # Always return True for proxy check
    # """Check if the proxy is active without logging."""
    # proxies = parse_proxy(proxy)
    # test_url = "http://httpbin.org/ip"
    # try:
        # response = requests.get(test_url, proxies=proxies, timeout=30)
        # return response.status_code == 200
    # except requests.RequestException:
    #     return False

def create_session(proxy=None):
    session = requests.Session()
    if proxy:
        proxies = parse_proxy(proxy)
        logging.info(f"Configuring session with proxy: {proxy}")
        session.proxies.update(proxies)
    return session

def read_account(filename):
    try:
        with open(filename, 'r') as file:
            data = json.load(file)
            accounts = data.get("accounts", [])
            return accounts 
    except FileNotFoundError:
        logging.error(f"Config file '{filename}' not found.")
        return []
    except json.JSONDecodeError:
        logging.error(f"Invalid JSON format in '{filename}'.")
        return []

def total_points(headers, session, get_points_url):
    try:
        headers["User-Agent"] = ua.random  # Gunakan User-Agent acak
        response = session.get(get_points_url, headers=headers, verify=False, timeout=30)
        response.raise_for_status()

        json_response = response.json()
        if json_response.get("status"):
            reward_point_data = json_response["data"]["rewardPoint"]
            referral_point_data = json_response["data"]["referralPoint"]
            total_points = (
                reward_point_data.get("points", 0) +
                reward_point_data.get("registerpoints", 0) +
                reward_point_data.get("signinpoints", 0) +
                reward_point_data.get("twitter_x_id_points", 0) +
                reward_point_data.get("discordid_points", 0) +
                reward_point_data.get("telegramid_points", 0) +
                reward_point_data.get("bonus_points", 0) +
                referral_point_data.get("commission", 0)
            )
            return total_points
    except (requests.exceptions.RequestException, ValueError, KeyError):
        pass  # Abaikan semua error tanpa logging
    return 0

def log_curl_to_file(email, headers, keepalive_url, keepalive_payload, proxy, reason, log_error_file):
    """Log error details as a curl command to log-error.txt."""
    curl_command = f"curl"
    if proxy:
        curl_command += f" --proxy '{proxy}'"
    curl_command += f" '{keepalive_url}'"
    for key, value in headers.items():
        curl_command += f" -H '{key}: {value}'"
    curl_command += f" --data-raw '{json.dumps(keepalive_payload)}'"

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = (
        f"[{timestamp}] Error for {email}\n"
        f"Reason: {reason}\n"
        f"{curl_command}\n"
        f"---------------------------------------\n"
    )

    with open(log_error_file, "a") as f:
        f.write(log_entry)

def keep_alive(headers, email, session, appid, base_keepalive_url, extension_id, _v, log_error_file):
    keepalive_url = f"{base_keepalive_url}?appid={appid}"
    keepalive_payload = {
        "username": email,
        "extensionid": extension_id,
        "numberoftabs": 0,
        "_v": _v
    }

    headers["User-Agent"] = ua.random  # Gunakan User-Agent acak
    try:
        response = session.post(keepalive_url, headers=headers, json=keepalive_payload, verify=False, timeout=30)
        response.raise_for_status()

        json_response = response.json()
        # Periksa message di dalam data.message
        if isinstance(json_response.get("data"), dict) and "message" in json_response["data"]:
            return True, json_response["data"]["message"]
        else:
            reason = f"Message key not found in response data: {json_response}"
            logging.warning(reason)
            # Log curl command for debugging
            curl_command = f"curl -X POST '{keepalive_url}'"
            for key, value in headers.items():
                curl_command += f" -H '{key}: {value}'"
            curl_command += f" -d '{json.dumps(keepalive_payload)}'"
            if session.proxies.get("http"):
                curl_command += f" --proxy '{session.proxies['http']}'"
            logging.error(f"Curl command for debugging:\n{curl_command}")
            log_curl_to_file(email, headers, keepalive_url, keepalive_payload, session.proxies.get("http"), reason, log_error_file)
            return False, "Message key not found in response data"
    except requests.exceptions.RequestException as e:
        reason = f"Request failed: {str(e)}"
        # Log curl command for debugging
        curl_command = f"curl -X POST '{keepalive_url}'"
        for key, value in headers.items():
            curl_command += f" -H '{key}: {value}'"
        curl_command += f" -d '{json.dumps(keepalive_payload)}'"
        if session.proxies.get("http"):
            curl_command += f" --proxy '{session.proxies['http']}'"
        logging.error(f"Curl command for debugging:\n{curl_command}")
        log_curl_to_file(email, headers, keepalive_url, keepalive_payload, session.proxies.get("http"), reason, log_error_file)
        return False, reason
    except ValueError as e:
        reason = f"Invalid JSON response: {str(e)}, content: {response.text}"
        # Log curl command for debugging
        curl_command = f"curl -X POST '{keepalive_url}'"
        for key, value in headers.items():
            curl_command += f" -H '{key}: {value}'"
        curl_command += f" -d '{json.dumps(keepalive_payload)}'"
        if session.proxies.get("http"):
            curl_command += f" --proxy '{session.proxies['http']}'"
        logging.error(f"Curl command for debugging:\n{curl_command}")
        log_curl_to_file(email, headers, keepalive_url, keepalive_payload, session.proxies.get("http"), reason, log_error_file)
        return False, reason

async def telegram_message(bot_token, chat_id, message):
    if bot_token and chat_id:
        try:
            bot = telegram.Bot(token=bot_token)
            await bot.send_message(chat_id=chat_id, text=message, parse_mode="Markdown")
            await asyncio.sleep(1)
        except Exception as e:
            logging.error(f"Error sending Telegram message: {e}")

async def telegram_worker(bot_token, chat_id):
    while True:
        try:
            message = await message_queue.get()
            if message:  # Only send if message is not None
                if isinstance(message, list):
                    for msg in message:
                        await telegram_message(bot_token, chat_id, msg)
                else:
                    await telegram_message(bot_token, chat_id, message)
                logging.info(f"Telegram message sent: {message[:100]}...")
            message_queue.task_done()
        except Exception as e:
            logging.error(f"Error in telegram worker: {e}")
            await asyncio.sleep(1)

def process_account(account, config_file, log_error_file, use_proxy, bot_token=None, chat_id=None, max_retries=3, retry_delay=5):
    email = account["email"]
    token = account.get("token")
    appid = account["appid"]
    password = account.get("password")
    proxy = account.get("proxy") if use_proxy else None

    # Get source account from config file name
    source_account = os.path.basename(config_file).replace("config_", "").replace(".json", "")

    # Define keep alive parameters
    base_keepalive_url = "https://ext-api.dawninternet.com/chromeapi/dawn/v1/userreward/keepalive"
    extension_id = "fpdkjdnhkakefebpekbdhillbhonfjjp"
    _v = "1.1.8"

    session = None
    try:
        if proxy and not check_proxy(proxy):
            logging.error(f"Proxy {proxy} for {email} is not active.")
            message = (
                "⚠️ *Keep Alive Failure Notification* ⚠️\n\n"
                f"👤 *Account:* {email}\n\n"
                "❌ *Status:* Proxy Not Active\n\n"
                f"🛠️ *Proxy:* {proxy}\n\n"
                f"📁 *Source:* Account {source_account}\n\n"
                "⚙️ *Action Required:* Please check proxy status.\n\n"
                "🤖 *Bot made by https://t.me/AirdropInsiderID*"
            )
            return email, False, message, bot_token, chat_id

        session = create_session(proxy)
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

        if not token:
            logging.info(f"No valid token for {email}. Attempting login...")
            new_token = re_login(email, password, appid, proxy, config_file)
            if not new_token:
                message = (
                    "⚠️ *Keep Alive Failure Notification* ⚠️\n\n"
                    f"👤 *Account:* {email}\n\n"
                    "❌ *Status:* Login Failed\n\n"
                    f"🛠️ *Proxy Used:* {proxy if proxy else 'No proxy'}\n\n"
                    f"📁 *Source:* Account {source_account}\n\n"
                    "⚙️ *Action Required:* Check credentials or CAPTCHA solver.\n\n"
                    "🤖 *Bot made by https://t.me/AirdropInsiderID*"
                )
                return email, False, message, bot_token, chat_id
            token = new_token
            headers["Authorization"] = f"Bearer {token}"

        attempt = 0
        while attempt < max_retries:
            attempt += 1
            try:
                success, status_message = keep_alive(headers, email, session, appid, base_keepalive_url, extension_id, _v, log_error_file)
                if success:
                    message = (
                        "✅ *🌟 Keep Alive Success Notification 🌟* ✅\n\n"
                        f"👤 *Account:* {email}\n\n"
                        f"📢 *Message:* {status_message}\n\n"
                        f"🛠️ *Proxy Used:* {proxy if proxy else 'No proxy'}\n\n"
                        f"📁 *Source:* Account {source_account}\n\n"
                        "🤖 *Bot made by https://t.me/AirdropInsiderID*"
                    )
                    logging.success(f"Success keep alive for {email} with proxy {proxy if proxy else 'No proxy'}. Reason: {status_message}")
                    return email, True, message, bot_token, chat_id
                else:
                    logging.error(f"Attempt {attempt}/{max_retries}: Failed keep alive for {email} with proxy {proxy if proxy else 'No proxy'} and appid {appid}. Reason: {status_message}")
                    if attempt == max_retries:
                        message = (
                            "⚠️ *Keep Alive Failure Notification* ⚠️\n\n"
                            f"👤 *Account:* {email}\n\n"
                            "❌ *Status:* Keep Alive Failed\n\n"
                            f"🛠️ *Proxy Used:* {proxy if proxy else 'No proxy'}\n\n"
                            f"📁 *Source:* Account {source_account}\n\n"
                            f"🔄 *Attempts:* {max_retries}/{max_retries}\n\n"
                            "⚙️ *Action Required:* Please check account or proxy status.\n\n"
                            "🤖 *Bot made by https://t.me/AirdropInsiderID*"
                        )
                        return email, False, message, bot_token, chat_id
                    else:
                        logging.info(f"Retrying after {retry_delay} seconds...")
                        time.sleep(retry_delay)
                        continue
            except Exception as e:
                logging.error(f"Attempt {attempt}/{max_retries}: Error for {email}: {str(e)}")
                if attempt == max_retries:
                    message = (
                        "⚠️ *Keep Alive Failure Notification* ⚠️\n\n"
                        f"👤 *Account:* {email}\n\n"
                        "❌ *Status:* Keep Alive Error\n\n"
                        f"🛠️ *Proxy Used:* {proxy if proxy else 'No proxy'}\n\n"
                        f"📁 *Source:* Account {source_account}\n\n"
                        f"🔄 *Attempts:* {max_retries}/{max_retries}\n\n"
                        f"📢 *Error:* {str(e)}\n\n"
                        "⚙️ *Action Required:* Please check account or proxy status.\n\n"
                        "🤖 *Bot made by https://t.me/AirdropInsiderID*"
                    )
                    return email, False, message, bot_token, chat_id
                else:
                    logging.info(f"Retrying after {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    continue
    except Exception as e:
        logging.error(f"Error processing account {email}: {str(e)}")
        message = (
            "⚠️ *Keep Alive Failure Notification* ⚠️\n\n"
            f"👤 *Account:* {email}\n\n"
            "❌ *Status:* Processing Error\n\n"
            f"🛠️ *Proxy Used:* {proxy if proxy else 'No proxy'}\n\n"
            f"📁 *Source:* Account {source_account}\n\n"
            f"📢 *Error:* {str(e)}\n\n"
            "⚙️ *Action Required:* Please check account or proxy status.\n\n"
            "🤖 *Bot made by https://t.me/AirdropInsiderID*"
        )
        return email, False, message, bot_token, chat_id
    finally:
        if session:
            session.close()

async def run_keep_alive(config_file, log_error_file, poll_interval=300):
    accounts = read_account(config_file)
    logging.info(f"Total accounts to process: {len(accounts)}")

    config = read_config(config_file)
    bot_token = config.get("telegram_bot_token")
    chat_id = config.get("telegram_chat_id")
    use_proxy = config.get("use_proxy", False)
    use_telegram = config.get("use_telegram", False)

    if use_telegram and (not bot_token or not chat_id):
        logging.error("Missing 'bot_token' or 'chat_id' in config.")
        return

    message_queue = asyncio.Queue()

    telegram_task = asyncio.create_task(telegram_worker(bot_token, chat_id)) if use_telegram else None

    while True:
        try:
            pool = None
            try:
                pool = Pool(processes=10)
                results = pool.starmap(process_account, [
                    (account, config_file, log_error_file, use_proxy, bot_token, chat_id)
                    for account in accounts
                ])

                for email, success, message, _, _ in results:
                    if use_telegram and message:  # Only send if message is not None
                        await message_queue.put(message)
                        logging.info(f"Message queued for {email}")
                    logging.info(f"Keep alive for {email} completed with status: {'success' if success else 'failed'}")
            except Exception as e:
                logging.error(f"Error in main loop: {e}")
                continue
            finally:
                if pool:
                    pool.close()
                    pool.join()

            logging.info(f"Keep alive cycle completed. Waiting {poll_interval} seconds for next cycle.")
            await asyncio.sleep(poll_interval)
        except Exception as e:
            logging.error(f"Error in main loop: {e}")
            await asyncio.sleep(10)
            continue

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: core_keep_alive.py <config_file> <log_error_file>")
        sys.exit(1)
    asyncio.run(run_keep_alive(sys.argv[1], sys.argv[2]))