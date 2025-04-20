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

CONFIG_FILE = "config.json"
ERROR_LOG_FILE = "log-error.txt"

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

# Adding a custom SUCCESS level between INFO and WARNING
SUCCESS_LEVEL = 25
logging.addLevelName(SUCCESS_LEVEL, "SUCCESS")

def log_success(message, *args, **kwargs):
    if logger.isEnabledFor(SUCCESS_LEVEL):
        logger._log(SUCCESS_LEVEL, message, args, **kwargs)

logging.success = log_success

def read_config(filename=CONFIG_FILE):
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

def update_config_remove_token(email):
    """Remove the token for the specified email in config.json."""
    try:
        config = read_config()
        for account in config.get("accounts", []):
            if account["email"] == email:
                if "token" in account:
                    del account["token"]
                    logging.info(f"Removed expired token for {email} from config.json")
                else:
                    logging.warning(f"No token found for {email} in config.json")
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
    except Exception as e:
        logging.error(f"Failed to update config.json for {email}: {e}")

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
    """Check if the proxy is active without logging."""
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

config = read_config(CONFIG_FILE)
bot_token = config.get("telegram_bot_token")
chat_id = config.get("telegram_chat_id")
use_proxy = config.get("use_proxy", False)
use_telegram = config.get("use_telegram", False)
get_points_interval = 1 * 60 * 60  # 12 hours in seconds

if use_telegram and (not bot_token or not chat_id):
    logging.error("Missing 'bot_token' or 'chat_id' in 'config.json'.")
    exit(1)

bot = telegram.Bot(token=bot_token) if use_telegram else None
get_points_url = "https://ext-api.dawninternet.com/api/atom/v1/userreferral/getpoint"

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def read_account(filename="config.json"):
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

def total_points(headers, session, appid, email):
    """Fetch total points for an account."""
    url = f"{get_points_url}?appid={appid}"
    try:
        headers["User-Agent"] = ua.random  # Use random User-Agent
        response = session.get(url, headers=headers, verify=False, timeout=30)
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
            return True, total_points, "Points retrieved successfully"
        else:
            message = json_response.get("message", "Unknown error")
            if message == "Your app session expired, Please login again.":
                logging.error(f"Session expired for {email}. Removing token from config.")
                update_config_remove_token(email)
                return False, 0, "Session expired, token removed from config"
            return False, 0, f"API status false: {json_response}"
    except (requests.exceptions.RequestException, ValueError, KeyError) as e:
        response_content = getattr(e.response, 'text', "No response content")
        try:
            json_response = json.loads(response_content)
            message = json_response.get("message", str(e))
            if message == "Your app session expired, Please login again.":
                logging.error(f"Session expired for {email}. Removing token from config.")
                update_config_remove_token(email)
                return False, 0, "Session expired, token removed from config"
        except json.JSONDecodeError:
            message = str(e)
        return False, 0, f"Error fetching points: {message}, Response: {response_content}"

def log_curl_to_file(email, headers, url, payload, proxy, reason, response_content=None):
    """Log error details as a curl command to log-error.txt with response content."""
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

    with open(ERROR_LOG_FILE, "a") as f:
        f.write(log_entry)

# Queue for Telegram messages
message_queue = Queue()

async def telegram_worker():
    while True:
        message = await message_queue.get()
        await telegram_message(message)
        message_queue.task_done()

async def queue_telegram_message(message):
    await message_queue.put(message)

async def telegram_message(message):
    if use_telegram:
        try:
            await bot.send_message(chat_id=chat_id, text=message, parse_mode="Markdown")
            await asyncio.sleep(1)  # Delay of 1 second after sending the message
        except Exception as e:
            logging.error(f"Error sending Telegram message: {e}")

def process_get_points(account, max_retries=3, retry_delay=5):
    """Process get points for an account."""
    email = account["email"]
    token = account.get("token")  # Use .get() to handle missing token
    appid = account["appid"]
    proxy = account.get("proxy") if use_proxy else None

    if not token:
        logging.error(f"No token found for {email}. Skipping get points.")
        message = (
            "⚠️ *Get Points Failure Notification* ⚠️\n\n"
            f"👤 *Account:* {email}\n\n"
            "❌ *Status:* No Token Available\n\n"
            f"🛠️ *Proxy Used:* {proxy if proxy else 'No proxy'}\n\n"
            "⚙️ *Action Required:* Please update token in config.json.\n\n"
            "🤖 *Bot made by https://t.me/AirdropInsiderID*"
        )
        return email, False, 0, message

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    attempt = 0

    while attempt < max_retries:
        attempt += 1
        session = None
        try:
            if proxy and not check_proxy(proxy):
                logging.error(f"Attempt {attempt}/{max_retries}: Proxy {proxy} for {email} is not active.")
                if attempt == max_retries:
                    message = (
                        "⚠️ *Get Points Failure Notification* ⚠️\n\n"
                        f"👤 *Account:* {email}\n\n"
                        "❌ *Status:* Proxy Not Active\n\n"
                        f"🛠️ *Proxy:* {proxy}\n\n"
                        f"🔄 *Attempts:* {max_retries}/{max_retries}\n\n"
                        "⚙️ *Action Required:* Please check proxy status.\n\n"
                        "🤖 *Bot made by https://t.me/AirdropInsiderID*"
                    )
                    return email, False, 0, message
                else:
                    logging.info(f"Retrying after {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    continue

            session = create_session(proxy)
            success, points, status_message = total_points(headers, session, appid, email)

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
                logging.error(f"Attempt {attempt}/{max_retries}: Failed get points for {email} with proxy {proxy if proxy else 'No proxy'} and appid {appid}. Reason: {status_message}")
                log_curl_to_file(email, headers, f"{get_points_url}?appid={appid}", None, session.proxies.get("http"), status_message)
                if "Session expired" in status_message:
                    # Token already removed in total_points, skip further attempts
                    message = (
                        "⚠️ *Get Points Failure Notification* ⚠️\n\n"
                        f"👤 *Account:* {email}\n\n"
                        "❌ *Status:* Session Expired\n\n"
                        f"📢 *Reason:* {status_message}\n\n"
                        f"🛠️ *Proxy Used:* {proxy if proxy else 'No proxy'}\n\n"
                        "⚙️ *Action Required:* Please login again to obtain a new token.\n\n"
                        "🤖 *Bot made by https://t.me/AirdropInsiderID*"
                    )
                    return email, False, 0, message
                if attempt == max_retries:
                    message = (
                        "⚠️ *Get Points Failure Notification* ⚠️\n\n"
                        f"👤 *Account:* {email}\n\n"
                        "❌ *Status:* Get Points Failed\n\n"
                        f"📢 *Reason:* {status_message}\n\n"
                        f"🛠️ *Proxy Used:* {proxy if proxy else 'No proxy'}\n\n"
                        f"🔄 *Attempts:* {max_retries}/{max_retries}\n\n"
                        "⚙️ *Action Required:* Please check account or proxy status.\n\n"
                        "🤖 *Bot made by https://t.me/AirdropInsiderID*"
                    )
                    return email, False, 0, message
                else:
                    logging.info(f"Retrying after {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    continue
        except requests.exceptions.RequestException as e:
            error_message = str(e)
            response_content = getattr(e.response, 'text', "No response content")
            try:
                json_response = json.loads(response_content)
                message = json_response.get("message", error_message)
                if message == "Your app session expired, Please login again.":
                    logging.error(f"Session expired for {email}. Token already removed.")
                    message = (
                        "⚠️ *Get Points Failure Notification* ⚠️\n\n"
                        f"👤 *Account:* {email}\n\n"
                        "❌ *Status:* Session Expired\n\n"
                        f"📢 *Reason:* {message}\n\n"
                        f"🛠️ *Proxy Used:* {proxy if proxy else 'No proxy'}\n\n"
                        "⚙️ *Action Required:* Please login again to obtain a new token.\n\n"
                        "🤖 *Bot made by https://t.me/AirdropInsiderID*"
                    )
                    return email, False, 0, message
            except json.JSONDecodeError:
                message = error_message
            logging.error(f"Attempt {attempt}/{max_retries}: Network error for {email}: {error_message}, Response: {response_content}")
            log_curl_to_file(email, headers, f"{get_points_url}?appid={appid}", None, session.proxies.get("http"), error_message, response_content)
            if attempt == max_retries:
                message = (
                    "⚠️ *Get Points Failure Notification* ⚠️\n\n"
                    f"👤 *Account:* {email}\n\n"
                    "❌ *Status:* Network Error\n\n"
                    f"🛠️ *Proxy Used:* {proxy if proxy else 'No proxy'}\n\n"
                    f"🔄 *Attempts:* {max_retries}/{max_retries}\n\n"
                    "⚙️ *Action Required:* Check network or proxy.\n\n"
                    "🤖 *Bot made by https://t.me/AirdropInsiderID*"
                )
                return email, False, 0, message
            else:
                logging.info(f"Retrying after {retry_delay} seconds...")
                time.sleep(retry_delay)
                continue
        finally:
            if session:
                session.close()

async def get_points_periodically():
    """Run get points every 1 hours for all accounts."""
    accounts = read_account()
    logging.info(f"Starting get points cycle for {len(accounts)} accounts every 1 hours")

    while True:
        pool = None
        try:
            pool = Pool(processes=2)  # Run 2 accounts concurrently
            results = pool.map(process_get_points, accounts)

            for email, success, points, message in results:
                await queue_telegram_message(message)
                logging.info(f"Get points for {email} completed with status: {'success' if success else 'failed'}, points: {points}")

            logging.info(f"Get points cycle completed. Waiting {get_points_interval} seconds (12 hours) for next cycle.")
        except Exception as e:
            logging.error(f"Error in get points cycle: {e}")
        finally:
            if pool:
                pool.close()
                pool.join()

        await asyncio.sleep(get_points_interval)

async def main():
    accounts = read_account()
    logging.info(f"Total accounts to process: {len(accounts)}")

    # Start the Telegram message worker
    telegram_task = asyncio.create_task(telegram_worker())
    # Start the get points worker
    get_points_task = asyncio.create_task(get_points_periodically())

    # Keep the event loop running
    while True:
        await asyncio.sleep(get_points_interval)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Script stopped by user.")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
    finally:
        logging.info("Cleaning up resources...")