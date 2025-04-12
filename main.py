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
from fake_useragent import UserAgent

CONFIG_FILE = "config.json"

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
poll_interval = config.get("poll_interval", 120)  # Default to 120 seconds

if use_telegram and (not bot_token or not chat_id):
    logging.error("Missing 'bot_token' or 'chat_id' in 'config.json'.")
    exit(1)

bot = telegram.Bot(token=bot_token) if use_telegram else None
base_keepalive_url = "https://ext-api.dawninternet.com/chromeapi/dawn/v1/userreward/keepalive"
get_points_url = "https://ext-api.dawninternet.com/api/atom/v1/userreferral/getpoint"
extension_id = "fpdkjdnhkakefebpekbdhillbhonfjjp"
_v = "1.1.5"

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
ua = UserAgent()
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

def total_points(headers, session):
    try:
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

def keep_alive(headers, email, session, appid):
    keepalive_url = f"{base_keepalive_url}?appid={appid}"
    keepalive_payload = {
        "username": email,
        "extensionid": extension_id,
        "numberoftabs": 0,
        "_v": _v
    }

    headers["User-Agent"] = ua.random
    logging.info(f"Sending keepalive request to {keepalive_url} with headers: {headers}, payload: {keepalive_payload}, proxies: {session.proxies}")

    try:
        response = session.post(keepalive_url, headers=headers, json=keepalive_payload, verify=False, timeout=30)
        logging.info(f"Keepalive response status: {response.status_code}, content: {response.text}")
        response.raise_for_status()

        json_response = response.json()
        if isinstance(json_response.get("data"), dict) and "message" in json_response["data"]:
            return True, json_response["data"]["message"]
        else:
            logging.warning(f"Message not found in response for {email}")
            return False, "Message not found in response"
    except requests.exceptions.RequestException as e:
        logging.warning(f"Keep alive failed for {email}: {str(e)}")
        return False, f"Request failed: {str(e)}"

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

def process_account(account, max_retries=3, retry_delay=5):
    email = account["email"]
    token = account["token"]
    appid = account["appid"]
    proxy = account.get("proxy") if use_proxy else None

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    logging.info(f"Processing {email} with proxy: {proxy if proxy else 'No proxy'}")
    attempt = 0

    while attempt < max_retries:
        attempt += 1
        session = None
        try:
            if proxy and not check_proxy(proxy):
                logging.error(f"Attempt {attempt}/{max_retries}: Proxy {proxy} for {email} is not active.")
                if attempt == max_retries:
                    message = (
                        "⚠️ *Failure Notification* ⚠️\n\n"
                        f"👤 *Account:* {email}\n\n"
                        "❌ *Status:* Proxy Not Active\n\n"
                        f"🛠️ *Proxy:* {proxy}\n\n"
                        f"🔄 *Attempts:* {max_retries}/{max_retries}\n\n"
                        "⚙️ *Action Required:* Please check proxy status.\n\n"
                        "🤖 *Bot made by https://t.me/AirdropInsiderID*"
                    )
                    return email, False, message
                else:
                    logging.info(f"Retrying after {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    continue

            session = create_session(proxy)
            success, status_message = keep_alive(headers, email, session, appid)

            if success:
                points = total_points(headers, session)
                message = (
                    "✅ *🌟 Success Notification 🌟* ✅\n\n"
                    f"👤 *Account:* {email}\n\n"
                    f"💰 *Points Earned:* {points}\n\n"
                    f"📢 *Message:* {status_message}\n\n"
                    f"🛠️ *Proxy Used:* {proxy if proxy else 'No proxy'}\n\n"
                    "🤖 *Bot made by https://t.me/AirdropInsiderID*"
                )
                logging.success(f"Success keep alive for {email} with proxy {proxy if proxy else 'No proxy'} and appid {appid}. Reason: {status_message}")
                return email, True, message
            else:
                logging.error(f"Attempt {attempt}/{max_retries}: Failed keep alive for {email} with proxy {proxy if proxy else 'No proxy'} and appid {appid}. Reason: {status_message}")
                if attempt == max_retries:
                    message = (
                        "⚠️ *Failure Notification* ⚠️\n\n"
                        f"👤 *Account:* {email}\n\n"
                        "❌ *Status:* Keep Alive Failed\n\n"
                        f"🛠️ *Proxy Used:* {proxy if proxy else 'No proxy'}\n\n"
                        f"🔄 *Attempts:* {max_retries}/{max_retries}\n\n"
                        "⚙️ *Action Required:* Please check account or proxy status.\n\n"
                        "🤖 *Bot made by https://t.me/AirdropInsiderID*"
                    )
                    return email, False, message
                else:
                    logging.info(f"Retrying after {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    continue
        except requests.exceptions.RequestException as e:
            error_message = str(e)
            logging.error(f"Attempt {attempt}/{max_retries}: Network error for {email}: {error_message}")
            if attempt == max_retries:
                message = (
                    "⚠️ *Failure Notification* ⚠️\n\n"
                    f"👤 *Account:* {email}\n\n"
                    "❌ *Status:* Network Error\n\n"
                    f"🛠️ *Proxy Used:* {proxy if proxy else 'No proxy'}\n\n"
                    f"🔄 *Attempts:* {max_retries}/{max_retries}\n\n"
                    "⚙️ *Action Required:* Check network or proxy.\n\n"
                    "🤖 *Bot made by https://t.me/AirdropInsiderID*"
                )
                return email, False, message
            else:
                logging.info(f"Retrying after {retry_delay} seconds...")
                time.sleep(retry_delay)
                continue
        finally:
            if session:
                session.close()

async def main():
    accounts = read_account()
    logging.info(f"Total accounts to process: {len(accounts)}")

    # Start the Telegram message worker
    telegram_task = asyncio.create_task(telegram_worker())

    while True:
        pool = None
        try:
            pool = Pool(processes=10)  # Jalankan 2 akun secara bersamaan
            results = pool.map(process_account, accounts)

            for email, success, message in results:
                await queue_telegram_message(message)
                logging.info(f"Account {email} completed with status: {'success' if success else 'failed'}")

            logging.info(f"All accounts processed. Waiting {poll_interval} seconds before next cycle.")
            await asyncio.sleep(poll_interval)
        except Exception as e:
            logging.error(f"Error in main loop: {e}")
            await asyncio.sleep(10)
        finally:
            if pool:
                pool.close()
                pool.join()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Script stopped by user.")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
    finally:
        logging.info("Cleaning up resources...")