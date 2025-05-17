import requests
import base64
import json
from datetime import datetime
from anticaptchaofficial.imagecaptcha import *
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
import logging
from fake_useragent import UserAgent
import os

# Setup logging sederhana
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger()

ua = UserAgent()

# File konfigurasi dan proxy
CONFIG_FILE = "config_3.json"
PROXY_FILE = "proxies.txt"

# Headers dasar untuk API request
headers = {
    'accept': '*/*',
    'accept-language': 'en-US,en;q=0.9',
    'origin': 'chrome-extension://fpdkjdnhkakefebpekbdhillbhonfjjp',
    'priority': 'u=1, i',
    'sec-ch-ua': '"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"macOS"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'cross-site'
}

# Fungsi untuk parsing proxy
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

# Fungsi untuk memeriksa proxy
def check_proxy(proxy):
    return True
    # proxies = parse_proxy(proxy)
    # test_url = "http://httpbin.org/ip"
    # try:
    #     response = requests.get(test_url, proxies=proxies, timeout=5)
    #     return response.status_code == 200
    # except requests.RequestException:
    #     return False

# Membaca daftar proxy dari file
def read_proxies(filename=PROXY_FILE):
    proxies = []
    try:
        with open(filename, 'r') as file:
            for line in file:
                proxy = line.strip()
                if proxy:
                    proxies.append(proxy)
        return proxies
    except FileNotFoundError:
        logger.error(f"Proxy file '{filename}' tidak ditemukan.")
        return []

# Mendapatkan proxy aktif
def get_active_proxies():
    proxies = read_proxies(PROXY_FILE)
    active_proxies = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(check_proxy, proxy) for proxy in proxies]
        for future, proxy in zip(futures, proxies):
            if future.result():
                active_proxies.append(proxy)
    if active_proxies:
        logger.info(f"Ditemukan {len(active_proxies)} proxy aktif.")
    else:
        logger.error("Tidak ada proxy aktif yang ditemukan.")
    return active_proxies

# Membuat session dengan atau tanpa proxy
def create_session(proxy=None):
    session = requests.Session()
    if proxy:
        proxies = parse_proxy(proxy)
        logger.info(f"Menggunakan proxy: {proxy}")
        session.proxies.update(proxies)
    else:
        logger.info("Menggunakan koneksi langsung (tanpa proxy).")
    return session

# Langkah 1: Mendapatkan puzzle_id dengan appid spesifik
def get_puzzle_id(session, appid):
    url = f"https://ext-api.dawninternet.com/chromeapi/dawn/v1/puzzle/get-puzzle?appid={appid}"
    try:
        response = session.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        if data.get("success") and "puzzle_id" in data:
            return data["puzzle_id"]
        else:
            logger.error("Gagal mendapatkan puzzle_id")
            return None
    except requests.exceptions.RequestException as e:
        logger.error(f"Error saat request puzzle_id: {e}")
        return None

# Langkah 2: Mendapatkan gambar captcha dengan appid spesifik
def get_captcha_image(session, puzzle_id, appid, output_file="captcha_image.png"):
    url = f"https://ext-api.dawninternet.com/chromeapi/dawn/v1/puzzle/get-puzzle-image?puzzle_id={puzzle_id}&appid={appid}"
    try:
        response = session.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        if data.get("success") and "imgBase64" in data:
            with open(output_file, "wb") as f:
                f.write(base64.b64decode(data["imgBase64"]))
            logger.info(f"Gambar captcha disimpan sebagai '{output_file}'")
            return output_file
        else:
            logger.error("Gagal mendapatkan gambar captcha")
            return None
    except requests.exceptions.RequestException as e:
        logger.error(f"Error saat request gambar captcha: {e}")
        return None

# Langkah 3: Memecahkan captcha
def solve_captcha(image_path):
    solver = imagecaptcha()
    solver.set_verbose(1)
    solver.set_key("377c52bebe64c59195ad7cdfd3a994fe")  # Ganti dengan API key Anda
    solver.set_soft_id(0)
    captcha_text = solver.solve_and_return_solution(image_path)
    if captcha_text != 0:
        logger.info("Captcha text: " + captcha_text)
        return captcha_text
    else:
        logger.error("Task selesai dengan error: " + solver.error_code)
        return None

# Langkah 5: Update config.json
def update_config_with_token(login_response, config_data, config_file=CONFIG_FILE):
    if not login_response or not login_response.get("status"):
        logger.error("Tidak ada data login yang valid untuk update config.")
        return config_data

    email = login_response["data"]["email"]
    token = login_response["data"]["token"]

    if "accounts" not in config_data:
        config_data["accounts"] = []

    found = False
    for account in config_data["accounts"]:
        if account["email"] == email:
            account["token"] = token
            found = True
            break

    if not found:
        config_data["accounts"].append({"email": email, "token": token})

    with open(config_file, "w") as f:
        json.dump(config_data, f, indent=2)
    logger.info(f"Token untuk {email} telah diperbarui di {config_file}")
    return config_data

# Fungsi untuk menulis log ke file teks
def log_to_file(filename, message):
    with open(filename, "a") as f:
        f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")

# Langkah 4: Melakukan login dengan appid spesifik (dari kode sebelumnya, diperbarui untuk debugging)
def perform_login(session, puzzle_id, captcha_solution, username, password, appid):
    url = f"https://ext-api.dawninternet.com/chromeapi/dawn/v1/user/login/v2?appid={appid}"
    
    login_headers = headers.copy()
    login_headers['content-type'] = 'application/json'
    login_headers["User-Agent"] = ua.random

    payload = {
        "username": username,
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
        response = session.post(url, headers=login_headers, data=json.dumps(payload))
        response.raise_for_status()
        data = response.json()
        logger.info(f"Login response untuk {username}: {json.dumps(data, indent=2)}")
        return data
    except requests.exceptions.RequestException as e:
        error_details = {
            "exception": str(e),
            "status_code": getattr(e.response, "status_code", "Tidak ada respons"),
            "headers": getattr(e.response, "headers", "Tidak ada header"),
            "content": None,
        }
        if hasattr(e, "response") and e.response is not None:
            try:
                error_details["content"] = e.response.json() if "application/json" in e.response.headers.get("content-type", "") else e.response.text
            except ValueError:
                error_details["content"] = "Isi respons bukan JSON atau tidak bisa diparse"
        logger.error(f"Error saat login untuk {username}: {json.dumps(error_details, indent=2, default=str)}")
        return error_details.get("content")  # Kembalikan isi respons meskipun error

# Langkah 6: Login semua akun dengan logika proxy, appid per akun, skip jika token ada, retry pada captcha salah, dan log ke txt
# Langkah 6: Login semua akun dengan logika proxy, appid per akun, skip jika token ada, retry pada captcha salah, dan log ke txt
def login_all_accounts(config_file=CONFIG_FILE, max_retries=1, error_log_file="captcha_errors.txt", invalid_log_file="invalid_password.txt"):
    try:
        with open(config_file, "r") as f:
            config = json.load(f)
    except FileNotFoundError:
        logger.error(f"File {config_file} tidak ditemukan.")
        return

    use_proxy = config.get("use_proxy", False)
    if "accounts" not in config or not config["accounts"]:
        logger.error("Tidak ada akun di config.json.")
        return

    proxy_list = get_active_proxies() if use_proxy else [None]
    if use_proxy and not proxy_list:
        logger.error("use_proxy true tetapi tidak ada proxy aktif. Berhenti.")
        return

    # Inisialisasi file log
    if not os.path.exists(error_log_file):
        with open(error_log_file, "w") as f:
            f.write("Log Error Captcha Salah\n\n")
    if not os.path.exists(invalid_log_file):
        with open(invalid_log_file, "w") as f:
            f.write("Log Invalid Username or Password\n\n")

    for account in config["accounts"]:
        if "email" not in account or "password" not in account or "appid" not in account:
            logger.error(f"Akun {account.get('email', 'tanpa email')} tidak memiliki email, password, atau appid.")
            continue
        
        email = account["email"]
        password = account["password"]
        appid = account["appid"]
        token = account.get("token", "")

        if token and token not in ["", "YOUR BEARER TOKEN"]:
            logger.info(f"Token sudah ada untuk {email}. Melewati akun ini.")
            continue

        logger.info(f"Memproses login untuk {email} dengan appid {appid}...")
        account_processed = False

        for proxy in proxy_list:
            session = create_session(proxy)
            try:
                puzzle_id = get_puzzle_id(session, appid)
                if not puzzle_id:
                    continue

                retries = 0
                while retries < max_retries:
                    captcha_file = get_captcha_image(session, puzzle_id, appid)
                    if not captcha_file:
                        break

                    captcha_solution = solve_captcha(captcha_file)
                    if not captcha_solution:
                        break

                    login_response = perform_login(session, puzzle_id, captcha_solution, email, password, appid)
                    logger.debug(f"Raw login response untuk {email}: {login_response}")  # Debugging

                    if login_response and isinstance(login_response, dict) and login_response.get("status"):
                        logger.info(f"Login berhasil untuk {email} dengan {'proxy ' + proxy if proxy else 'tanpa proxy'}!")
                        config = update_config_with_token(login_response, config)
                        account_processed = True
                        break
                    else:
                        # Cek apakah error karena captcha salah
                        if (login_response and isinstance(login_response, dict) and 
                            not login_response.get("success", True) and 
                            login_response.get("message") == "Incorrect answer. Try again!"):
                            retries += 1
                            error_message = (f"Email: {email} | Captcha: {captcha_solution} | "
                                           f"Proxy: {proxy if proxy else 'Tanpa Proxy'} | "
                                           f"Retry: {retries}/{max_retries}")
                            logger.info(f"Captcha salah untuk {email}. Retry {retries}/{max_retries}...")
                            log_to_file(error_log_file, f"ERROR: Incorrect answer - {error_message}")
                            continue
                        # Cek apakah error karena username/password salah
                        elif (login_response and isinstance(login_response, dict) and 
                              login_response.get("message") == "Invalid username or Password!"):
                            error_message = (f"Email: {email} | Proxy: {proxy if proxy else 'Tanpa Proxy'} | "
                                            f"Error: Invalid username or Password!")
                            logger.error(f"Login gagal untuk {email}: Invalid username or Password!")
                            log_to_file(invalid_log_file, f"ERROR: {error_message}")
                            account_processed = True  # Tandai akun sebagai diproses untuk skip
                            break
                        else:
                            logger.error(f"Login gagal untuk {email} dengan {'proxy ' + proxy if proxy else 'tanpa proxy'}.")
                            break

                if account_processed:
                    break
                if retries >= max_retries:
                    logger.error(f"Gagal login untuk {email} setelah {max_retries} percobaan captcha.")
                    break

            finally:
                session.close()
    try:
        with open(config_file, "r") as f:
            config = json.load(f)
    except FileNotFoundError:
        logger.error(f"File {config_file} tidak ditemukan.")
        return

    use_proxy = config.get("use_proxy", False)
    if "accounts" not in config or not config["accounts"]:
        logger.error("Tidak ada akun di config.json.")
        return

    proxy_list = get_active_proxies() if use_proxy else [None]
    if use_proxy and not proxy_list:
        logger.error("use_proxy true tetapi tidak ada proxy aktif. Berhenti.")
        return

    if not os.path.exists(error_log_file):
        with open(error_log_file, "w") as f:
            f.write("Log Error Captcha Salah\n\n")

    for account in config["accounts"]:
        if "email" not in account or "password" not in account or "appid" not in account:
            logger.error(f"Akun {account.get('email', 'tanpa email')} tidak memiliki email, password, atau appid.")
            continue
        
        email = account["email"]
        password = account["password"]
        appid = account["appid"]
        token = account.get("token", "")

        if token and token not in ["", "YOUR BEARER TOKEN"]:
            logger.info(f"Token sudah ada untuk {email}. Melewati akun ini.")
            continue

        logger.info(f"Memproses login untuk {email} dengan appid {appid}...")
        account_processed = False

        for proxy in proxy_list:
            session = create_session(proxy)
            try:
                puzzle_id = get_puzzle_id(session, appid)
                if not puzzle_id:
                    continue

                retries = 0
                while retries < max_retries:
                    captcha_file = get_captcha_image(session, puzzle_id, appid)
                    if not captcha_file:
                        break

                    captcha_solution = solve_captcha(captcha_file)
                    if not captcha_solution:
                        break

                    login_response = perform_login(session, puzzle_id, captcha_solution, email, password, appid)
                    logger.debug(f"Raw login response untuk {email}: {login_response}")  # Debugging

                    if login_response and isinstance(login_response, dict) and login_response.get("status"):
                        logger.info(f"Login berhasil untuk {email} dengan {'proxy ' + proxy if proxy else 'tanpa proxy'}!")
                        config = update_config_with_token(login_response, config)
                        account_processed = True
                        break
                    else:
                        # Cek apakah error karena captcha salah
                        if (login_response and isinstance(login_response, dict) and 
                            not login_response.get("success", True) and 
                            login_response.get("message") == "Incorrect answer. Try again!"):
                            retries += 1
                            error_message = (f"Email: {email} | Captcha: {captcha_solution} | "
                                           f"Proxy: {proxy if proxy else 'Tanpa Proxy'} | "
                                           f"Retry: {retries}/{max_retries}")
                            logger.info(f"Captcha salah untuk {email}. Retry {retries}/{max_retries}...")
                            log_to_file(error_log_file, f"ERROR: Incorrect answer - {error_message}")
                            continue
                        else:
                            logger.error(f"Login gagal untuk {email} dengan {'proxy ' + proxy if proxy else 'tanpa proxy'}.")
                            break

                if account_processed:
                    break
                if retries >= max_retries:
                    logger.error(f"Gagal login untuk {email} setelah {max_retries} percobaan captcha.")
                    break

            finally:
                session.close()

# Fungsi utama
def main():
    login_all_accounts()

if __name__ == "__main__":
    main()