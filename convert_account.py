import json
import random
import string
from datetime import datetime

# Fungsi untuk generate appid random dengan panjang 24 karakter
def generate_appid():
    characters = string.ascii_lowercase + string.digits
    return ''.join(random.choice(characters) for _ in range(24))

# Config awal untuk proxy
proxy_base = "http://bda3498ff170f27a3618:1142078ecc2a3ab9@gw.dataimpulse.com"
start_port = 10000  # Port awal, bisa diubah sesuai config

# List untuk menyimpan data JSON
json_data = []

# Membaca data dari file account36.txt
try:
    with open('account_info-36.txt', 'r') as file:
        accounts = file.readlines()
    
    # Proses setiap akun
    for index, account in enumerate(accounts):
        # Skip baris kosong
        if not account.strip():
            continue
            
        # Split hanya pada | pertama untuk menangani | dalam password
        try:
            parts = account.strip().split('|', 1)  # Split hanya pada | pertama
            if len(parts) != 2:
                print(f"Baris tidak valid diabaikan: {account.strip()}")
                continue
                
            email = parts[0]
            # Ambil password (hapus | di akhir jika ada)
            password = parts[1].rstrip('|')
            
            # Generate data untuk setiap akun
            account_data = {
                "proxy": f"{proxy_base}:{start_port + index}",
                "appid": generate_appid(),
                "email": email,
                "password": password,
                "token": "",
            }
            json_data.append(account_data)
        except Exception as e:
            print(f"Baris tidak valid diabaikan: {account.strip()} - Error: {str(e)}")
            continue

    # Simpan ke file JSON
    with open('accounts.json', 'w') as f:
        json.dump(json_data, f, indent=2)

    print("File JSON telah digenerate: accounts.json")

except FileNotFoundError:
    print("Error: File account36.txt tidak ditemukan!")
except Exception as e:
    print(f"Error: Terjadi kesalahan - {str(e)}")