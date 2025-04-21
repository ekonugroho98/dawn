import json

# Membaca file config.json
try:
    with open("config_old.json", "r") as f:
        data = json.load(f)
except FileNotFoundError:
    print("Error: File config.json tidak ditemukan!")
    exit(1)
except json.JSONDecodeError:
    print("Error: File config.json tidak valid!")
    exit(1)

# Menghapus field token dari setiap account
for account in data.get("accounts", []):
    if "token" in account:
        del account["token"]

# Mengupdate file config.json
try:
    with open("config_old.json", "w") as f:
        json.dump(data, f, indent=2)
    print("File config_old.json berhasil diupdate!")
except Exception as e:
    print(f"Error saat menyimpan file: {e}")