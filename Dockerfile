# Gunakan base image Python
FROM python:3.10-slim

# Set direktori kerja di container
WORKDIR /app

# Salin seluruh isi project ke dalam container
COPY . .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Default command: bisa diubah dari docker-compose
CMD ["python", "main.py"]
