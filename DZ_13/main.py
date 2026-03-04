"""
Script: VirusTotal API request example

Requirements:
pip install requests

Before running the script you need to set the API key.

PowerShell (Windows):
$env:VT_API_KEY="YOUR_API_KEY"

Linux / macOS:
export VT_API_KEY="YOUR_API_KEY"

Run the script:
python main.py

Description:
This script sends a request to the VirusTotal API to get
the scan report for a file hash and prints scan statistics
(malicious, suspicious, harmless, undetected).
"""


import os
import requests
import json


API_KEY = os.getenv("VT_API_KEY")

if not API_KEY:
    print("Не найден API ключ. Установите VT_API_KEY")
    exit()

FILE_HASH = "44d88612fea8a8f36de82e1278abb02f"

url = f"https://www.virustotal.com/api/v3/files/{FILE_HASH}"

headers = {
    "x-apikey": API_KEY
}

response = requests.get(url, headers=headers)

if response.status_code != 200:
    print("Ошибка запроса:", response.status_code)
    print(response.text)
    exit()

data = response.json()

with open("result.json", "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2, ensure_ascii=False)

# Полный JSON (можно оставить для задания)
print("----- RAW JSON -----")
print(json.dumps(data, indent=2))

stats = data["data"]["attributes"]["last_analysis_stats"]

print("\n----- Scan Results -----")
print("Malicious:", stats["malicious"])
print("Suspicious:", stats["suspicious"])
print("Harmless:", stats["harmless"])
print("Undetected:", stats["undetected"])
