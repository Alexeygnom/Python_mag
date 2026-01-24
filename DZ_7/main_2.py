import os
import requests


BASE_URL = "https://api.openweathermap.org/data/2.5/weather"


def get_api_key() -> str:
    api_key = os.getenv("OPENWEATHER_API_KEY")
    if not api_key:
        raise SystemExit(
            "Ошибка: не найден API ключ.\n"
            "Установи переменную окружения OPENWEATHER_API_KEY и запусти снова.\n"
            'PowerShell пример: $env:OPENWEATHER_API_KEY="твой_ключ"'
        )
    return api_key


def fetch_weather(city: str, api_key: str) -> dict:
    params = {
        "q": city,
        "appid": api_key,
        "units": "metric",  # температура в °C
        "lang": "ru",       # описание на русском
    }

    try:
        response = requests.get(BASE_URL, params=params, timeout=10)
        # Если город не найден или ключ неверный, тут будет 4xx
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError:
        # Попробуем вытащить текст ошибки из JSON, если он есть
        try:
            err = response.json()
            message = err.get("message", "неизвестная ошибка")
        except Exception:
            message = response.text.strip() or "неизвестная ошибка"

        raise SystemExit(f"Ошибка API ({response.status_code}): {message}")
    except requests.exceptions.RequestException as e:
        raise SystemExit(f"Ошибка запроса: {e}") from e
    except ValueError as e:
        raise SystemExit(f"Ошибка: не удалось распарсить JSON: {e}") from e


def main() -> None:
    city = input("Введите название города: ").strip()
    if not city:
        print("Город не указан.")
        return

    api_key = get_api_key()
    data = fetch_weather(city, api_key)

    temp = data.get("main", {}).get("temp")
    description = None
    weather_list = data.get("weather")
    if isinstance(weather_list, list) and weather_list:
        description = weather_list[0].get("description")

    name = data.get("name", city)

    print(f"\nГород: {name}")
    if temp is not None:
        print(f"Температура: {temp} °C")
    else:
        print("Температура: нет данных")

    if description:
        print(f"Описание: {description}")
    else:
        print("Описание: нет данных")


if __name__ == "__main__":
    main()