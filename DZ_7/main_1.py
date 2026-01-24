import requests

BASE_URL = "https://jsonplaceholder.typicode.com"


def main() -> None:
    url = f"{BASE_URL}/posts"

    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        posts = response.json()
    except requests.exceptions.RequestException as e:
        print(f"Ошибка запроса: {e}")
        return
    except ValueError:
        print("Ошибка: не удалось распарсить JSON.")
        return

    # первые 5 постов
    for i, post in enumerate(posts[:5], start=1):
        title = post.get("title", "")
        body = post.get("body", "")

        print(f"Пост {i}")
        print(f"Заголовок: {title}")
        print("Тело:")
        print(body)
        print("-" * 40)


if __name__ == "__main__":
    main()
