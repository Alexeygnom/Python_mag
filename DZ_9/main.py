import argparse
import json
from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt


def load_events(json_path: Path) -> pd.DataFrame:
    """Читает JSON и возвращает DataFrame с событиями."""
    with json_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    # ожидаемый формат: {"events": [{...}, {...}]}
    events = data.get("events", [])
    df = pd.DataFrame(events)

    # на всякий случай приводим timestamp к datetime (не обязателен для распределения)
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    return df


def analyze_distribution(df: pd.DataFrame) -> pd.Series:
    """Возвращает распределение событий по signature (кол-во каждого типа)."""
    if "signature" not in df.columns:
        raise KeyError("В данных нет поля 'signature'")

    return df["signature"].value_counts()


def plot_distribution(counts: pd.Series, output_path: Path) -> None:
    """Строит bar chart и сохраняет в PNG."""
    plt.figure(figsize=(12, 6))
    counts.plot(kind="bar")
    plt.title("Распределение типов событий ИБ (signature)")
    plt.xlabel("Тип события (signature)")
    plt.ylabel("Количество")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()


def main():
    parser = argparse.ArgumentParser(description="Анализ и визуализация событий ИБ из JSON")
    parser.add_argument(
        "--input",
        default="events.json",
        help="Путь к JSON файлу (по умолчанию: events.json)",
    )
    parser.add_argument(
        "--out",
        default="graph.png",
        help="Имя PNG файла для графика (по умолчанию: graph.png)",
    )
    args = parser.parse_args()

    json_path = Path(args.input)
    if not json_path.exists():
        raise FileNotFoundError(f"Файл не найден: {json_path.resolve()}")

    df = load_events(json_path)

    print("Первые 5 строк данных:")
    print(df.head(), end="\n\n")

    counts = analyze_distribution(df)

    print("Распределение по signature:")
    print(counts, end="\n\n")

    out_path = Path(args.out)
    plot_distribution(counts, out_path)

    print(f"График сохранен в файл: {out_path.resolve()}")


if __name__ == "__main__":
    main()