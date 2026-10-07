import csv
import json
import logging
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

# Налаштовуємо базове форматування, але створюємо власний логер для Ruff (LOG015)
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def analyze_access_log(
    log_path: str,
    output_path: str,
    min_status: int = 400,
    top_n: int = 5,
    report_format: str = "json",
):
    log_file = Path(log_path)

    if not log_file.exists():
        logger.error(
            f"Файл {log_path} не знайдено! Переконайся, що він лежить у папці data."
        )
        return

    logger.info(f"Loading access log from {log_path}...")

    # Регулярний вираз для розбору рядка журналу Nginx/Apache
    log_pattern = re.compile(
        r"(?P<ip>\d+\.\d+\.\d+\.\d+)\s+-\s+-\s+"
        r"\[(?P<date>.*?)]\s+"
        r'"(?P<method>[A-Z]+)\s+(?P<uri>.*?)\s+HTTP/.*?"\s+'
        r"(?P<status>\d{3})\s+(?P<size>\d+|-)"
    )

    # Регулярні вирази для пошуку сигнатур атак
    sql_injection_pattern = re.compile(r"(UNION.*?SELECT|--|%27)", re.IGNORECASE)
    dt_pattern = re.compile(r"\.\./")
    xss_pattern = re.compile(r"<script.*?>", re.IGNORECASE)

    error_ips = Counter()
    status_counts = {}
    attack_alerts = []

    parsed_entries = 0
    min_time = None
    max_time = None

    # Читаємо файл порядково
    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            match = log_pattern.search(line)
            if not match:
                continue

            parsed_entries += 1
            ip = match.group("ip")
            status = int(match.group("status"))
            uri = match.group("uri")
            method = match.group("method")
            date_str = match.group("date")

            # Обробка дати з додаванням часового поясу для Ruff (DTZ007)
            try:
                dt_obj = datetime.strptime(
                    date_str.split()[0], "%d/%b/%Y:%H:%M:%S"
                ).replace(tzinfo=timezone.utc)
                if min_time is None or dt_obj < min_time:
                    min_time = dt_obj
                if max_time is None or dt_obj > max_time:
                    max_time = dt_obj
            except ValueError:
                pass

            # Рахуємо помилкові статуси (4xx, 5xx)
            if status >= min_status:
                error_ips[ip] += 1
                if ip not in status_counts:
                    status_counts[ip] = Counter()
                status_counts[ip][status] += 1

            # Шукаємо атаки у URI
            req_line = f"{method} {uri}"
            if sql_injection_pattern.search(uri):
                attack_alerts.append(
                    f'[ALERT] Potential SQLi attack from {ip}: "{req_line}"'
                )
            elif dt_pattern.search(uri):
                attack_alerts.append(
                    f'[ALERT] Potential Directory Traversal from {ip}: "{req_line}"'
                )
            elif xss_pattern.search(uri):
                attack_alerts.append(f'[ALERT] Potential XSS from {ip}: "{req_line}"')

    # Вивід загальної інформації
    time_range = ""
    if min_time and max_time:
        time_range = f" from {min_time.strftime('%Y-%m-%d %H:%M:%S')} to {max_time.strftime('%Y-%m-%d %H:%M:%S')}"
    logger.info(f"Processed {parsed_entries} log entries{time_range}.")

    # Вивід Топ IP адрес
    print(
        f"\n=== Top-{top_n} IP Addresses with Error Statuses ({str(min_status)[:1]}xx/5xx) ==="
    )
    top_ips = error_ips.most_common(top_n)
    for ip, count in top_ips:
        details = ", ".join([f"{st}: {cnt}" for st, cnt in status_counts[ip].items()])
        print(f"{ip:15} {count} errors ({details})")

    # Вивід знайдених атак
    print("\n=== Detected Attack Signatures ===")
    for alert in attack_alerts:
        print(alert)

    # Формування та збереження звіту
    out_path = Path(output_path)
    if report_format == "json":
        report_data = {
            "total_processed": parsed_entries,
            "top_error_ips": [
                {"ip": ip, "count": count, "details": dict(status_counts[ip])}
                for ip, count in top_ips
            ],
            "attack_alerts": attack_alerts,
        }
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4)

    elif report_format == "csv":
        with open(out_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["IP", "Error Count", "Details"])
            for ip, count in top_ips:
                writer.writerow([ip, count, str(dict(status_counts[ip]))])

    logger.info(f"Analysis report saved to {output_path}")


if __name__ == "__main__":
    analyze_access_log(
        log_path="data/access.log",
        output_path="data/web_analysis_report.json",
        min_status=400,
        top_n=3,
        report_format="json",
    )
