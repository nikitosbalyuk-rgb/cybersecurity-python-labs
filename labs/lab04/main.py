import argparse
import json
import pathlib
import re
import sys

import requests

from labs.lab04 import analysis, api_client

# Змінна має бути доступна для підміни у тестах через модуль main
from shared.student import VARIANT_NUMBER


def load_response(path: str) -> dict:

    file_path = pathlib.Path(path)
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Клієнт для NVD API")
    parser.add_argument(
        "--cve", required=True, help="Ідентифікатор CVE (наприклад, CVE-2021-44228)"
    )
    parser.add_argument(
        "--input", help="Шлях до локального JSON-файлу (замість мережевого запиту)"
    )

    args = parser.parse_args(argv)

    if not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", args.cve):
        sys.stderr.write("Помилка: Неправильний формат ідентифікатора CVE.\n")
        return 2

    if (
        isinstance(VARIANT_NUMBER, bool)
        or not isinstance(VARIANT_NUMBER, int)
        or not (1 <= VARIANT_NUMBER <= 15)
    ):
        sys.stderr.write("Помилка: VARIANT_NUMBER має бути цілим числом від 1 до 15.\n")
        return 2

    cve_id = args.cve

    if args.input is not None:
        try:
            payload = load_response(args.input)
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            sys.stderr.write("Помилка читання або парсингу локального файлу.\n")
            return 1
    else:
        try:
            payload = api_client.fetch_response(cve_id)
        except requests.exceptions.Timeout:
            sys.stderr.write("Помилка: Перевищено час очікування (таймаут).\n")
            return 1
        except requests.exceptions.ConnectionError:
            sys.stderr.write("Помилка: Проблема зі з'єднанням.\n")
            return 1
        except requests.exceptions.HTTPError as e:
            code = e.response.status_code if e.response is not None else "Unknown"
            sys.stderr.write(f"Помилка: HTTP статус {code}\n")
            return 1
        except requests.exceptions.RequestException:
            sys.stderr.write("Помилка: Запит завершився невдало.\n")
            return 1
        except ValueError:
            sys.stderr.write("Помилка: Отримана відповідь не є валідним JSON.\n")
            return 1

    try:
        record = analysis.extract_record(payload, cve_id)
        report = analysis.build_report(record, cve_id, VARIANT_NUMBER)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0
    except ValueError as e:
        sys.stderr.write(f"Помилка перевірки даних: {e}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
