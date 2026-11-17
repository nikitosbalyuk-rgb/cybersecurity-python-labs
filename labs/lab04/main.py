import sys
import json
import argparse
import pathlib
import requests

from shared import student
from labs.lab04 import api_client, analysis


def load_response(path):
    file_path = pathlib.Path(path)
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        sys.stderr.write(f"Помилка читання файлу: {e}\n")
        return None


def main(argv=None):
    parser = argparse.ArgumentParser(description="Клієнт для NVD API")
    parser.add_argument("--cve", required=True, help="Ідентифікатор CVE")
    parser.add_argument("--input", help="Шлях до локального JSON-файлу")

    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return 2

    try:
        if student.VARIANT_NUMBER != 1:
            sys.stderr.write("Помилка: Цей код розрахований на Варіант 1.\n")
            return 2
    except AttributeError:
        sys.stderr.write("Помилка: Не знайдено VARIANT_NUMBER у shared.student\n")
        return 2

    cve_id = args.cve

    if args.input:
        payload = load_response(args.input)
        if payload is None:
            return 1
    else:
        try:
            payload = api_client.fetch_response(cve_id)
        except requests.exceptions.RequestException as e:
            sys.stderr.write(f"Мережева помилка: {e}\n")
            return 1

    try:
        record = analysis.extract_record(payload, cve_id)
        report = analysis.build_report(record, cve_id, student.VARIANT_NUMBER)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0
    except ValueError as e:
        sys.stderr.write(f"Помилка перевірки даних: {e}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
