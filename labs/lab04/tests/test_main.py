import pytest
from labs.lab04.main import main
from shared import student


def test_main_local_file_success(capsys, tmp_path):
    # Використовуємо tmp_path для створення тимчасового файлу для тесту
    sample_json = tmp_path / "sample.json"
    sample_json.write_text(
        '{"vulnerabilities": [{"cve": {"id": "CVE-2099-10001", "vulnStatus": "Rejected"}}]}'
    )

    exit_code = main(["--cve", "CVE-2099-10001", "--input", str(sample_json)])
    assert exit_code == 0

    captured = capsys.readouterr()
    assert "CVE-2099-10001" in captured.out
    assert "rejected" in captured.out


def test_main_wrong_variant(monkeypatch, capsys):
    monkeypatch.setattr(student, "VARIANT_NUMBER", 2)
    exit_code = main(["--cve", "CVE-2099-10001"])
    assert exit_code == 2

    captured = capsys.readouterr()
    assert "Цей код розрахований на Варіант 1" in captured.err


def test_main_missing_args(capsys):
    exit_code = main([])
    assert exit_code == 2
    captured = capsys.readouterr()
    assert "required" in captured.err
