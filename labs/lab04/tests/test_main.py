import pytest
import requests

from labs.lab04.main import main


def test_main_local_file_success(capsys, tmp_path):
    sample_json = tmp_path / "sample.json"
    sample_json.write_text(
        '{"vulnerabilities": [{"cve": {"id": "CVE-2099-10001", "vulnStatus": "Rejected"}}]}',
        encoding="utf-8",
    )

    exit_code = main(["--cve", "CVE-2099-10001", "--input", str(sample_json)])
    assert exit_code == 0

    captured = capsys.readouterr()
    assert "CVE-2099-10001" in captured.out
    assert "rejected" in captured.out


def test_main_wrong_cve_format(capsys):
    exit_code = main(["--cve", "INVALID-CVE"])
    assert exit_code == 2
    captured = capsys.readouterr()
    assert "Неправильний формат ідентифікатора CVE" in captured.err


def test_main_wrong_variant(monkeypatch, capsys):
    monkeypatch.setattr("labs.lab04.main.VARIANT_NUMBER", 100)
    exit_code = main(["--cve", "CVE-2099-10001"])
    assert exit_code == 2
    captured = capsys.readouterr()
    assert "VARIANT_NUMBER має бути" in captured.err


def test_main_missing_args():
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code == 2


def test_main_missing_local_file(capsys):
    exit_code = main(["--cve", "CVE-2099-10001", "--input", "non_existent.json"])
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "Помилка читання або парсингу" in captured.err


def test_main_invalid_local_json(capsys, tmp_path):
    sample_json = tmp_path / "sample.json"
    sample_json.write_text('{"vulnerabilities": ', encoding="utf-8")

    exit_code = main(["--cve", "CVE-2099-10001", "--input", str(sample_json)])
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "Помилка читання або парсингу" in captured.err


def test_main_network_timeout(monkeypatch, capsys):
    from labs.lab04 import api_client

    def fake_fetch(*_, **__):
        raise requests.exceptions.Timeout("Timeout")

    monkeypatch.setattr(api_client, "fetch_response", fake_fetch)

    exit_code = main(["--cve", "CVE-2099-10001"])
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "Перевищено час очікування" in captured.err
    assert "Traceback" not in captured.err


def test_main_network_http_error(monkeypatch, capsys):
    from labs.lab04 import api_client

    def fake_fetch(*_, **__):
        err_resp = requests.Response()
        err_resp.status_code = 404
        raise requests.exceptions.HTTPError("Not found", response=err_resp)

    monkeypatch.setattr(api_client, "fetch_response", fake_fetch)

    exit_code = main(["--cve", "CVE-2099-10001"])
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "HTTP статус 404" in captured.err
    assert "Traceback" not in captured.err
