from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client


def test_build_headers_no_key(monkeypatch):
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    headers = api_client.build_headers()
    assert "apiKey" not in headers
    assert headers["Accept"] == "application/json"


def test_build_headers_with_key(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "test-secret-key")
    headers = api_client.build_headers()
    assert headers["apiKey"] == "test-secret-key"


def test_fetch_uses_expected_request(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "test-key")
    payload = {"vulnerabilities": []}

    response = Mock(spec=requests.Response)
    response.status_code = 200
    response.json.return_value = payload

    fake_get = Mock(return_value=response)
    # Використовуємо рядковий шлях для monkeypatch, щоб уникнути попереджень PyCharm
    monkeypatch.setattr("labs.lab04.api_client.requests.get", fake_get)

    assert api_client.fetch_response("CVE-2099-10001") == payload

    fake_get.assert_called_once_with(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"cveId": "CVE-2099-10001"},
        headers={"Accept": "application/json", "apiKey": "test-key"},
        timeout=(3.05, 10),
        allow_redirects=False,
    )
    response.raise_for_status.assert_called_once_with()


@pytest.mark.parametrize("status_code", [204, 301, 302])
def test_fetch_unexpected_status(monkeypatch, status_code):
    response = Mock(spec=requests.Response)
    response.status_code = status_code

    fake_get = Mock(return_value=response)
    monkeypatch.setattr("labs.lab04.api_client.requests.get", fake_get)

    with pytest.raises(requests.exceptions.HTTPError):
        api_client.fetch_response("CVE-2099-10001")


def test_fetch_http_error(monkeypatch):
    response = Mock(spec=requests.Response)
    response.status_code = 404
    response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        "404 Error", response=response
    )

    fake_get = Mock(return_value=response)
    monkeypatch.setattr("labs.lab04.api_client.requests.get", fake_get)

    with pytest.raises(requests.exceptions.HTTPError):
        api_client.fetch_response("CVE-NOT-FOUND")


def test_fetch_connection_error(monkeypatch):
    fake_get = Mock(side_effect=requests.exceptions.ConnectionError)
    monkeypatch.setattr("labs.lab04.api_client.requests.get", fake_get)

    with pytest.raises(requests.exceptions.ConnectionError):
        api_client.fetch_response("CVE-TEST")


def test_fetch_json_decode_error(monkeypatch):
    response = Mock(spec=requests.Response)
    response.status_code = 200
    response.json.side_effect = requests.exceptions.JSONDecodeError(
        "Invalid JSON", "{", 1
    )

    fake_get = Mock(return_value=response)
    monkeypatch.setattr("labs.lab04.api_client.requests.get", fake_get)

    with pytest.raises(requests.exceptions.JSONDecodeError):
        api_client.fetch_response("CVE-TEST")
