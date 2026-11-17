import pytest
import requests
from unittest.mock import Mock, patch
from labs.lab04 import api_client


def test_build_headers_no_key(monkeypatch):
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    headers = api_client.build_headers()
    assert "apiKey" not in headers
    assert headers["Accept"] == "application/json"


def test_build_headers_with_key(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "  my-secret-key  ")
    headers = api_client.build_headers()
    assert headers["apiKey"] == "my-secret-key"


@patch("labs.lab04.api_client.requests.get")
def test_fetch_uses_expected_request(mock_get):
    payload = {"startIndex": 0, "totalResults": 0, "vulnerabilities": []}
    response = Mock(spec=requests.Response)
    response.status_code = 200
    response.json.return_value = payload

    mock_get.return_value = response

    assert api_client.fetch_response("CVE-2099-10001") == payload

    mock_get.assert_called_once_with(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"cveId": "CVE-2099-10001"},
        headers={"Accept": "application/json"},
        timeout=(3.05, 10),
        allow_redirects=False,
    )
    response.raise_for_status.assert_called_once_with()


@patch("labs.lab04.api_client.requests.get")
def test_fetch_http_error(mock_get):
    response = Mock(spec=requests.Response)
    response.raise_for_status.side_effect = requests.exceptions.HTTPError("404 Error")

    mock_get.return_value = response

    with pytest.raises(requests.exceptions.HTTPError):
        api_client.fetch_response("CVE-NOT-FOUND")
