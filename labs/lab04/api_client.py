import os
import requests


def build_headers():
    headers = {"Accept": "application/json"}
    api_key = os.getenv("NVD_API_KEY")
    if api_key and api_key.strip():
        headers["apiKey"] = api_key.strip()
    return headers


def fetch_response(cve_id):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cveId": cve_id}
    headers = build_headers()

    response = requests.get(
        url, params=params, headers=headers, timeout=(3.05, 10), allow_redirects=False
    )
    response.raise_for_status()
    return response.json()
