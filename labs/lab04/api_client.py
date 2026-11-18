import os

import requests


def build_headers() -> dict[str, str]:

    headers = {"Accept": "application/json"}
    api_key = os.getenv("NVD_API_KEY")
    if api_key and api_key.strip():
        headers["apiKey"] = api_key.strip()
    return headers


def fetch_response(cve_id: str) -> dict:

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cveId": cve_id}

    response = requests.get(
        url,
        params=params,
        headers=build_headers(),
        timeout=(3.05, 10),
        allow_redirects=False,
    )

    response.raise_for_status()

    if response.status_code != 200:
        raise requests.exceptions.HTTPError(
            f"Отримано неочікуваний HTTP статус: {response.status_code}",
            response=response,
        )

    return response.json()
