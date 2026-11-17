import pytest
import copy
from labs.lab04.analysis import build_report, extract_record


@pytest.fixture
def base_record():
    return {
        "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "en", "value": "Test description"}],
        "metrics": {
            "cvssMetricV31": [
                {
                    "type": "Primary",
                    "source": "nvd@nist.gov",
                    # noinspection SpellCheckingInspection
                    "cvssData": {
                        "version": "3.1",
                        "baseScore": 9.8,
                        "attackVector": "NETWORK",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    },
                }
            ]
        },
    }


def test_extract_record_valid():
    payload = {"vulnerabilities": [{"cve": {"id": "CVE-TEST"}}]}
    assert extract_record(payload, "CVE-TEST") == {"id": "CVE-TEST"}


def test_extract_record_invalid_json():
    with pytest.raises(ValueError, match="Неправильна структура"):
        extract_record([], "CVE-TEST")


def test_extract_record_wrong_id():
    payload = {"vulnerabilities": [{"cve": {"id": "CVE-OTHER"}}]}
    with pytest.raises(ValueError, match="не збігається"):
        extract_record(payload, "CVE-TEST")


@pytest.mark.parametrize(
    "score, vector, expected_decision",
    [
        (7.0, "NETWORK", "review"),
        (9.8, "NETWORK", "review"),
        (6.9, "NETWORK", "other"),
        (9.8, "LOCAL", "other"),
    ],
)
def test_build_report_variant_1_rules(base_record, score, vector, expected_decision):
    record = copy.deepcopy(base_record)

    cvss_data = record["metrics"]["cvssMetricV31"][0]["cvssData"]
    if isinstance(cvss_data, dict):
        cvss_data["baseScore"] = score
        cvss_data["attackVector"] = vector

    report = build_report(record, "CVE-TEST", 1)
    assert report["decision"] == expected_decision


def test_build_report_not_found():
    report = build_report(None, "CVE-TEST", 1)
    assert report["decision"] == "not_found"


def test_build_report_rejected():
    record = {"vulnStatus": "Rejected"}
    report = build_report(record, "CVE-TEST", 1)
    assert report["decision"] == "rejected"
