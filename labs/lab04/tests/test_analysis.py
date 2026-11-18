import copy
import math
from collections.abc import Callable
from typing import Any

import pytest

from labs.lab04.analysis import build_report, extract_record


@pytest.fixture
def base_record() -> dict[str, Any]:
    return {
        "id": "CVE-TEST",
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


def test_extract_record_empty():
    assert extract_record({"vulnerabilities": []}, "CVE-TEST") is None


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"vulnerabilities": {}},
        {"vulnerabilities": ["not_dict"]},
        {"vulnerabilities": [{}, {}]},
        {"vulnerabilities": [{"cve": []}]},
    ],
)
def test_extract_record_invalid_structure(payload):
    with pytest.raises(ValueError):
        extract_record(payload, "CVE-TEST")


@pytest.mark.parametrize(
    "score, vector, expected_decision",
    [
        (6.9, "NETWORK", "other"),
        (7.0, "NETWORK", "review"),
        (7.1, "NETWORK", "review"),
        (9.8, "NETWORK", "review"),
        (9.8, "LOCAL", "other"),
    ],
)
def test_build_report_variant_1_rules(
    base_record: dict[str, Any], score: float, vector: str, expected_decision: str
):
    record = copy.deepcopy(base_record)
    cvss_data = record["metrics"]["cvssMetricV31"][0]["cvssData"]
    if isinstance(cvss_data, dict):
        cvss_data["baseScore"] = score
        cvss_data["attackVector"] = vector

    report = build_report(record, "CVE-TEST", 1)
    assert report["decision"] == expected_decision


def test_build_report_insufficient_data(base_record: dict[str, Any]):
    rec1 = copy.deepcopy(base_record)
    rec1.pop("vulnStatus")
    assert build_report(rec1, "CVE-TEST", 1)["decision"] == "insufficient_data"

    rec2 = copy.deepcopy(base_record)
    rec2.pop("metrics")
    assert build_report(rec2, "CVE-TEST", 1)["decision"] == "insufficient_data"

    rec3 = copy.deepcopy(base_record)
    metrics = rec3.get("metrics")
    if isinstance(metrics, dict):
        metrics.pop("cvssMetricV31")
    assert build_report(rec3, "CVE-TEST", 1)["decision"] == "insufficient_data"

    rec4 = copy.deepcopy(base_record)
    metrics = rec4.get("metrics")
    if isinstance(metrics, dict):
        cvss_metrics = metrics.get("cvssMetricV31")
        if isinstance(cvss_metrics, list) and len(cvss_metrics) > 0:
            cvss_data = cvss_metrics[0].get("cvssData")
            if isinstance(cvss_data, dict):
                cvss_data.pop("baseScore")
    assert build_report(rec4, "CVE-TEST", 1)["decision"] == "insufficient_data"

    rec5 = copy.deepcopy(base_record)
    metrics = rec5.get("metrics")
    if isinstance(metrics, dict):
        cvss_metrics = metrics.get("cvssMetricV31")
        if isinstance(cvss_metrics, list) and len(cvss_metrics) > 0:
            cvss_data = cvss_metrics[0].get("cvssData")
            if isinstance(cvss_data, dict):
                cvss_data.pop("attackVector")
    assert build_report(rec5, "CVE-TEST", 1)["decision"] == "insufficient_data"


@pytest.mark.parametrize(
    "modify_func",
    [
        lambda r: r.update({"vulnStatus": ""}),
        lambda r: r.update({"vulnStatus": None}),
        lambda r: (
            r["metrics"]["cvssMetricV31"][0].update({"cvssData": None})
            if isinstance(r.get("metrics"), dict)
            and isinstance(r["metrics"].get("cvssMetricV31"), list)
            else None
        ),
        lambda r: (
            r["metrics"]["cvssMetricV31"][0]["cvssData"].update({"version": "2.0"})
            if isinstance(r.get("metrics"), dict)
            and isinstance(r["metrics"].get("cvssMetricV31"), list)
            and isinstance(r["metrics"]["cvssMetricV31"][0].get("cvssData"), dict)
            else None
        ),
        lambda r: (
            r["metrics"]["cvssMetricV31"][0]["cvssData"].update({"baseScore": "9.8"})
            if isinstance(r.get("metrics"), dict)
            and isinstance(r["metrics"].get("cvssMetricV31"), list)
            and isinstance(r["metrics"]["cvssMetricV31"][0].get("cvssData"), dict)
            else None
        ),
        lambda r: (
            r["metrics"]["cvssMetricV31"][0]["cvssData"].update({"baseScore": True})
            if isinstance(r.get("metrics"), dict)
            and isinstance(r["metrics"].get("cvssMetricV31"), list)
            and isinstance(r["metrics"]["cvssMetricV31"][0].get("cvssData"), dict)
            else None
        ),
        lambda r: (
            r["metrics"]["cvssMetricV31"][0]["cvssData"].update({"baseScore": None})
            if isinstance(r.get("metrics"), dict)
            and isinstance(r["metrics"].get("cvssMetricV31"), list)
            and isinstance(r["metrics"]["cvssMetricV31"][0].get("cvssData"), dict)
            else None
        ),
        lambda r: (
            r["metrics"]["cvssMetricV31"][0]["cvssData"].update({"baseScore": math.nan})
            if isinstance(r.get("metrics"), dict)
            and isinstance(r["metrics"].get("cvssMetricV31"), list)
            and isinstance(r["metrics"]["cvssMetricV31"][0].get("cvssData"), dict)
            else None
        ),
        lambda r: (
            r["metrics"]["cvssMetricV31"][0]["cvssData"].update({"baseScore": 11})
            if isinstance(r.get("metrics"), dict)
            and isinstance(r["metrics"].get("cvssMetricV31"), list)
            and isinstance(r["metrics"]["cvssMetricV31"][0].get("cvssData"), dict)
            else None
        ),
        lambda r: (
            r["metrics"]["cvssMetricV31"][0]["cvssData"].update(
                {"attackVector": "UNKNOWN"}
            )
            if isinstance(r.get("metrics"), dict)
            and isinstance(r["metrics"].get("cvssMetricV31"), list)
            and isinstance(r["metrics"]["cvssMetricV31"][0].get("cvssData"), dict)
            else None
        ),
        lambda r: (
            r["metrics"]["cvssMetricV31"][0]["cvssData"].update({"attackVector": None})
            if isinstance(r.get("metrics"), dict)
            and isinstance(r["metrics"].get("cvssMetricV31"), list)
            and isinstance(r["metrics"]["cvssMetricV31"][0].get("cvssData"), dict)
            else None
        ),
    ],
)
def test_build_report_value_errors(
    base_record: dict[str, Any], modify_func: Callable[[dict[str, Any]], None]
):
    record = copy.deepcopy(base_record)
    modify_func(record)
    with pytest.raises(ValueError):
        build_report(record, "CVE-TEST", 1)


def test_build_report_metric_selection(base_record: dict[str, Any]):
    record = copy.deepcopy(base_record)
    metrics = record.get("metrics")
    if isinstance(metrics, dict):
        cvss_metrics = metrics.get("cvssMetricV31")
        if isinstance(cvss_metrics, list) and len(cvss_metrics) > 0:
            sec_metric = copy.deepcopy(cvss_metrics[0])
            sec_metric["type"] = "Secondary"
            if isinstance(sec_metric.get("cvssData"), dict):
                sec_metric["cvssData"]["baseScore"] = 5.0

            prim_metric = copy.deepcopy(cvss_metrics[0])
            prim_metric["type"] = "Primary"
            if isinstance(prim_metric.get("cvssData"), dict):
                prim_metric["cvssData"]["baseScore"] = 9.8

            metrics["cvssMetricV31"] = [sec_metric, prim_metric]

            report = build_report(record, "CVE-TEST", 1)
            assert report["score"] == 9.8
            assert report["decision"] == "review"

            metrics["cvssMetricV31"] = [sec_metric]
            report2 = build_report(record, "CVE-TEST", 1)
            assert report2["score"] == 5.0
