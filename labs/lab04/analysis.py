# ruff: noqa: TRY004
import math


def extract_record(payload: dict, cve_id: str) -> dict | None:
    """
    Перевіряє базову структуру відповіді NVD API.
    Повертає внутрішній запис (словник, що відповідає об'єкту cve)
    або None, якщо список vulnerabilities порожній.
    """
    if not isinstance(payload, dict) or "vulnerabilities" not in payload:
        raise ValueError(
            "Неправильна структура JSON: очікувався словник із ключем 'vulnerabilities'"
        )

    vulnerabilities = payload["vulnerabilities"]
    if not isinstance(vulnerabilities, list):
        raise ValueError("Поле 'vulnerabilities' має бути списком")

    if len(vulnerabilities) > 1:
        raise ValueError(
            "Очікується не більше одного елемента у списку vulnerabilities"
        )

    if not vulnerabilities:
        return None

    item = vulnerabilities[0]
    if not isinstance(item, dict):
        raise ValueError("Елемент 'vulnerabilities' має бути словником")

    cve_record = item.get("cve")
    if not isinstance(cve_record, dict):
        raise ValueError("Поле 'cve' має бути словником")

    if cve_record.get("id") != cve_id:
        raise ValueError("Отриманий ідентифікатор не збігається із запитаним")

    return cve_record


def build_report(record: dict | None, cve_id: str, variant: int) -> dict:
    """
    Аналізує внутрішній запис, вибирає оцінку CVSS v3.1
    і застосовує правило відповідно до варіанта.
    """
    report = {
        "cve_id": cve_id,
        "variant": variant,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": {"threshold": 7.0, "field": "attackVector", "expected": "NETWORK"},
        "observed": None,
        "decision": "other",
    }

    if record is None:
        report["decision"] = "not_found"
        return report

    descriptions = record.get("descriptions")
    if descriptions is not None:
        if not isinstance(descriptions, list):
            raise ValueError("descriptions має бути списком")
        for desc in descriptions:
            if not isinstance(desc, dict):
                raise ValueError("Елемент descriptions має бути словником")
            if desc.get("lang") == "en" and desc.get("value"):
                report["description"] = desc["value"]
                break

    if "vulnStatus" not in record:
        report["decision"] = "insufficient_data"
        return report

    vuln_status = record["vulnStatus"]
    if not isinstance(vuln_status, str) or not vuln_status:
        raise ValueError("vulnStatus має бути непорожнім рядком")

    report["vuln_status"] = vuln_status

    if vuln_status == "Rejected":
        report["decision"] = "rejected"
        return report

    if "metrics" not in record:
        report["decision"] = "insufficient_data"
        return report

    metrics = record["metrics"]
    if not isinstance(metrics, dict):
        raise ValueError("metrics має бути словником")

    if "cvssMetricV31" not in metrics:
        report["decision"] = "insufficient_data"
        return report

    cvss_metrics = metrics["cvssMetricV31"]
    if not isinstance(cvss_metrics, list):
        raise ValueError("cvssMetricV31 має бути списком")

    if not cvss_metrics:
        report["decision"] = "insufficient_data"
        return report

    chosen_metric = None
    for m in cvss_metrics:
        if not isinstance(m, dict):
            raise ValueError("Елемент cvssMetricV31 має бути словником")
        if m.get("type") == "Primary":
            chosen_metric = m
            break
    if chosen_metric is None:
        chosen_metric = cvss_metrics[0]

    if "cvssData" not in chosen_metric:
        raise ValueError("cvssData відсутній у вибраній оцінці")

    cvss_data = chosen_metric["cvssData"]
    if not isinstance(cvss_data, dict):
        raise ValueError("cvssData має бути словником")

    version = cvss_data.get("version")
    if version is not None:
        if version != "3.1":
            raise ValueError("version має дорівнювати '3.1'")
        report["cvss_version"] = version

    vector_string = cvss_data.get("vectorString")
    if vector_string is not None:
        if not isinstance(vector_string, str) or not vector_string:
            raise ValueError("vectorString має бути непорожнім рядком")
        report["vector"] = vector_string

    source = chosen_metric.get("source")
    if source is not None:
        if not isinstance(source, str) or not source:
            raise ValueError("source має бути непорожнім рядком")
        report["score_source"] = source

    if "baseScore" not in cvss_data:
        report["decision"] = "insufficient_data"
        return report

    score = cvss_data["baseScore"]
    if (
        not isinstance(score, (int, float))
        or isinstance(score, bool)
        or math.isnan(score)
        or math.isinf(score)
        or not (0 <= score <= 10)
    ):
        raise ValueError("baseScore має бути скінченним числом від 0 до 10")
    report["score"] = float(score)

    if "attackVector" not in cvss_data:
        report["decision"] = "insufficient_data"
        return report

    attack_vector = cvss_data["attackVector"]
    allowed_vectors = {"NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"}
    if attack_vector not in allowed_vectors:
        raise ValueError(f"attackVector має бути одним із {allowed_vectors}")
    report["observed"] = attack_vector

    score_val = report["score"]
    if isinstance(score_val, float) and score_val >= 7.0 and attack_vector == "NETWORK":
        report["decision"] = "review"

    return report
