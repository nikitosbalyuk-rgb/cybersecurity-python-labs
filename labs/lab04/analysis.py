def extract_record(payload, cve_id):
    if not isinstance(payload, dict) or "vulnerabilities" not in payload:
        raise ValueError(
            "Неправильна структура JSON: очікувався словник із ключем 'vulnerabilities'"
        )

    vulnerabilities = payload["vulnerabilities"]
    if not vulnerabilities:
        return None

    cve_record = vulnerabilities[0].get("cve", {})
    if cve_record.get("id") != cve_id:
        raise ValueError("Отриманий ідентифікатор не збігається із запитаним")

    return cve_record


def build_report(record, cve_id, variant):
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

    for desc in record.get("descriptions", []):
        if desc.get("lang") == "en" and desc.get("value"):
            report["description"] = desc["value"]
            break

    vuln_status = record.get("vulnStatus")
    if vuln_status:
        report["vuln_status"] = vuln_status
    else:
        report["decision"] = "insufficient_data"
        return report

    if vuln_status == "Rejected":
        report["decision"] = "rejected"
        return report

    metrics = record.get("metrics", {})
    cvss_metrics = metrics.get("cvssMetricV31", [])

    if not isinstance(cvss_metrics, list):
        raise ValueError("cvssMetricV31 має бути списком")

    if not cvss_metrics:
        report["decision"] = "insufficient_data"
        return report

    chosen_metric = next(
        (m for m in cvss_metrics if m.get("type") == "Primary"), cvss_metrics[0]
    )
    cvss_data = chosen_metric.get("cvssData", {})

    report["cvss_version"] = cvss_data.get("version")
    report["vector"] = cvss_data.get("vectorString")
    report["score_source"] = chosen_metric.get("source")

    if report["cvss_version"] != "3.1":
        report["decision"] = "insufficient_data"
        return report

    score = cvss_data.get("baseScore")
    if score is None:
        report["decision"] = "insufficient_data"
        return report

    if (
        not isinstance(score, (int, float))
        or isinstance(score, bool)
        or not (0 <= score <= 10)
    ):
        raise ValueError("Оцінка baseScore має бути числом від 0 до 10")

    report["score"] = score

    attack_vector = cvss_data.get("attackVector")
    if attack_vector is None:
        report["decision"] = "insufficient_data"
        return report

    report["observed"] = attack_vector

    if score >= 7.0 and attack_vector == "NETWORK":
        report["decision"] = "review"

    return report
