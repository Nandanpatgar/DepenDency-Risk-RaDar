import csv
import io
import json
from datetime import datetime, timezone

from severity_analyzer import extract_severity


SEVERITY_ORDER = {
    "Critical": 5,
    "High": 4,
    "Medium": 3,
    "Low": 2,
    "None": 1,
    "Unknown": 0,
}


def enrich_vulnerability(vulnerability):
    """
    Add severity information to a vulnerability record
    while preserving the original OSV data.
    """

    severity_info = extract_severity(vulnerability)

    enriched = dict(vulnerability)
    enriched["risk_severity"] = severity_info["severity"]
    enriched["cvss_score"] = severity_info["score"]
    enriched["severity_source"] = severity_info["source"]

    return enriched


def enrich_results(results):
    """
    Enrich scan results with severity information.

    Each vulnerability receives a severity classification,
    CVSS score when available, and severity source.
    """

    enriched_results = []

    for result in results:
        enriched_result = dict(result)

        details = result.get("Details", [])

        enriched_result["Details"] = [
            enrich_vulnerability(vulnerability)
            for vulnerability in details
        ]

        enriched_results.append(enriched_result)

    return enriched_results


def generate_summary(results):
    """
    Calculate dashboard metrics and severity counts.

    Accepts raw scan results or results that have already
    been enriched.
    """

    # Ensure severity information exists before calculating metrics.
    results = enrich_results(results)

    successful = [
        result
        for result in results
        if result.get("Status") == "Completed"
    ]

    failed = [
        result
        for result in results
        if result.get("Status") != "Completed"
    ]

    vulnerable = [
        result
        for result in successful
        if (result.get("Vulnerabilities") or 0) > 0
    ]

    total_records = sum(
        result.get("Vulnerabilities") or 0
        for result in successful
    )

    severity_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "None": 0,
        "Unknown": 0,
    }

    for result in successful:
        for vulnerability in result.get("Details", []):
            severity = vulnerability.get(
                "risk_severity",
                "Unknown",
            )

            if severity not in severity_counts:
                severity = "Unknown"

            severity_counts[severity] += 1

    return {
        "total_dependencies": len(results),
        "successfully_scanned": len(successful),
        "vulnerable_packages": len(vulnerable),
        "vulnerability_records": total_records,
        "failed_scans": len(failed),
        "severity_counts": severity_counts,
    }


def prioritize_vulnerabilities(results):
    """
    Flatten vulnerability records and sort them by severity.

    Higher-severity findings appear first. Unknown findings
    remain visible without receiving an invented severity score.
    """

    results = enrich_results(results)
    findings = []

    for result in results:

        if result.get("Status") != "Completed":
            continue

        for vulnerability in result.get("Details", []):

            findings.append({
                "Package": result.get("Package"),
                "Version": result.get("Version"),
                "Vulnerability ID": vulnerability.get("id"),
                "Summary": vulnerability.get("summary"),
                "Severity": vulnerability.get(
                    "risk_severity",
                    "Unknown",
                ),
                "CVSS Score": vulnerability.get("cvss_score"),
                "Severity Source": vulnerability.get(
                    "severity_source",
                    "No usable severity information",
                ),
                "References": [
                    reference.get("url")
                    for reference in vulnerability.get("references", [])
                    if reference.get("url")
                ],
            })

    findings.sort(
        key=lambda finding: (
            SEVERITY_ORDER.get(finding["Severity"], 0),
            (
                finding["CVSS Score"]
                if finding["CVSS Score"] is not None
                else -1
            ),
        ),
        reverse=True,
    )

    return findings


def generate_json_report(results, ecosystem="npm"):
    """Generate a downloadable JSON security report."""

    enriched_results = enrich_results(results)

    report = {
        "project": "Dependency Risk Radar",
        "ecosystem": ecosystem,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": generate_summary(enriched_results),
        "dependencies": [],
        "prioritized_findings": prioritize_vulnerabilities(
            enriched_results
        ),
    }

    for result in enriched_results:

        dependency = {
            "package": result.get("Package"),
            "version": result.get("Version"),
            "scan_status": result.get("Status"),
            "vulnerability_records": result.get("Vulnerabilities"),
            "vulnerabilities": [],
        }

        for vulnerability in result.get("Details", []):

            dependency["vulnerabilities"].append({
                "id": vulnerability.get("id"),
                "summary": vulnerability.get("summary"),
                "severity": vulnerability.get("risk_severity"),
                "cvss_score": vulnerability.get("cvss_score"),
                "severity_source": vulnerability.get(
                    "severity_source"
                ),
                "aliases": vulnerability.get("aliases", []),
                "references": [
                    reference.get("url")
                    for reference in vulnerability.get("references", [])
                    if reference.get("url")
                ],
            })

        report["dependencies"].append(dependency)

    return json.dumps(report, indent=2)


def generate_csv_report(results):
    """Generate a CSV report containing dependency severity details."""

    enriched_results = enrich_results(results)

    output = io.StringIO()

    fieldnames = [
        "Package",
        "Version",
        "Scan Status",
        "Vulnerability Records",
        "Highest Severity",
        "Highest CVSS Score",
        "Vulnerability IDs",
    ]

    writer = csv.DictWriter(
        output,
        fieldnames=fieldnames,
    )

    writer.writeheader()

    for result in enriched_results:

        details = result.get("Details", [])

        if details:
            highest_severity = max(
                details,
                key=lambda vulnerability: (
                    SEVERITY_ORDER.get(
                        vulnerability.get("risk_severity", "Unknown"),
                        0,
                    ),
                    (
                        vulnerability.get("cvss_score")
                        if vulnerability.get("cvss_score") is not None
                        else -1
                    ),
                ),
            )

            severity_label = highest_severity.get(
                "risk_severity",
                "Unknown",
            )

            cvss_score = highest_severity.get("cvss_score")

            vulnerability_ids = [
                vulnerability.get("id", "Unknown")
                for vulnerability in details
            ]

        else:
            severity_label = "Unknown"
            cvss_score = ""
            vulnerability_ids = []

        writer.writerow({
            "Package": result.get("Package", ""),
            "Version": result.get("Version", ""),
            "Scan Status": result.get("Status", "Unknown"),
            "Vulnerability Records": result.get("Vulnerabilities"),
            "Highest Severity": severity_label,
            "Highest CVSS Score": cvss_score,
            "Vulnerability IDs": "; ".join(vulnerability_ids),
        })

    return output.getvalue()