import csv
import io
import json
from datetime import datetime, timezone

from severity_analyzer import extract_severity


# Higher values indicate higher severity.
SEVERITY_ORDER = {
    "Critical": 5,
    "High": 4,
    "Medium": 3,
    "Low": 2,
    "None": 1,
    "Unknown": 0,
}


# =========================================================
# REMEDIATION ANALYSIS
# =========================================================

def get_remediation_info(vulnerability):
    """
    Extract affected-version and remediation information
    from an OSV vulnerability record.

    Fixed versions are taken from OSV's affected ranges.
    No fixed version is invented when information is missing.
    """

    fixed_versions = set()
    affected_ranges = set()
    affected_versions = set()

    affected_entries = vulnerability.get("affected", [])

    if not isinstance(affected_entries, list):
        affected_entries = []

    for affected in affected_entries:

        if not isinstance(affected, dict):
            continue

        # Extract explicitly listed affected versions.
        versions = affected.get("versions", [])

        if isinstance(versions, list):
            for version in versions:
                if version is not None:
                    affected_versions.add(str(version))

        ranges = affected.get("ranges", [])

        if not isinstance(ranges, list):
            continue

        for version_range in ranges:

            if not isinstance(version_range, dict):
                continue

            range_type = version_range.get("type", "Unknown")
            events = version_range.get("events", [])

            if not isinstance(events, list):
                continue

            introduced_versions = []
            fixed_in_range = []

            for event in events:

                if not isinstance(event, dict):
                    continue

                introduced = event.get("introduced")
                fixed = event.get("fixed")
                last_affected = event.get("last_affected")

                if introduced is not None:
                    introduced_versions.append(str(introduced))

                if fixed is not None:
                    fixed = str(fixed)
                    fixed_versions.add(fixed)
                    fixed_in_range.append(fixed)

                if last_affected is not None:
                    last_affected = str(last_affected)

                    affected_ranges.add(
                        f"{range_type}: last affected {last_affected}"
                    )

            # Preserve the version-range information for the report.
            if introduced_versions or fixed_in_range:

                start = (
                    introduced_versions[0]
                    if introduced_versions
                    else "Not specified"
                )

                end = (
                    fixed_in_range[-1]
                    if fixed_in_range
                    else "No fixed version listed"
                )

                affected_ranges.add(
                    f"{range_type}: introduced {start}, fixed {end}"
                )

    fixed_versions = sorted(fixed_versions)
    affected_ranges = sorted(affected_ranges)
    affected_versions = sorted(affected_versions)

    if fixed_versions:
        remediation = (
            "OSV lists the following fixed version(s): "
            + ", ".join(fixed_versions)
            + ". Review the affected version ranges and package "
              "compatibility before upgrading. Run your project's "
              "tests after applying the update."
        )

        remediation_status = "Fixed version information available"

    else:
        remediation = (
            "No fixed version was identified in the available OSV "
            "affected-version data. Review the advisory references "
            "and check for vendor-recommended updates or mitigations."
        )

        remediation_status = "Manual review required"

    return {
        "fixed_versions": fixed_versions,
        "affected_ranges": affected_ranges,
        "affected_versions": affected_versions,
        "remediation": remediation,
        "remediation_status": remediation_status,
    }


# =========================================================
# VULNERABILITY ENRICHMENT
# =========================================================

def enrich_vulnerability(vulnerability):
    """
    Enrich an OSV vulnerability record with severity,
    CVSS, and remediation information.

    Original OSV fields are preserved.
    """

    severity_info = extract_severity(vulnerability)
    remediation_info = get_remediation_info(vulnerability)

    enriched = dict(vulnerability)

    enriched["risk_severity"] = severity_info["severity"]
    enriched["cvss_score"] = severity_info["score"]
    enriched["severity_source"] = severity_info["source"]

    enriched.update(remediation_info)

    return enriched


def enrich_results(results):
    """
    Enrich scan results with severity and remediation information.
    """

    enriched_results = []

    for result in results:

        enriched_result = dict(result)
        details = result.get("Details", [])

        if not isinstance(details, list):
            details = []

        enriched_result["Details"] = [
            enrich_vulnerability(vulnerability)
            for vulnerability in details
            if isinstance(vulnerability, dict)
        ]

        enriched_results.append(enriched_result)

    return enriched_results


# =========================================================
# SUMMARY GENERATION
# =========================================================

def generate_summary(results):
    """
    Calculate scan metrics and vulnerability severity counts.

    Accepts raw results or previously enriched results.
    """

    results = enrich_results(results)

    successful = [
        result
        for result in results
        if result.get("Status") in {
            "Completed",
            "Vulnerabilities Found",
            "No Known Vulnerabilities Found",
        }
    ]

    failed = [
        result
        for result in results
        if result not in successful
    ]

    vulnerable = [
        result
        for result in successful
        if result.get("Details")
    ]

    total_records = sum(
        len(result.get("Details", []))
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


# =========================================================
# VULNERABILITY PRIORITIZATION
# =========================================================

def prioritize_vulnerabilities(results):
    """
    Flatten vulnerability records and prioritize by severity
    and available CVSS score.

    Includes remediation guidance in each finding.
    """

    results = enrich_results(results)
    findings = []

    for result in results:

        if result.get("Status") not in {
            "Completed",
            "Vulnerabilities Found",
            "No Known Vulnerabilities Found",
        }:
            continue

        for vulnerability in result.get("Details", []):

            findings.append({
                "Package": result.get("Package"),
                "Version": result.get("Version"),
                "Ecosystem": result.get("Ecosystem"),
                "Vulnerability ID": (
                    vulnerability.get("id")
                    or vulnerability.get("ID")
                    or "Unknown"
                ),
                "Summary": (
                    vulnerability.get("summary")
                    or vulnerability.get("details")
                    or "No description available"
                ),
                "Severity": vulnerability.get(
                    "risk_severity",
                    "Unknown",
                ),
                "CVSS Score": vulnerability.get("cvss_score"),
                "Severity Source": vulnerability.get(
                    "severity_source",
                    "No usable severity information",
                ),
                "Affected Versions": vulnerability.get(
                    "affected_versions",
                    [],
                ),
                "Affected Ranges": vulnerability.get(
                    "affected_ranges",
                    [],
                ),
                "Fixed Versions": vulnerability.get(
                    "fixed_versions",
                    [],
                ),
                "Remediation Status": vulnerability.get(
                    "remediation_status",
                    "Manual review required",
                ),
                "Recommended Action": vulnerability.get(
                    "remediation",
                    "Review the original advisory.",
                ),
                "References": [
                    reference.get("url")
                    for reference in vulnerability.get(
                        "references", []
                    )
                    if isinstance(reference, dict)
                    and reference.get("url")
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


# =========================================================
# JSON REPORT
# =========================================================

def generate_json_report(results, ecosystem="npm"):
    """
    Generate a JSON report containing:
    - Scan summary
    - Dependency inventory
    - Severity information
    - Affected and fixed versions
    - Remediation recommendations
    - Prioritized vulnerability findings
    """

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
            "ecosystem": result.get("Ecosystem", ecosystem),
            "scan_status": result.get("Status"),
            "scan_error": result.get("Error"),
            "vulnerability_records": len(
                result.get("Details", [])
            ),
            "vulnerabilities": [],
        }

        for vulnerability in result.get("Details", []):

            dependency["vulnerabilities"].append({
                "id": (
                    vulnerability.get("id")
                    or vulnerability.get("ID")
                    or "Unknown"
                ),
                "summary": (
                    vulnerability.get("summary")
                    or vulnerability.get("details")
                    or "No description available"
                ),
                "severity": vulnerability.get("risk_severity"),
                "cvss_score": vulnerability.get("cvss_score"),
                "severity_source": vulnerability.get(
                    "severity_source"
                ),
                "aliases": vulnerability.get("aliases", []),
                "affected_versions": vulnerability.get(
                    "affected_versions", []
                ),
                "affected_ranges": vulnerability.get(
                    "affected_ranges", []
                ),
                "fixed_versions": vulnerability.get(
                    "fixed_versions", []
                ),
                "remediation_status": vulnerability.get(
                    "remediation_status"
                ),
                "recommended_action": vulnerability.get(
                    "remediation"
                ),
                "references": [
                    reference.get("url")
                    for reference in vulnerability.get(
                        "references", []
                    )
                    if isinstance(reference, dict)
                    and reference.get("url")
                ],
            })

        report["dependencies"].append(dependency)

    return json.dumps(report, indent=2)


# =========================================================
# CSV REPORT
# =========================================================

def generate_csv_report(results):
    """
    Generate a CSV report containing dependency,
    severity, and remediation information.
    """

    enriched_results = enrich_results(results)

    output = io.StringIO()

    fieldnames = [
        "Package",
        "Version",
        "Ecosystem",
        "Scan Status",
        "Vulnerability Records",
        "Highest Severity",
        "Highest CVSS Score",
        "Vulnerability IDs",
        "Fixed Versions",
        "Remediation Status",
        "Recommended Actions",
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
                        vulnerability.get(
                            "risk_severity",
                            "Unknown",
                        ),
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
                str(
                    vulnerability.get("id")
                    or vulnerability.get("ID")
                    or "Unknown"
                )
                for vulnerability in details
            ]

            fixed_versions = sorted({
                str(version)
                for vulnerability in details
                for version in vulnerability.get(
                    "fixed_versions", []
                )
            })

            remediation_actions = [
                vulnerability.get("remediation", "")
                for vulnerability in details
                if vulnerability.get("remediation")
            ]

            remediation_status = (
                "Fixed version information available"
                if fixed_versions
                else "Manual review required"
            )

        else:
            severity_label = "Unknown"
            cvss_score = ""
            vulnerability_ids = []
            fixed_versions = []
            remediation_actions = []
            remediation_status = "No vulnerability findings"

        writer.writerow({
            "Package": result.get("Package", ""),
            "Version": result.get("Version", ""),
            "Ecosystem": result.get("Ecosystem", ""),
            "Scan Status": result.get("Status", "Unknown"),
            "Vulnerability Records": len(details),
            "Highest Severity": severity_label,
            "Highest CVSS Score": cvss_score,
            "Vulnerability IDs": "; ".join(vulnerability_ids),
            "Fixed Versions": "; ".join(fixed_versions),
            "Remediation Status": remediation_status,
            "Recommended Actions": " | ".join(remediation_actions),
        })

    return output.getvalue()