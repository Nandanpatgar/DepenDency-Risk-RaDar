import csv
import io
import json
from datetime import datetime, timezone


def generate_summary(results):
    """
    Calculate summary metrics from dependency scan results.
    """

    successful = [
        result for result in results
        if result.get("Status") == "Completed"
    ]

    failed = [
        result for result in results
        if result.get("Status") != "Completed"
    ]

    vulnerable = [
        result for result in successful
        if (result.get("Vulnerabilities") or 0) > 0
    ]

    total_records = sum(
        result.get("Vulnerabilities") or 0
        for result in successful
    )

    return {
        "total_dependencies": len(results),
        "successfully_scanned": len(successful),
        "vulnerable_packages": len(vulnerable),
        "vulnerability_records": total_records,
        "failed_scans": len(failed),
    }


def generate_json_report(results, ecosystem="npm"):
    """
    Generate a downloadable JSON report.
    """

    report = {
        "project": "Dependency Risk Radar",
        "ecosystem": ecosystem,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": generate_summary(results),
        "dependencies": []
    }

    for result in results:
        dependency = {
            "package": result.get("Package"),
            "version": result.get("Version"),
            "scan_status": result.get("Status"),
            "vulnerability_records": result.get("Vulnerabilities"),
            "vulnerabilities": []
        }

        for vulnerability in result.get("Details", []):
            dependency["vulnerabilities"].append({
                "id": vulnerability.get("id"),
                "summary": vulnerability.get("summary"),
                "aliases": vulnerability.get("aliases", []),
                "references": [
                    reference.get("url")
                    for reference in vulnerability.get("references", [])
                    if reference.get("url")
                ]
            })

        report["dependencies"].append(dependency)

    return json.dumps(report, indent=2)


def generate_csv_report(results):
    """
    Generate a CSV report with one row per dependency.
    """

    output = io.StringIO()

    fieldnames = [
        "Package",
        "Version",
        "Scan Status",
        "Vulnerability Records",
        "Vulnerability IDs"
    ]

    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for result in results:
        vulnerability_ids = [
            vulnerability.get("id", "Unknown")
            for vulnerability in result.get("Details", [])
        ]

        writer.writerow({
            "Package": result.get("Package", ""),
            "Version": result.get("Version", ""),
            "Scan Status": result.get("Status", "Unknown"),
            "Vulnerability Records": result.get("Vulnerabilities", ""),
            "Vulnerability IDs": "; ".join(vulnerability_ids)
        })

    return output.getvalue()