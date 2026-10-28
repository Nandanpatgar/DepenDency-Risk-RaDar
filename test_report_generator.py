import csv
import io
import json

from report_generator import (
    generate_summary,
    generate_json_report,
    generate_csv_report,
    prioritize_vulnerabilities,
)


sample_results = [
    {
        "Package": "example-critical",
        "Version": "1.0.0",
        "Vulnerabilities": 1,
        "Details": [
            {
                "id": "TEST-CRITICAL",
                "summary": "Synthetic critical vulnerability",
                "severity": [
                    {
                        "type": "CVSS_V3",
                        "score": (
                            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/"
                            "S:U/C:H/I:H/A:H"
                        ),
                    }
                ],
                "references": [],
            }
        ],
        "Status": "Completed",
    },
    {
        "Package": "example-unknown",
        "Version": "1.0.0",
        "Vulnerabilities": 1,
        "Details": [
            {
                "id": "TEST-UNKNOWN",
                "summary": "Synthetic record without severity",
                "references": [],
            }
        ],
        "Status": "Completed",
    },
    {
        "Package": "example-failed",
        "Version": "1.0.0",
        "Vulnerabilities": None,
        "Details": [],
        "Status": "Scan failed",
    },
]


def test_summary():
    summary = generate_summary(sample_results)

    assert summary["total_dependencies"] == 3
    assert summary["successfully_scanned"] == 2
    assert summary["vulnerable_packages"] == 2
    assert summary["vulnerability_records"] == 2
    assert summary["failed_scans"] == 1

    assert summary["severity_counts"]["Critical"] == 1
    assert summary["severity_counts"]["Unknown"] == 1

    print("PASS: Summary and severity counts")


def test_json_report():
    report = json.loads(generate_json_report(sample_results))

    assert len(report["dependencies"]) == 3

    critical_vulnerability = (
        report["dependencies"][0]["vulnerabilities"][0]
    )

    assert critical_vulnerability["severity"] == "Critical"
    assert critical_vulnerability["cvss_score"] == 9.8

    print("PASS: JSON severity report")


def test_csv_report():
    csv_text = generate_csv_report(sample_results)

    rows = list(csv.DictReader(io.StringIO(csv_text)))

    assert len(rows) == 3
    assert rows[0]["Package"] == "example-critical"
    assert rows[0]["Highest Severity"] == "Critical"
    assert rows[1]["Highest Severity"] == "Unknown"
    assert rows[2]["Scan Status"] == "Scan failed"

    print("PASS: CSV severity report")


def test_prioritization():
    findings = prioritize_vulnerabilities(sample_results)

    assert findings[0]["Severity"] == "Critical"
    assert findings[0]["Vulnerability ID"] == "TEST-CRITICAL"

    assert findings[-1]["Severity"] == "Unknown"

    print("PASS: Vulnerability prioritization")


if __name__ == "__main__":
    test_summary()
    test_json_report()
    test_csv_report()
    test_prioritization()

    print("\nAll report generator tests passed.")