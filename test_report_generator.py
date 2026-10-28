from report_generator import (
    generate_summary,
    generate_json_report,
    generate_csv_report
)

import json
import csv
import io


sample_results = [
    {
        "Package": "lodash",
        "Version": "4.17.20",
        "Vulnerabilities": 2,
        "Details": [
            {
                "id": "GHSA-TEST-001",
                "summary": "Example vulnerability",
                "aliases": ["CVE-TEST-001"],
                "references": [
                    {"url": "https://example.com/advisory"}
                ]
            },
            {
                "id": "GHSA-TEST-002",
                "summary": "Another example vulnerability",
                "aliases": [],
                "references": []
            }
        ],
        "Status": "Completed"
    },
    {
        "Package": "express",
        "Version": "4.17.1",
        "Vulnerabilities": 0,
        "Details": [],
        "Status": "Completed"
    },
    {
        "Package": "minimist",
        "Version": "1.2.5",
        "Vulnerabilities": None,
        "Details": [],
        "Status": "Scan failed"
    }
]


def test_summary():
    summary = generate_summary(sample_results)

    assert summary["total_dependencies"] == 3
    assert summary["successfully_scanned"] == 2
    assert summary["vulnerable_packages"] == 1
    assert summary["vulnerability_records"] == 2
    assert summary["failed_scans"] == 1

    print("PASS: Summary calculations")


def test_json_report():
    report_text = generate_json_report(sample_results)
    report = json.loads(report_text)

    assert report["project"] == "Dependency Risk Radar"
    assert len(report["dependencies"]) == 3
    assert report["summary"]["failed_scans"] == 1

    print("PASS: JSON report generation")


def test_csv_report():
    csv_text = generate_csv_report(sample_results)

    rows = list(csv.DictReader(io.StringIO(csv_text)))

    assert len(rows) == 3
    assert rows[0]["Package"] == "lodash"
    assert rows[2]["Scan Status"] == "Scan failed"

    print("PASS: CSV report generation")


if __name__ == "__main__":
    test_summary()
    test_json_report()
    test_csv_report()

    print("\nAll report generator tests passed.")