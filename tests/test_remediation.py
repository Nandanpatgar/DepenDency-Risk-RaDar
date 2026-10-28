import json

from report_generator import (
    get_remediation_info,
    enrich_vulnerability,
    generate_json_report,
    generate_csv_report,
)


def test_extracts_fixed_version():
    vulnerability = {
        "id": "TEST-001",
        "affected": [
            {
                "package": {
                    "name": "example-package",
                    "ecosystem": "npm",
                },
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "2.5.0"},
                        ],
                    }
                ],
            }
        ],
    }

    result = get_remediation_info(vulnerability)

    assert result["fixed_versions"] == ["2.5.0"]
    assert result["remediation_status"] == (
        "Fixed version information available"
    )
    assert "2.5.0" in result["remediation"]


def test_handles_missing_fixed_version():
    vulnerability = {
        "id": "TEST-002",
        "affected": [
            {
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "0"},
                        ],
                    }
                ]
            }
        ],
    }

    result = get_remediation_info(vulnerability)

    assert result["fixed_versions"] == []
    assert result["remediation_status"] == (
        "Manual review required"
    )


def test_handles_missing_affected_data():
    result = get_remediation_info({})

    assert result["fixed_versions"] == []
    assert result["affected_ranges"] == []
    assert result["affected_versions"] == []
    assert result["remediation_status"] == (
        "Manual review required"
    )


def test_enrich_vulnerability_preserves_original_data():
    vulnerability = {
        "id": "TEST-003",
        "summary": "Example vulnerability",
        "affected": [
            {
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "1.0.0"},
                            {"fixed": "1.5.0"},
                        ],
                    }
                ]
            }
        ],
    }

    result = enrich_vulnerability(vulnerability)

    assert result["id"] == "TEST-003"
    assert result["summary"] == "Example vulnerability"
    assert result["fixed_versions"] == ["1.5.0"]
    assert "risk_severity" in result
    assert "cvss_score" in result


def test_json_report_contains_remediation():
    results = [
        {
            "Package": "example-package",
            "Version": "1.0.0",
            "Ecosystem": "npm",
            "Status": "Vulnerabilities Found",
            "Vulnerabilities": 1,
            "Details": [
                {
                    "id": "TEST-004",
                    "summary": "Test vulnerability",
                    "affected": [
                        {
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [
                                        {"introduced": "0"},
                                        {"fixed": "2.0.0"},
                                    ],
                                }
                            ]
                        }
                    ],
                }
            ],
        }
    ]

    report = json.loads(generate_json_report(results))

    vulnerability = report["dependencies"][0]["vulnerabilities"][0]

    assert vulnerability["fixed_versions"] == ["2.0.0"]
    assert vulnerability["recommended_action"]


def test_csv_report_contains_remediation_columns():
    results = [
        {
            "Package": "example-package",
            "Version": "1.0.0",
            "Ecosystem": "npm",
            "Status": "Vulnerabilities Found",
            "Vulnerabilities": 1,
            "Details": [
                {
                    "id": "TEST-005",
                    "summary": "Test vulnerability",
                    "affected": [
                        {
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [
                                        {"introduced": "0"},
                                        {"fixed": "2.0.0"},
                                    ],
                                }
                            ]
                        }
                    ],
                }
            ],
        }
    ]

    report = generate_csv_report(results)

    assert "Fixed Versions" in report
    assert "Recommended Actions" in report
    assert "2.0.0" in report