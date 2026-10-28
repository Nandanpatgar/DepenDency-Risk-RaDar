from severity_analyzer import (
    classify_cvss_score,
    extract_severity,
)


def test_cvss_v3_classification():
    assert classify_cvss_score(9.8, "3") == "Critical"
    assert classify_cvss_score(8.1, "3") == "High"
    assert classify_cvss_score(5.4, "3") == "Medium"
    assert classify_cvss_score(2.5, "3") == "Low"
    assert classify_cvss_score(0.0, "3") == "None"

    print("PASS: CVSS v3 severity classifications")


def test_cvss_v4_classification():
    assert classify_cvss_score(9.5, "4") == "Critical"
    assert classify_cvss_score(8.0, "4") == "High"
    assert classify_cvss_score(5.0, "4") == "Medium"
    assert classify_cvss_score(2.0, "4") == "Low"
    assert classify_cvss_score(0.0, "4") == "None"

    print("PASS: CVSS v4 severity classifications")


def test_unknown_severity():
    result = extract_severity({
        "id": "TEST-UNKNOWN",
        "summary": "Example record without severity"
    })

    assert result["severity"] == "Unknown"
    assert result["score"] is None

    print("PASS: Missing severity handled correctly")


def test_database_severity_label():
    result = extract_severity({
        "id": "TEST-HIGH",
        "database_specific": {
            "severity": "HIGH"
        }
    })

    assert result["severity"] == "High"
    assert result["score"] is None

    print("PASS: Database-provided severity handled correctly")


if __name__ == "__main__":
    test_cvss_v3_classification()
    test_cvss_v4_classification()
    test_unknown_severity()
    test_database_severity_label()

    print("\nAll severity analyzer tests passed.")