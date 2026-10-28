from cvss import CVSS3, CVSS4


def classify_cvss_score(score, version):
    """
    Classify a CVSS score using the appropriate severity bands.

    CVSS v3.x and CVSS v4.0 use different scoring scales,
    so this function handles their classifications separately.
    """

    if score is None:
        return "Unknown"

    if version == "3":
        if score == 0:
            return "None"
        elif score < 4.0:
            return "Low"
        elif score < 7.0:
            return "Medium"
        elif score < 9.0:
            return "High"
        return "Critical"

    if version == "4":
        if score == 0:
            return "None"
        elif score < 4.0:
            return "Low"
        elif score < 7.0:
            return "Medium"
        elif score < 9.0:
            return "High"
        return "Critical"

    return "Unknown"


def extract_severity(vulnerability):
    """
    Extract severity from an OSV vulnerability record.

    Returns:
        {
            "score": float or None,
            "severity": str,
            "source": str
        }

    Severity remains Unknown when the record does not provide
    sufficient information to classify it reliably.
    """

    # First, inspect the CVSS vectors supplied by OSV.
    severity_entries = vulnerability.get("severity", [])

    for entry in severity_entries:
        vector = entry.get("score", "")
        vector_type = entry.get("type", "")

        if not isinstance(vector, str):
            continue

        try:
            if vector_type == "CVSS_V3":
                cvss = CVSS3(vector)
                score = float(cvss.scores()[0])

                return {
                    "score": score,
                    "severity": classify_cvss_score(score, "3"),
                    "source": "CVSS v3"
                }

            elif vector_type == "CVSS_V4":
                cvss = CVSS4(vector)
                score = float(cvss.scores()[0])

                return {
                    "score": score,
                    "severity": classify_cvss_score(score, "4"),
                    "source": "CVSS v4"
                }

        except (ValueError, TypeError, IndexError):
            # An invalid vector should not crash the entire scan.
            continue

    # Next, check whether the database provides an explicit
    # severity label.
    database_specific = vulnerability.get("database_specific", {})

    if isinstance(database_specific, dict):
        severity_label = database_specific.get("severity")

        if isinstance(severity_label, str):
            normalized = severity_label.strip().upper()

            valid_labels = {
                "CRITICAL",
                "HIGH",
                "MEDIUM",
                "MODERATE",
                "LOW",
                "NONE"
            }

            if normalized in valid_labels:
                if normalized == "MODERATE":
                    normalized = "MEDIUM"

                return {
                    "score": None,
                    "severity": normalized.title(),
                    "source": "Database-provided label"
                }

    # Do not invent severity if the record has no usable data.
    return {
        "score": None,
        "severity": "Unknown",
        "source": "No usable severity information"
    }