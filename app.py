
import json
import re
from collections import Counter

import pandas as pd
import requests
import streamlit as st

from node_scanner import parse_package_lock
from report_generator import (
    generate_summary,
    prioritize_vulnerabilities,
    generate_json_report,
    generate_csv_report,
)

# =========================================================
# CONFIGURATION
# =========================================================

OSV_API_URL = "https://api.osv.dev/v1/query"
REQUEST_TIMEOUT = 20

st.set_page_config(
    page_title="Dependency Risk Radar",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# =========================================================
# OPTIONAL SEVERITY ANALYZER
# =========================================================

try:
    from severity_analyzer import analyze_severity

    SEVERITY_ANALYZER_AVAILABLE = True

except ImportError:
    analyze_severity = None
    SEVERITY_ANALYZER_AVAILABLE = False


# =========================================================
# STYLING
# =========================================================

st.markdown(
    """
    <style>
        .stApp {
            background-color: #0b1120;
            color: #e5edf8;
        }

        [data-testid="stHeader"] {
            background: rgba(11, 17, 32, 0.9);
        }

        [data-testid="stSidebar"] {
            background-color: #0e1728;
            border-right: 1px solid #263650;
        }

        .block-container {
            max-width: 1450px;
            padding-top: 2rem;
            padding-bottom: 3rem;
        }

        h1, h2, h3 {
            color: #f1f5f9 !important;
        }

        p, label {
            color: #d7e2f0;
        }

        .hero {
            padding: 30px;
            border-radius: 18px;
            background:
                radial-gradient(
                    circle at 90% 10%,
                    rgba(56, 189, 248, 0.16),
                    transparent 35%
                ),
                linear-gradient(135deg, #14233a, #101827);
            border: 1px solid #263a55;
            margin-bottom: 28px;
        }

        .hero-eyebrow {
            color: #38bdf8;
            font-size: 0.78rem;
            font-weight: 700;
            letter-spacing: 2px;
            text-transform: uppercase;
            margin-bottom: 10px;
        }

        .hero-title {
            color: #f8fafc;
            font-size: 2.2rem;
            font-weight: 800;
            line-height: 1.2;
            margin-bottom: 12px;
        }

        .hero-description {
            color: #a8b8cc;
            font-size: 1rem;
            line-height: 1.7;
            max-width: 800px;
        }

        .section-label {
            color: #38bdf8;
            font-size: 0.75rem;
            font-weight: 700;
            letter-spacing: 1.6px;
            text-transform: uppercase;
            margin-bottom: 8px;
        }

        .info-card {
            background: #111b2e;
            border: 1px solid #263650;
            border-radius: 14px;
            padding: 18px;
            margin-bottom: 12px;
        }

        .info-card-title {
            color: #f1f5f9;
            font-size: 1rem;
            font-weight: 700;
            margin-bottom: 7px;
        }

        .info-card-text {
            color: #a8b8cc;
            font-size: 0.88rem;
            line-height: 1.6;
        }

        [data-testid="stMetric"] {
            background: #111b2e;
            border: 1px solid #263650;
            border-radius: 14px;
            padding: 18px;
        }

        [data-testid="stMetricLabel"] {
            color: #a8b8cc !important;
        }

        [data-testid="stMetricValue"] {
            color: #f8fafc !important;
            font-weight: 800;
        }

        .stButton > button,
        .stDownloadButton > button {
            min-height: 42px;
            border-radius: 9px;
            font-weight: 650;
            border: 1px solid #334b68;
        }

        .stButton > button[kind="primary"] {
            background: #0284c7;
            border-color: #0284c7;
            color: white;
        }

        [data-testid="stFileUploader"] {
            background: #111b2e;
            border: 1px dashed #3a526e;
            border-radius: 12px;
            padding: 10px;
        }

        [data-testid="stDataFrame"] {
            border: 1px solid #263650;
            border-radius: 10px;
            overflow: hidden;
        }

        .stTabs [data-baseweb="tab-list"] {
            gap: 12px;
            border-bottom: 1px solid #263650;
        }

        .stTabs [data-baseweb="tab"] {
            padding: 12px 18px;
            color: #91a1b8;
        }

        .stTabs [aria-selected="true"] {
            color: #38bdf8 !important;
        }

        hr {
            border-color: #263650;
        }
    </style>
    """,
    unsafe_allow_html=True,
)

# =========================================================
# SESSION STATE
# =========================================================

DEFAULT_STATE = {
    "python_scan_results": None,
    "node_scan_results": None,
    "python_scan_name": None,
    "node_scan_name": None,
    "selected_scanner": None,
}

for key, default in DEFAULT_STATE.items():
    if key not in st.session_state:
        st.session_state[key] = default

# =========================================================
# HEADER
# =========================================================

st.markdown(
    """
    <div class="hero">
        <div class="hero-eyebrow">
            Application Security · Dependency Intelligence
        </div>
        <div class="hero-title">
            Dependency Risk Radar
        </div>
        <div class="hero-description">
            Identify known vulnerabilities in software dependencies.
            Scan Python packages and Node.js projects, review severity,
            prioritize findings, and export security reports.
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# =========================================================
# SEVERITY NORMALIZATION
# =========================================================

def normalize_severity(value):
    """Normalize severity labels into consistent categories."""

    if not value:
        return "Unknown"

    text = str(value).strip().lower()

    aliases = {
        "critical": "Critical",
        "crit": "Critical",
        "high": "High",
        "important": "High",
        "medium": "Medium",
        "moderate": "Medium",
        "warning": "Medium",
        "low": "Low",
        "negligible": "Low",
        "unknown": "Unknown",
        "none": "Unknown",
        "null": "Unknown",
    }

    if text in aliases:
        return aliases[text]

    # Recognize CVSS vector strings.
    if text.startswith("cvss:"):
        score = calculate_cvss_score(text)

        if score is not None:
            return severity_from_score(score)

    return "Unknown"


def calculate_cvss_score(vector):
    """
    Calculate a score from a CVSS vector using the optional cvss package.

    Returns None if the vector cannot be evaluated.
    """

    if not isinstance(vector, str):
        return None

    try:
        from cvss import CVSS2, CVSS3, CVSS4

        if vector.startswith("CVSS:4."):
            return float(CVSS4(vector).scores()[0])

        if vector.startswith("CVSS:3."):
            return float(CVSS3(vector).scores()[0])

        if vector.startswith("CVSS:2."):
            return float(CVSS2(vector).scores()[0])

    except Exception:
        return None

    return None


def severity_from_score(score):
    """Map a numerical CVSS score to a severity category."""

    if score is None:
        return "Unknown"

    try:
        score = float(score)
    except (TypeError, ValueError):
        return "Unknown"

    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"

    return "Unknown"


def get_cvss_information(vulnerability):
    """
    Extract severity and CVSS score from common OSV vulnerability formats.

    Supports OSV severity vectors and database_specific severity/score data.
    """

    database_specific = vulnerability.get("database_specific") or {}

    if not isinstance(database_specific, dict):
        database_specific = {}

    severity = normalize_severity(
        database_specific.get("severity")
    )

    raw_score = (
        database_specific.get("cvss")
        or database_specific.get("cvss_score")
        or database_specific.get("cvssScore")
    )

    score = None

    if isinstance(raw_score, (int, float)):
        score = float(raw_score)

    elif isinstance(raw_score, str):
        try:
            score = float(raw_score)
        except ValueError:
            score = calculate_cvss_score(raw_score)

    vectors = vulnerability.get("severity") or []

    if isinstance(vectors, dict):
        vectors = [vectors]

    if isinstance(vectors, list):
        for entry in vectors:
            if not isinstance(entry, dict):
                continue

            vector = entry.get("score")

            if not vector:
                continue

            calculated_score = calculate_cvss_score(vector)

            if calculated_score is not None:
                score = calculated_score
                break

    if score is not None:
        severity = severity_from_score(score)

    if severity == "Unknown" and SEVERITY_ANALYZER_AVAILABLE:
        try:
            analysis = analyze_severity(vulnerability)

            if isinstance(analysis, dict):
                severity = normalize_severity(
                    analysis.get("risk_severity")
                    or analysis.get("severity")
                )

                if score is None:
                    candidate = analysis.get("cvss_score")

                    if candidate is not None:
                        score = float(candidate)

        except Exception:
            pass

    return severity, score


def enrich_findings(results):
    """
    Create a flattened list of vulnerability records.

    Severity is calculated for each vulnerability independently.
    """

    findings = []

    for result in results:
        details = result.get("Details", []) or []

        if not isinstance(details, list):
            continue

        for vulnerability in details:
            if not isinstance(vulnerability, dict):
                continue

            finding = dict(vulnerability)

            finding["Package"] = result.get("Package", "Unknown")
            finding["Version"] = result.get("Version", "Unknown")
            finding["Ecosystem"] = result.get("Ecosystem", "Unknown")

            severity, score = get_cvss_information(finding)

            finding["risk_severity"] = severity
            finding["cvss_score"] = score

            finding["Vulnerability ID"] = (
                finding.get("id")
                or finding.get("ID")
                or "Unknown"
            )

            finding["Summary"] = (
                finding.get("summary")
                or finding.get("details")
                or "No description available"
            )

            findings.append(finding)

    return findings


def calculate_severity_counts(findings):
    """Count vulnerability records by normalized severity."""

    counts = Counter({
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Unknown": 0,
    })

    for finding in findings:
        severity = normalize_severity(
            finding.get("risk_severity")
            or finding.get("severity")
        )

        counts[severity] += 1

    return counts


# =========================================================
# OSV API CLIENT
# =========================================================

def query_osv(package_name, version, ecosystem):
    """Query OSV for vulnerabilities affecting a package version."""

    if not package_name:
        raise ValueError("Package name cannot be empty.")

    package_name = str(package_name).strip()
    version = str(version or "").strip()

    if not version or version.lower() in {
        "not specified",
        "unknown",
        "none",
    }:
        return {
            "Status": "Version Required",
            "Details": [],
            "Error": "An exact package version is required.",
        }

    payload = {
        "version": version,
        "package": {
            "name": package_name,
            "ecosystem": ecosystem,
        },
    }

    response = requests.post(
        OSV_API_URL,
        json=payload,
        timeout=REQUEST_TIMEOUT,
    )

    response.raise_for_status()

    data = response.json()
    vulnerabilities = data.get("vulns", [])

    return {
        "Status": (
            "Vulnerabilities Found"
            if vulnerabilities
            else "No Known Vulnerabilities Found"
        ),
        "Details": vulnerabilities,
    }


# =========================================================
# SCAN UTILITIES
# =========================================================

def clear_previous_results():
    st.session_state.python_scan_results = None
    st.session_state.node_scan_results = None
    st.session_state.python_scan_name = None
    st.session_state.node_scan_name = None


def run_python_scan(package_specifications):
    results = []

    for specification in package_specifications:
        specification = specification.strip()

        match = re.match(
            r"^\s*([A-Za-z0-9_.-]+)\s*(?:==\s*([^\s;]+))?\s*$",
            specification,
        )

        if not match:
            results.append({
                "Package": specification,
                "Version": "Unknown",
                "Ecosystem": "PyPI",
                "Status": "Scan Failed",
                "Details": [],
                "Error": "Invalid package specification.",
            })
            continue

        package_name = match.group(1)
        version = match.group(2) or ""

        result = {
            "Package": package_name,
            "Version": version or "Not specified",
            "Ecosystem": "PyPI",
        }

        try:
            result.update(
                query_osv(package_name, version, "PyPI")
            )

        except requests.RequestException as exc:
            result.update({
                "Status": "Scan Failed",
                "Details": [],
                "Error": str(exc),
            })

        except (ValueError, TypeError) as exc:
            result.update({
                "Status": "Scan Failed",
                "Details": [],
                "Error": str(exc),
            })

        results.append(result)

    return results


def run_node_scan(lockfile_content):
    """Parse and scan a package-lock.json file."""

    dependencies = parse_package_lock(lockfile_content)

    if not dependencies:
        raise ValueError("No dependencies found in package-lock.json.")

    results = []

    for dependency in dependencies:
        package_name = dependency.get("name")
        version = dependency.get("version")

        result = {
            "Package": package_name or "Unknown",
            "Version": version or "Unknown",
            "Ecosystem": "npm",
        }

        try:
            if not package_name or not version:
                raise ValueError("Dependency name or version is missing.")

            result.update(
                query_osv(package_name, version, "npm")
            )

        except requests.RequestException as exc:
            result.update({
                "Status": "Scan Failed",
                "Details": [],
                "Error": str(exc),
            })

        except (ValueError, TypeError) as exc:
            result.update({
                "Status": "Scan Failed",
                "Details": [],
                "Error": str(exc),
            })

        results.append(result)

    return results


# =========================================================
# SECURITY DASHBOARD
# =========================================================

def display_security_dashboard(results, scan_name="Security Scan"):
    if not results:
        st.info("No scan results are available.")
        return

    # Preserve the existing report-generator integration.
    try:
        generate_summary(results)
    except Exception as exc:
        st.warning(f"Unable to generate summary: {exc}")

    try:
        prioritized = prioritize_vulnerabilities(results) or []
    except Exception:
        prioritized = []

    # Recalculate severity from the actual OSV records.
    findings = enrich_findings(results)
    severity_counts = calculate_severity_counts(findings)

    total_dependencies = len(results)

    failed_scans = sum(
        1
        for result in results
        if result.get("Status") == "Scan Failed"
    )

    vulnerable_packages = len({
        (
            finding.get("Package"),
            finding.get("Version"),
        )
        for finding in findings
    })

    st.divider()

    st.markdown(
        '<div class="section-label">Scan results</div>',
        unsafe_allow_html=True,
    )

    st.subheader(scan_name)

    st.caption(
        "Severity is calculated from available vulnerability metadata. "
        "Unknown means that sufficient severity information was unavailable."
    )

    overview_tab, findings_tab, dependencies_tab, reports_tab = st.tabs(
        [
            "Overview",
            "Vulnerability Findings",
            "Dependencies",
            "Reports",
        ]
    )

    # -----------------------------------------------------
    # OVERVIEW
    # -----------------------------------------------------

    with overview_tab:
        st.markdown("### Security overview")

        col1, col2, col3, col4 = st.columns(4)

        col1.metric("Dependencies checked", total_dependencies)
        col2.metric("Vulnerable packages", vulnerable_packages)
        col3.metric("Vulnerability records", len(findings))
        col4.metric("Failed checks", failed_scans)

        st.markdown("### Severity distribution")

        severity_columns = st.columns(5)

        for column, label in zip(
            severity_columns,
            ["Critical", "High", "Medium", "Low", "Unknown"],
        ):
            column.metric(label, severity_counts[label])

        if findings:
            st.markdown("### Highest-priority findings")

            priority_rows = []

            for finding in findings:
                priority_rows.append({
                    "Package": finding.get("Package", "Unknown"),
                    "Version": finding.get("Version", "Unknown"),
                    "Vulnerability ID": finding.get(
                        "Vulnerability ID", "Unknown"
                    ),
                    "Severity": finding.get(
                        "risk_severity", "Unknown"
                    ),
                    "CVSS": finding.get("cvss_score"),
                })

            severity_order = {
                "Critical": 0,
                "High": 1,
                "Medium": 2,
                "Low": 3,
                "Unknown": 4,
            }

            priority_rows.sort(
                key=lambda row: (
                    severity_order.get(row["Severity"], 4),
                    -(
                        row["CVSS"]
                        if isinstance(row["CVSS"], (int, float))
                        else -1
                    ),
                )
            )

            st.dataframe(
                pd.DataFrame(priority_rows[:10]),
                use_container_width=True,
                hide_index=True,
            )

        elif failed_scans:
            st.warning(
                "Some dependency checks failed. Review the Dependencies tab."
            )

        else:
            st.success(
                "No known vulnerability records were returned."
            )

        if findings and severity_counts["Unknown"] == len(findings):
            st.warning(
                "All findings currently have unknown severity. The OSV "
                "records may not provide usable CVSS vectors or scores. "
                "Inspect a record in the Debug section below."
            )

    # -----------------------------------------------------
    # FINDINGS
    # -----------------------------------------------------

    with findings_tab:
        st.markdown("### Vulnerability findings")

        if not findings:
            st.info("No vulnerability records were returned.")

        else:
            severities = sorted({
                finding["risk_severity"]
                for finding in findings
            })

            selected_severities = st.multiselect(
                "Filter by severity",
                options=severities,
                default=severities,
            )

            search_text = st.text_input(
                "Search package or vulnerability ID",
                placeholder="e.g. lodash or GHSA",
            )

            rows = []

            for finding in findings:
                searchable = (
                    f"{finding.get('Package', '')} "
                    f"{finding.get('Version', '')} "
                    f"{finding.get('Vulnerability ID', '')}"
                ).lower()

                if finding["risk_severity"] not in selected_severities:
                    continue

                if search_text and search_text.lower() not in searchable:
                    continue

                rows.append({
                    "Severity": finding["risk_severity"],
                    "Package": finding["Package"],
                    "Version": finding["Version"],
                    "Vulnerability ID": finding["Vulnerability ID"],
                    "CVSS Score": finding["cvss_score"],
                    "Summary": finding["Summary"],
                })

            if rows:
                st.dataframe(
                    pd.DataFrame(rows),
                    use_container_width=True,
                    hide_index=True,
                    column_config={
                        "Summary": st.column_config.TextColumn(
                            "Summary",
                            width="large",
                        ),
                        "CVSS Score": st.column_config.NumberColumn(
                            "CVSS Score",
                            format="%.1f",
                        ),
                    },
                )

            else:
                st.info("No findings match your filters.")

            st.markdown("### Detailed findings")

            for finding in findings:
                vulnerability_id = finding["Vulnerability ID"]

                with st.expander(
                    f"{finding['risk_severity']} · "
                    f"{finding['Package']}@{finding['Version']} · "
                    f"{vulnerability_id}"
                ):
                    st.write(finding["Summary"])

                    detail_col1, detail_col2 = st.columns(2)

                    detail_col1.metric(
                        "Severity",
                        finding["risk_severity"],
                    )

                    score = finding["cvss_score"]

                    detail_col2.metric(
                        "CVSS score",
                        f"{score:.1f}" if score is not None else "Unknown",
                    )

                    references = finding.get("references", [])

                    if isinstance(references, list) and references:
                        st.markdown("**References**")

                        for reference in references[:8]:
                            if not isinstance(reference, dict):
                                continue

                            url = reference.get("url")

                            if url and url.startswith(("https://", "http://")):
                                st.markdown(f"- [{url}]({url})")

    # -----------------------------------------------------
    # DEPENDENCIES
    # -----------------------------------------------------

    with dependencies_tab:
        st.markdown("### Dependency inventory")

        dependency_rows = []

        for result in results:
            details = result.get("Details", []) or []

            if result.get("Status") == "Scan Failed":
                status = "Scan Failed"
            elif result.get("Status") == "Version Required":
                status = "Version Required"
            elif details:
                status = "Vulnerabilities Found"
            else:
                status = "No Known Vulnerabilities Found"

            dependency_rows.append({
                "Package": result.get("Package", "Unknown"),
                "Version": result.get("Version", "Unknown"),
                "Ecosystem": result.get("Ecosystem", "Unknown"),
                "Vulnerabilities": len(details),
                "Status": status,
            })

        dependency_df = pd.DataFrame(dependency_rows)

        statuses = sorted(dependency_df["Status"].unique().tolist())

        selected_statuses = st.multiselect(
            "Filter by scan status",
            options=statuses,
            default=statuses,
        )

        st.dataframe(
            dependency_df[
                dependency_df["Status"].isin(selected_statuses)
            ],
            use_container_width=True,
            hide_index=True,
        )

        failed_dependencies = [
            result
            for result in results
            if result.get("Status") in {
                "Scan Failed",
                "Version Required",
            }
        ]

        if failed_dependencies:
            st.markdown("### Checks requiring attention")

            for result in failed_dependencies:
                with st.expander(
                    f"{result.get('Package', 'Unknown')} — "
                    f"{result.get('Status')}"
                ):
                    st.warning(
                        result.get("Error", "Check could not be completed.")
                    )

    # -----------------------------------------------------
    # REPORTS
    # -----------------------------------------------------

    with reports_tab:
        st.markdown("### Export security reports")

        report_col1, report_col2 = st.columns(2)

        with report_col1:
            st.markdown(
                """
                <div class="info-card">
                    <div class="info-card-title">JSON report</div>
                    <div class="info-card-text">
                        Structured dependency and vulnerability records.
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            try:
                json_report = generate_json_report(results)

                if not isinstance(json_report, str):
                    json_report = json.dumps(
                        json_report,
                        indent=2,
                        default=str,
                    )

                st.download_button(
                    "Download JSON",
                    data=json_report,
                    file_name="dependency_risk_report.json",
                    mime="application/json",
                    use_container_width=True,
                )

            except Exception as exc:
                st.error(f"JSON report generation failed: {exc}")

        with report_col2:
            st.markdown(
                """
                <div class="info-card">
                    <div class="info-card-title">CSV report</div>
                    <div class="info-card-text">
                        Tabular vulnerability data for spreadsheets.
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            try:
                csv_report = generate_csv_report(results)

                if not isinstance(csv_report, str):
                    csv_report = str(csv_report)

                st.download_button(
                    "Download CSV",
                    data=csv_report,
                    file_name="dependency_risk_report.csv",
                    mime="text/csv",
                    use_container_width=True,
                )

            except Exception as exc:
                st.error(f"CSV report generation failed: {exc}")

    # -----------------------------------------------------
    # DEBUG
    # -----------------------------------------------------

    with st.expander("Debug: Inspect vulnerability data"):
        if findings:
            st.caption(
                "Inspect the first normalized finding and its original OSV record."
            )

            first_finding = findings[0]

            st.write("Normalized finding")
            st.json({
                "Package": first_finding.get("Package"),
                "Version": first_finding.get("Version"),
                "Vulnerability ID": first_finding.get("Vulnerability ID"),
                "Severity": first_finding.get("risk_severity"),
                "CVSS score": first_finding.get("cvss_score"),
            })

            st.write("Original OSV record")
            st.json({
                key: value
                for key, value in first_finding.items()
                if key not in {
                    "Package",
                    "Version",
                    "Ecosystem",
                    "risk_severity",
                    "cvss_score",
                    "Vulnerability ID",
                    "Summary",
                }
            })

        else:
            st.info("No vulnerability records are available to inspect.")


# =========================================================
# PYTHON SCANNER PAGE
# =========================================================

def render_python_scanner():
    st.markdown(
        '<div class="section-label">Python ecosystem</div>',
        unsafe_allow_html=True,
    )

    st.header("Python Package Scanner")

    st.write(
        "Enter package names with exact versions for version-specific checks."
    )

    st.markdown(
        """
        <div class="info-card">
            <div class="info-card-title">Example input</div>
            <div class="info-card-text">
                requests==2.31.0<br>
                flask==3.0.0<br>
                pandas==2.2.0
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    with st.form("python_scan_form"):
        package_input = st.text_area(
            "Package specifications",
            placeholder=(
                "requests==2.31.0\n"
                "flask==3.0.0\n"
                "pandas==2.2.0"
            ),
            height=150,
        )

        submitted = st.form_submit_button(
            "Run Python Security Scan",
            type="primary",
            use_container_width=True,
        )

    if submitted:
        packages = [
            line.strip()
            for line in package_input.splitlines()
            if line.strip()
        ]

        if not packages:
            st.warning("Enter at least one package.")
        else:
            clear_previous_results()

            results = []
            progress = st.progress(0, text="Starting scan...")

            for index, package in enumerate(packages):
                progress.progress(
                    (index + 1) / len(packages),
                    text=f"Checking {package}...",
                )

                results.extend(run_python_scan([package]))

            progress.empty()

            st.session_state.python_scan_results = results
            st.session_state.python_scan_name = "Python Package Scan"

            st.success(f"Checked {len(results)} package specification(s).")

    if st.session_state.python_scan_results:
        display_security_dashboard(
            st.session_state.python_scan_results,
            st.session_state.python_scan_name or "Python Package Scan",
        )


# =========================================================
# NODE.JS SCANNER PAGE
# =========================================================

def render_node_scanner():
    st.markdown(
        '<div class="section-label">Node.js ecosystem</div>',
        unsafe_allow_html=True,
    )

    st.header("Node.js Project Scanner")

    st.write(
        "Upload package-lock.json to inspect direct and transitive npm dependencies."
    )

    st.markdown(
        """
        <div class="info-card">
            <div class="info-card-title">Supported lockfiles</div>
            <div class="info-card-text">
                Upload a package-lock.json using lockfile version 2 or 3.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    uploaded_file = st.file_uploader(
        "Upload package-lock.json",
        type=["json"],
        key="node_lockfile_uploader",
    )

    if st.button(
        "Run Node.js Security Scan",
        type="primary",
        use_container_width=True,
        disabled=uploaded_file is None,
        key="run_node_security_scan",
    ):
        clear_previous_results()

        try:
            # The existing parser expects the original JSON string.
            lockfile_content = uploaded_file.getvalue().decode("utf-8")

            with st.spinner("Parsing and scanning dependencies..."):
                results = run_node_scan(lockfile_content)

            st.session_state.node_scan_results = results
            st.session_state.node_scan_name = uploaded_file.name

            st.success(
                f"Scan completed. Checked {len(results)} dependencies."
            )

        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValueError,
        ) as exc:
            st.error(f"Unable to process package-lock.json: {exc}")

        except Exception as exc:
            st.error(f"Node.js scan failed: {exc}")

    if st.session_state.node_scan_results:
        display_security_dashboard(
            st.session_state.node_scan_results,
            st.session_state.node_scan_name or "Node.js Project Scan",
        )


# =========================================================
# OVERVIEW PAGE
# =========================================================

def render_overview():
    st.markdown(
        '<div class="section-label">Workspace</div>',
        unsafe_allow_html=True,
    )

    st.header("Security workspace")

    st.write(
        "Choose a scanner to inspect dependencies or review previous results."
    )

    col1, col2 = st.columns(2)

    with col1:
        st.markdown(
            """
            <div class="info-card">
                <div class="info-card-title">Python Package Scan</div>
                <div class="info-card-text">
                    Check version-specific Python packages against OSV.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        if st.button("Open Python Scanner", use_container_width=True):
            st.session_state.selected_scanner = "Python Package Scan"
            st.rerun()

    with col2:
        st.markdown(
            """
            <div class="info-card">
                <div class="info-card-title">Node.js Project Scan</div>
                <div class="info-card-text">
                    Analyze package-lock.json and check npm dependency versions.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        if st.button("Open Node.js Scanner", use_container_width=True):
            st.session_state.selected_scanner = "Node.js Project Scan"
            st.rerun()

    st.markdown("### Security workflow")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown(
            """
            <div class="info-card">
                <div class="info-card-title">01 · Detect</div>
                <div class="info-card-text">
                    Query known vulnerability records.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col2:
        st.markdown(
            """
            <div class="info-card">
                <div class="info-card-title">02 · Prioritize</div>
                <div class="info-card-text">
                    Review severity and CVSS information.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col3:
        st.markdown(
            """
            <div class="info-card">
                <div class="info-card-title">03 · Report</div>
                <div class="info-card-text">
                    Export findings to JSON or CSV.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    if st.session_state.python_scan_results:
        st.markdown("### Previous Python scan")

        display_security_dashboard(
            st.session_state.python_scan_results,
            st.session_state.python_scan_name or "Python Package Scan",
        )

    if st.session_state.node_scan_results:
        st.markdown("### Previous Node.js scan")

        display_security_dashboard(
            st.session_state.node_scan_results,
            st.session_state.node_scan_name or "Node.js Project Scan",
        )


# =========================================================
# SIDEBAR AND NAVIGATION
# =========================================================

with st.sidebar:
    st.markdown("## 🛡️ Risk Radar")
    st.caption("Dependency security scanner")

    st.divider()

    selected_page = st.radio(
        "Navigation",
        [
            "Overview",
            "Python Package Scan",
            "Node.js Project Scan",
        ],
        label_visibility="collapsed",
    )

    st.divider()

    st.markdown("### Supported ecosystems")

    st.markdown(
        """
        <div class="info-card">
            <div class="info-card-title">Python · PyPI</div>
            <div class="info-card-text">
                Version-specific Python package checks.
            </div>
        </div>

        <div class="info-card">
            <div class="info-card-title">Node.js · npm</div>
            <div class="info-card-text">
                Lockfile-based dependency analysis.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.divider()

    st.caption("Vulnerability intelligence: OSV database")


if st.session_state.selected_scanner and selected_page == "Overview":
    selected_page = st.session_state.selected_scanner
    st.session_state.selected_scanner = None

if selected_page == "Overview":
    render_overview()

elif selected_page == "Python Package Scan":
    render_python_scanner()

elif selected_page == "Node.js Project Scan":
    render_node_scanner()

