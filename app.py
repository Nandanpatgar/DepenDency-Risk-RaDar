import json
import re

import pandas as pd
import requests
import streamlit as st

from node_scanner import parse_package_lock
from report_generator import (
    enrich_vulnerability,
    generate_summary,
    prioritize_vulnerabilities,
    generate_json_report,
    generate_csv_report,
)


# =========================================================
# APPLICATION CONFIGURATION
# =========================================================

st.set_page_config(
    page_title="Dependency Risk Radar",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

OSV_API_URL = "https://api.osv.dev/v1/query"
REQUEST_TIMEOUT = 20


# =========================================================
# STYLING
# =========================================================

st.markdown(
    """
    <style>
    .stApp {
        background: #0b1120;
        color: #e5e7eb;
    }

    [data-testid="stSidebar"] {
        background: #101827;
        border-right: 1px solid #243247;
    }

    h1, h2, h3 {
        color: #f8fafc;
    }

    .hero-card, .info-card {
        background: linear-gradient(135deg, #111c2f, #15243a);
        border: 1px solid #293b54;
        border-radius: 14px;
        padding: 18px;
        margin-bottom: 12px;
    }

    .hero-title {
        font-size: 1.8rem;
        font-weight: 750;
        color: #f8fafc;
        margin-bottom: 6px;
    }

    .hero-subtitle, .info-card-text {
        color: #aab8cc;
        font-size: 0.95rem;
        line-height: 1.55;
    }

    .section-label {
        color: #5eead4;
        font-size: 0.76rem;
        font-weight: 750;
        letter-spacing: 0.13em;
        text-transform: uppercase;
        margin-bottom: 0.4rem;
    }

    .info-card-title {
        color: #f1f5f9;
        font-size: 1.05rem;
        font-weight: 700;
        margin-bottom: 6px;
    }

    div[data-testid="stMetric"] {
        background: #111c2f;
        border: 1px solid #293b54;
        padding: 14px;
        border-radius: 12px;
    }

    div[data-testid="stMetricLabel"] {
        color: #aab8cc;
    }

    .stButton > button[kind="primary"],
    .stFormSubmitButton > button[kind="primary"] {
        background: #0f9f91;
        border: 1px solid #14b8a6;
        color: white;
        font-weight: 700;
        border-radius: 9px;
    }

    .stButton > button[kind="primary"]:hover,
    .stFormSubmitButton > button[kind="primary"]:hover {
        background: #0d887d;
        border-color: #5eead4;
        color: white;
    }

    [data-testid="stTabs"] button {
        font-weight: 650;
    }

    hr {
        border-color: #293b54;
    }

    a {
        color: #5eead4 !important;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# =========================================================
# SESSION STATE
# =========================================================

SESSION_DEFAULTS = {
    "python_scan_results": None,
    "node_scan_results": None,
    "python_scan_name": None,
    "node_scan_name": None,
    "selected_scanner": None,
}

for key, default_value in SESSION_DEFAULTS.items():
    if key not in st.session_state:
        st.session_state[key] = default_value


# =========================================================
# SEVERITY AND FINDING UTILITIES
# =========================================================

def normalize_severity(value):
    """Normalize severity labels into the dashboard's categories."""

    if not isinstance(value, str):
        return "Unknown"

    normalized = value.strip().lower()

    mapping = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "moderate": "Medium",
        "low": "Low",
        "none": "None",
        "unknown": "Unknown",
    }

    return mapping.get(normalized, "Unknown")


def enrich_findings(results):
    """
    Flatten scan results into vulnerability-level records.

    The shared report-generator enrichment function supplies CVSS
    and remediation fields so the dashboard and reports use the
    same logic.
    """

    findings = []

    for result in results:
        details = result.get("Details", []) or []

        if not isinstance(details, list):
            continue

        for vulnerability in details:
            if not isinstance(vulnerability, dict):
                continue

            finding = enrich_vulnerability(vulnerability)

            finding["Package"] = result.get("Package", "Unknown")
            finding["Version"] = result.get("Version", "Unknown")
            finding["Ecosystem"] = result.get("Ecosystem", "Unknown")
            finding["Scan Status"] = result.get("Status", "Unknown")

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

            finding["risk_severity"] = normalize_severity(
                finding.get("risk_severity")
                or finding.get("severity")
            )

            findings.append(finding)

    return findings


def calculate_severity_counts(findings):
    """Count findings by normalized severity."""

    counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "None": 0,
        "Unknown": 0,
    }

    for finding in findings:
        severity = normalize_severity(
            finding.get("risk_severity")
            or finding.get("severity")
        )
        counts[severity] += 1

    return counts


def clear_previous_results():
    """Clear previous scans when starting a new scan."""

    st.session_state.python_scan_results = None
    st.session_state.node_scan_results = None
    st.session_state.python_scan_name = None
    st.session_state.node_scan_name = None


# =========================================================
# OSV API CLIENT
# =========================================================

def query_osv(package_name, version, ecosystem):
    """Query OSV for vulnerabilities affecting one exact package version."""

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
            "Vulnerabilities": 0,
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

    if not isinstance(vulnerabilities, list):
        vulnerabilities = []

    return {
        "Status": (
            "Vulnerabilities Found"
            if vulnerabilities
            else "No Known Vulnerabilities Found"
        ),
        "Details": vulnerabilities,
        "Vulnerabilities": len(vulnerabilities),
    }


# =========================================================
# SCANNERS
# =========================================================

def run_python_scan(package_specifications):
    """Scan package specifications such as requests==2.31.0."""

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
                "Vulnerabilities": 0,
                "Error": "Invalid package specification. Use package==version.",
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
            result.update(query_osv(package_name, version, "PyPI"))

        except requests.RequestException as exc:
            result.update({
                "Status": "Scan Failed",
                "Details": [],
                "Vulnerabilities": 0,
                "Error": str(exc),
            })

        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            result.update({
                "Status": "Scan Failed",
                "Details": [],
                "Vulnerabilities": 0,
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

            result.update(query_osv(package_name, version, "npm"))

        except requests.RequestException as exc:
            result.update({
                "Status": "Scan Failed",
                "Details": [],
                "Vulnerabilities": 0,
                "Error": str(exc),
            })

        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            result.update({
                "Status": "Scan Failed",
                "Details": [],
                "Vulnerabilities": 0,
                "Error": str(exc),
            })

        results.append(result)

    return results


# =========================================================
# VULNERABILITY DETAILS UI
# =========================================================

def display_finding_details(finding):
    """Display one finding, including remediation information."""

    st.write(finding.get("Summary", "No description available"))

    detail_col1, detail_col2, detail_col3 = st.columns(3)

    detail_col1.metric(
        "Severity",
        finding.get("risk_severity", "Unknown"),
    )

    score = finding.get("cvss_score")
    detail_col2.metric(
        "CVSS score",
        f"{score:.1f}" if isinstance(score, (int, float)) else "Unknown",
    )

    detail_col3.metric(
        "Ecosystem",
        finding.get("Ecosystem", "Unknown"),
    )

    st.markdown("#### Remediation guidance")

    fixed_versions = finding.get("fixed_versions", [])
    affected_versions = finding.get("affected_versions", [])
    affected_ranges = finding.get("affected_ranges", [])

    if fixed_versions:
        st.success("Fixed-version information is available.")
        st.write("**Fixed versions:** " + ", ".join(map(str, fixed_versions)))
    else:
        st.warning(
            "No fixed version was identified in the available OSV "
            "affected-version data. Review the advisory for mitigations."
        )

    if affected_versions:
        st.write(
            "**Explicitly listed affected versions:** "
            + ", ".join(map(str, affected_versions[:30]))
        )

    if affected_ranges:
        st.write("**Affected version ranges:**")
        for version_range in affected_ranges:
            st.markdown(f"- {version_range}")
    else:
        st.caption(
            "No affected version ranges were provided in the available record."
        )

    st.info(
        finding.get(
            "remediation",
            "Review the original advisory for recommended mitigations.",
        )
    )

    severity_source = finding.get("severity_source")
    if severity_source:
        st.caption(f"Severity source: {severity_source}")

    references = finding.get("references", [])

    if isinstance(references, list) and references:
        st.markdown("#### Advisory references")

        displayed = 0
        for reference in references:
            if not isinstance(reference, dict):
                continue

            url = reference.get("url", "")
            if url.startswith(("https://", "http://")):
                st.markdown(f"- [{url}]({url})")
                displayed += 1

            if displayed >= 8:
                break

    aliases = finding.get("aliases", [])
    if isinstance(aliases, list) and aliases:
        st.caption("Aliases: " + ", ".join(map(str, aliases[:10])))


# =========================================================
# SECURITY DASHBOARD
# =========================================================

def display_security_dashboard(results, scan_name="Security Scan"):
    """Render summary metrics, findings, dependencies, and reports."""

    if not results:
        st.info("No scan results are available.")
        return

    try:
        summary = generate_summary(results)
    except Exception as exc:
        st.warning(f"Unable to generate summary: {exc}")
        summary = {}

    try:
        prioritized = prioritize_vulnerabilities(results) or []
    except Exception:
        prioritized = []

    findings = enrich_findings(results)
    severity_counts = calculate_severity_counts(findings)

    total_dependencies = len(results)

    successful_statuses = {
        "Completed",
        "Vulnerabilities Found",
        "No Known Vulnerabilities Found",
    }

    successful_scans = sum(
        1 for result in results
        if result.get("Status") in successful_statuses
    )

    failed_scans = sum(
        1 for result in results
        if result.get("Status") in {"Scan Failed", "Version Required"}
    )

    vulnerable_packages = len({
        (finding.get("Package"), finding.get("Version"))
        for finding in findings
    })

    st.divider()
    st.markdown(
        '<div class="section-label">Scan results</div>',
        unsafe_allow_html=True,
    )
    st.subheader(scan_name)
    st.caption(
        "Severity and remediation guidance are based on available OSV "
        "metadata. Unknown means the record did not provide enough usable "
        "information for a reliable classification."
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

        st.caption(
            f"Successful checks: {successful_scans} · "
            f"Failed or incomplete checks: {failed_scans}"
        )

        st.markdown("### Severity distribution")
        severity_columns = st.columns(6)

        for column, label in zip(
            severity_columns,
            ["Critical", "High", "Medium", "Low", "None", "Unknown"],
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
                    "Severity": finding.get("risk_severity", "Unknown"),
                    "CVSS": finding.get("cvss_score"),
                    "Fixed Versions": ", ".join(
                        map(str, finding.get("fixed_versions", []))
                    ),
                })

            severity_order = {
                "Critical": 0,
                "High": 1,
                "Medium": 2,
                "Low": 3,
                "None": 4,
                "Unknown": 5,
            }

            priority_rows.sort(
                key=lambda row: (
                    severity_order.get(row["Severity"], 5),
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
            st.success("No known vulnerability records were returned.")

        if findings and severity_counts["Unknown"] == len(findings):
            st.warning(
                "All findings currently have unknown severity. The OSV "
                "records may not provide usable CVSS vectors or severity "
                "labels. Inspect the detailed findings and debug data."
            )

        if summary:
            with st.expander("Summary data"):
                st.json(summary)

    # -----------------------------------------------------
    # VULNERABILITY FINDINGS
    # -----------------------------------------------------

    with findings_tab:
        st.markdown("### Vulnerability findings")

        if not findings:
            st.info("No vulnerability records were returned.")
        else:
            severities = sorted({
                finding.get("risk_severity", "Unknown")
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

            filtered_findings = []

            for finding in findings:
                searchable = (
                    f"{finding.get('Package', '')} "
                    f"{finding.get('Version', '')} "
                    f"{finding.get('Vulnerability ID', '')} "
                    f"{finding.get('Summary', '')}"
                ).lower()

                if finding.get("risk_severity") not in selected_severities:
                    continue

                if search_text and search_text.lower() not in searchable:
                    continue

                filtered_findings.append(finding)

            rows = []
            for finding in filtered_findings:
                rows.append({
                    "Severity": finding.get("risk_severity", "Unknown"),
                    "Package": finding.get("Package", "Unknown"),
                    "Version": finding.get("Version", "Unknown"),
                    "Vulnerability ID": finding.get(
                        "Vulnerability ID", "Unknown"
                    ),
                    "CVSS Score": finding.get("cvss_score"),
                    "Fixed Versions": ", ".join(
                        map(str, finding.get("fixed_versions", []))
                    ),
                    "Summary": finding.get("Summary", ""),
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

            for finding in filtered_findings:
                vulnerability_id = finding.get(
                    "Vulnerability ID", "Unknown"
                )

                with st.expander(
                    f"{finding.get('risk_severity', 'Unknown')} · "
                    f"{finding.get('Package', 'Unknown')}@"
                    f"{finding.get('Version', 'Unknown')} · "
                    f"{vulnerability_id}"
                ):
                    display_finding_details(finding)

    # -----------------------------------------------------
    # DEPENDENCIES
    # -----------------------------------------------------

    with dependencies_tab:
        st.markdown("### Dependency inventory")

        dependency_rows = []

        for result in results:
            details = result.get("Details", []) or []
            scan_status = result.get("Status", "Unknown")

            if scan_status == "Scan Failed":
                status = "Scan Failed"
            elif scan_status == "Version Required":
                status = "Version Required"
            elif details:
                status = "Vulnerabilities Found"
            elif scan_status in successful_statuses:
                status = "No Known Vulnerabilities Found"
            else:
                status = scan_status

            dependency_rows.append({
                "Package": result.get("Package", "Unknown"),
                "Version": result.get("Version", "Unknown"),
                "Ecosystem": result.get("Ecosystem", "Unknown"),
                "Vulnerabilities": len(details),
                "Status": status,
            })

        dependency_df = pd.DataFrame(dependency_rows)

        if dependency_df.empty:
            st.info("No dependency records are available.")
        else:
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
                    f"{result.get('Status', 'Unknown')}"
                ):
                    st.warning(
                        result.get(
                            "Error",
                            "The check could not be completed.",
                        )
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
                        Structured dependency, vulnerability, severity,
                        and remediation information.
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            try:
                ecosystem = (
                    results[0].get("Ecosystem", "Unknown")
                    if results else "Unknown"
                )
                json_report = generate_json_report(
                    results,
                    ecosystem=ecosystem,
                )

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
                        Tabular dependency findings, severity, fixed versions,
                        and recommended actions.
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            try:
                csv_report = generate_csv_report(results)

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
            first_finding = findings[0]

            st.caption(
                "Inspect the first normalized finding and the OSV fields "
                "used for severity and remediation."
            )

            st.write("Normalized finding")
            st.json({
                "Package": first_finding.get("Package"),
                "Version": first_finding.get("Version"),
                "Ecosystem": first_finding.get("Ecosystem"),
                "Vulnerability ID": first_finding.get("Vulnerability ID"),
                "Severity": first_finding.get("risk_severity"),
                "CVSS score": first_finding.get("cvss_score"),
                "Fixed versions": first_finding.get("fixed_versions", []),
                "Affected ranges": first_finding.get("affected_ranges", []),
                "Remediation": first_finding.get("remediation"),
            })

            st.write("Original OSV record")
            excluded_keys = {
                "Package",
                "Version",
                "Ecosystem",
                "Scan Status",
                "risk_severity",
                "cvss_score",
                "severity_source",
                "Vulnerability ID",
                "Summary",
                "fixed_versions",
                "affected_ranges",
                "affected_versions",
                "remediation",
                "remediation_status",
            }

            st.json({
                key: value
                for key, value in first_finding.items()
                if key not in excluded_keys
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

            st.success(f"Processed {len(results)} package specification(s).")

    if st.session_state.python_scan_results is not None:
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
            # parse_package_lock expects JSON text, not a Python dictionary.
            lockfile_content = uploaded_file.getvalue().decode("utf-8")

            with st.spinner("Parsing and scanning dependencies..."):
                results = run_node_scan(lockfile_content)

            st.session_state.node_scan_results = results
            st.session_state.node_scan_name = uploaded_file.name

            st.success(
                f"Scan processed {len(results)} dependencies."
            )

        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValueError,
        ) as exc:
            st.error(f"Unable to process package-lock.json: {exc}")

        except Exception as exc:
            st.error(f"Node.js scan failed: {exc}")

    if st.session_state.node_scan_results is not None:
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
        "Scan dependencies, investigate known vulnerabilities, and review "
        "remediation information."
    )

    col1, col2 = st.columns(2)

    with col1:
        st.markdown(
            """
            <div class="info-card">
                <div class="info-card-title">Python Package Scan</div>
                <div class="info-card-text">
                    Check exact Python package versions against OSV.
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
                    Query known vulnerability records from OSV.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col2:
        st.markdown(
            """
            <div class="info-card">
                <div class="info-card-title">02 · Prioritize and remediate</div>
                <div class="info-card-text">
                    Review severity, affected versions, and available fix information.
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
                    Export findings and recommendations to JSON or CSV.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    if st.session_state.python_scan_results is not None:
        display_security_dashboard(
            st.session_state.python_scan_results,
            st.session_state.python_scan_name or "Previous Python Scan",
        )

    if st.session_state.node_scan_results is not None:
        display_security_dashboard(
            st.session_state.node_scan_results,
            st.session_state.node_scan_name or "Previous Node.js Scan",
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
