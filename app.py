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
    :root {
        --rr-bg: #080e18;
        --rr-surface: #101a29;
        --rr-surface-2: #142237;
        --rr-border: #26374d;
        --rr-text: #edf3fb;
        --rr-muted: #96a8bf;
        --rr-teal: #46d5c0;
    }
    .stApp { background: var(--rr-bg); color: var(--rr-text); }
    [data-testid="stHeader"] { background: rgba(8,14,24,.92); }
    [data-testid="stSidebar"] { background: #0b1422; border-right: 1px solid var(--rr-border); }
    [data-testid="stSidebar"] > div:first-child { padding-top: 1.15rem; }
    h1,h2,h3,h4 { color: var(--rr-text) !important; letter-spacing: -.025em; }
    h1 { font-size: 2.05rem !important; font-weight: 800 !important; }
    h2 { font-size: 1.45rem !important; font-weight: 760 !important; }
    h3 { font-size: 1.08rem !important; font-weight: 740 !important; }
    p, label, [data-testid="stCaptionContainer"] { color: var(--rr-muted); }
    .rr-hero { padding: 28px 30px; border-radius: 18px; border: 1px solid #2b4059; background: linear-gradient(115deg,#152941 0%,#101a2a 64%,#10242b 100%); margin: 4px 0 22px; position: relative; overflow: hidden; }
    .rr-hero:after { content: ''; position: absolute; width: 210px; height: 210px; border: 1px solid rgba(70,213,192,.16); border-radius: 50%; right: -54px; top: -86px; box-shadow: 0 0 0 25px rgba(70,213,192,.025),0 0 0 52px rgba(70,213,192,.02); }
    .rr-eyebrow { color: var(--rr-teal); font-size: .71rem; font-weight: 850; letter-spacing: .18em; text-transform: uppercase; margin-bottom: 10px; }
    .rr-hero-title { font-size: 1.9rem; line-height: 1.15; color: #f6f9ff; font-weight: 820; margin-bottom: 10px; max-width: 780px; }
    .rr-hero-copy { color: #aabbd0; font-size: .96rem; line-height: 1.65; max-width: 760px; margin: 0; }
    .rr-section-head { display:flex; justify-content:space-between; align-items:flex-end; gap:12px; margin: 22px 0 12px; }
    .rr-section-title { color:#edf3fb; font-size:1.12rem; font-weight:780; }
    .rr-section-sub { color:#91a4bb; font-size:.82rem; margin-top:4px; }
    .rr-card { background: linear-gradient(150deg,#132238,#0f1928); border:1px solid var(--rr-border); border-radius:15px; padding:19px 20px; min-height:132px; }
    .rr-card-top { color:#9db0c7; text-transform:uppercase; font-size:.7rem; font-weight:800; letter-spacing:.12em; margin-bottom:13px; }
    .rr-card-value { color:#f3f7fd; font-size:2rem; line-height:1.05; font-weight:830; letter-spacing:-.04em; }
    .rr-card-note { color:#9bacc1; font-size:.81rem; line-height:1.45; margin-top:10px; }
    .rr-step { background:#101b2b; border:1px solid #26384e; border-radius:13px; padding:16px; min-height:124px; }
    .rr-step-num { color:var(--rr-teal); font-size:.72rem; font-weight:850; letter-spacing:.12em; margin-bottom:13px; }
    .rr-step-title { color:#eff5fc; font-size:.98rem; font-weight:760; margin-bottom:6px; }
    .rr-step-copy { color:#9baec4; font-size:.82rem; line-height:1.5; }
    .rr-pill { display:inline-block; border:1px solid #315168; color:#a6f0e4; background:#112d35; border-radius:999px; padding:5px 10px; font-size:.72rem; font-weight:750; margin:3px 4px 0 0; }
    .rr-risk-panel { background:#101a29; border:1px solid #2a3b51; border-radius:15px; padding:21px; height:100%; }
    .rr-risk-number { color:#f5f8fc; font-size:2.65rem; font-weight:850; line-height:1; margin:8px 0; }
    .rr-risk-caption { color:#9bacc1; font-size:.84rem; line-height:1.5; }
    div[data-testid="stMetric"] { background:#101a29; border:1px solid #26374d; border-radius:13px; padding:15px 16px; min-height:102px; }
    div[data-testid="stMetricLabel"] { color:#9eb0c6; font-size:.78rem; }
    div[data-testid="stMetricValue"] { color:#f5f8fd; font-weight:800; }
    [data-testid="stTabs"] { border-bottom:1px solid var(--rr-border); margin-top:4px; }
    [data-testid="stTabs"] button { font-weight:700; padding:.72rem .85rem; }
    [data-testid="stTabs"] button[aria-selected="true"] { color:var(--rr-teal); }
    .stButton > button,.stDownloadButton > button,.stFormSubmitButton > button { border-radius:10px; min-height:2.75rem; font-weight:750; border:1px solid #344a62; transition:all .15s ease; }
    .stButton > button[kind="primary"],.stFormSubmitButton > button[kind="primary"] { background:#13877d; border-color:#27ad9e; color:white; }
    .stButton > button[kind="primary"]:hover,.stFormSubmitButton > button[kind="primary"]:hover { background:#159b8e; border-color:#52d9c8; color:white; }
    [data-testid="stDataFrame"] { border:1px solid var(--rr-border); border-radius:12px; overflow:hidden; }
    [data-testid="stFileUploader"] { background:#0f1a2a; border:1px dashed #3a536d; border-radius:13px; padding:10px; }
    input,textarea,[data-baseweb="select"] > div { background-color:#0f1a2a !important; border-color:#34485f !important; }
    hr { border-color:#26374d; }
    a { color:#65e0d0 !important; }
    [data-testid="stProgressBar"] > div > div { background:#36c7b4; }
    @media(max-width:760px) { .rr-hero {padding:20px;} .rr-hero-title{font-size:1.5rem;} .rr-card{min-height:110px;} }
    
    /* Sidebar ecosystem cards */
    .rr-ecosystem-heading { display:flex; align-items:center; justify-content:space-between; gap:8px; margin:2px 0 6px; }
    .rr-ecosystem-kicker { color:#54d8c4; font-size:.62rem; font-weight:850; letter-spacing:.17em; margin-bottom:4px; }
    .rr-ecosystem-title { color:#eef4fc; font-size:.96rem; font-weight:780; letter-spacing:-.02em; line-height:1.25; }
    .rr-ecosystem-count { display:flex; align-items:center; justify-content:center; min-width:35px; height:30px; border:1px solid #2b465b; border-radius:8px; background:#122534; color:#83e7d8; font-size:.76rem; font-weight:850; letter-spacing:.08em; }
    .rr-ecosystem-summary { color:#8fa3bb; font-size:.74rem; line-height:1.5; margin:0 0 13px; }
    .rr-ecosystem-card { position:relative; background:linear-gradient(145deg,#142338 0%,#0f1a29 100%); border:1px solid #2a3c52; border-radius:12px; padding:12px 11px 11px; margin:0 0 10px; overflow:hidden; }
    .rr-ecosystem-card:before { content:""; position:absolute; top:0; left:0; right:0; height:2px; background:linear-gradient(90deg,#3ccbb7,#315b70 72%,transparent); }
    .rr-ecosystem-card-head { display:flex; align-items:center; gap:9px; min-width:0; }
    .rr-ecosystem-monogram { width:35px; height:35px; min-width:35px; display:flex; align-items:center; justify-content:center; border-radius:9px; font-size:.77rem; font-weight:850; letter-spacing:-.03em; }
    .rr-python-mark { color:#9ed8f5; background:#18364a; border:1px solid #2c5b73; }
    .rr-node-mark { color:#a9e6bd; background:#18382f; border:1px solid #2b604a; }
    .rr-ecosystem-identity { flex:1; min-width:0; }
    .rr-ecosystem-name { color:#f1f6fc; font-size:.89rem; font-weight:800; line-height:1.2; }
    .rr-ecosystem-registry { color:#8298b1; font-size:.56rem; font-weight:800; letter-spacing:.1em; margin-top:4px; }
    .rr-ecosystem-status { color:#6ee1ce; border:1px solid #285d5b; background:#102f34; border-radius:5px; padding:3px 5px; font-size:.55rem; font-weight:850; letter-spacing:.06em; white-space:nowrap; }
    .rr-ecosystem-rule { height:1px; background:#273a50; margin:11px 0 8px; }
    .rr-ecosystem-detail { display:flex; align-items:flex-start; justify-content:space-between; gap:8px; padding:4px 0; font-size:.69rem; line-height:1.35; }
    .rr-ecosystem-detail span { color:#8fa3ba; flex:0 0 auto; }
    .rr-ecosystem-detail strong { color:#d7e2ef; text-align:right; font-weight:650; overflow-wrap:anywhere; }
    .rr-ecosystem-capability { border-top:1px solid #273a50; color:#a7b8cb; font-size:.68rem; line-height:1.4; margin-top:7px; padding-top:8px; }
    .rr-ecosystem-source { display:flex; flex-wrap:wrap; align-items:center; gap:6px; border:1px solid #26384b; background:#0d1927; border-radius:8px; padding:9px 10px; color:#8fa2b8; font-size:.65rem; line-height:1.35; }
    .rr-ecosystem-source strong { color:#d8e4f1; font-weight:750; }
    .rr-source-indicator { display:inline-block; width:6px; height:6px; border-radius:50%; background:#49d2bb; box-shadow:0 0 0 3px rgba(73,210,187,.12); margin-right:2px; }

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

    st.markdown(
        f"""
        <div class="page-hero">
            <div class="page-kicker">Scan results</div>
            <div class="page-hero-title">{scan_name}</div>
            <p class="page-hero-copy">
                Review dependency exposure, prioritize vulnerability findings,
                and inspect evidence-based remediation guidance. Severity and
                fix information depend on the available OSV advisory data.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
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
        st.markdown(
            '<div class="rr-section-head"><div><div class="rr-section-title">Security posture</div><div class="rr-section-sub">A quick view of the dependency scan and its highest-priority exposure.</div></div></div>',
            unsafe_allow_html=True,
        )

        metric_cols = st.columns(4, gap="medium")
        metric_data = [
            ("DEPENDENCIES CHECKED", total_dependencies, "Packages and lockfile entries reviewed"),
            ("VULNERABLE PACKAGES", vulnerable_packages, "Unique package-version pairs with findings"),
            ("VULNERABILITY RECORDS", len(findings), "Advisories returned by OSV"),
            ("INCOMPLETE CHECKS", failed_scans, "Checks that need investigation"),
        ]
        for col, (label, value, note) in zip(metric_cols, metric_data):
            with col:
                st.markdown(
                    f'<div class="rr-card"><div class="rr-card-top">{label}</div><div class="rr-card-value">{value}</div><div class="rr-card-note">{note}</div></div>',
                    unsafe_allow_html=True,
                )

        st.markdown(
            '<div class="rr-section-head"><div><div class="rr-section-title">Severity breakdown</div><div class="rr-section-sub">Severity categories from the available advisory metadata.</div></div></div>',
            unsafe_allow_html=True,
        )
        chart_col, risk_col = st.columns([1.7, 1], gap="large")
        severity_labels = ["Critical", "High", "Medium", "Low", "None", "Unknown"]
        with chart_col:
            chart_df = pd.DataFrame({
                "Severity": severity_labels,
                "Vulnerabilities": [severity_counts[x] for x in severity_labels],
            })
            if findings:
                st.bar_chart(chart_df.set_index("Severity"), height=290, use_container_width=True)
            else:
                st.markdown(
                    '<div class="rr-card"><div class="rr-card-top">No findings to visualize</div><div class="rr-card-note">Run a scan to populate the severity chart and vulnerability summary.</div></div>',
                    unsafe_allow_html=True,
                )
        with risk_col:
            critical = severity_counts["Critical"]
            high = severity_counts["High"]
            medium = severity_counts["Medium"]
            critical_high = critical + high
            if critical:
                posture = "Critical findings detected"
                posture_copy = "Investigate critical findings first and confirm whether the affected code is reachable."
            elif high:
                posture = "High-priority review needed"
                posture_copy = "Review high-severity findings and available fixed versions before lower-priority work."
            elif findings:
                posture = "Review findings"
                posture_copy = "No critical or high findings were classified, but review the remaining advisories."
            elif failed_scans:
                posture = "Scan needs attention"
                posture_copy = "Some checks did not complete. Resolve those errors before interpreting this as a clean scan."
            else:
                posture = "No known findings returned"
                posture_copy = "The scan returned no known vulnerability records for the checked versions."
            st.markdown(
                f'<div class="rr-risk-panel"><div class="rr-card-top">Risk snapshot</div><div class="rr-risk-number">{critical_high}</div><div class="rr-risk-caption">Critical + high severity findings</div><hr><div style="color:#edf3fb;font-weight:760;margin:12px 0 7px">{posture}</div><div class="rr-risk-caption">{posture_copy}</div><div style="margin-top:16px"><span class="rr-pill">Critical {critical}</span><span class="rr-pill">High {high}</span><span class="rr-pill">Medium {medium}</span></div></div>',
                unsafe_allow_html=True,
            )
            if findings:
                known = sum(severity_counts[x] for x in ["Critical", "High", "Medium", "Low", "None"])
                coverage = known / len(findings)
                st.markdown("**Severity data coverage**")
                st.progress(coverage)
                st.caption(f"{coverage:.0%} of findings have a recognized severity category")

        st.markdown(
            '<div class="rr-section-head"><div><div class="rr-section-title">Priority queue</div><div class="rr-section-sub">The most urgent findings appear first. Open Vulnerability Findings for filters and full details.</div></div></div>',
            unsafe_allow_html=True,
        )
        if findings:
            priority_rows = []
            for finding in findings:
                priority_rows.append({
                    "Severity": finding.get("risk_severity", "Unknown"),
                    "Package": finding.get("Package", "Unknown"),
                    "Installed": finding.get("Version", "Unknown"),
                    "Advisory": finding.get("Vulnerability ID", "Unknown"),
                    "CVSS": finding.get("cvss_score"),
                    "Known fix": ", ".join(map(str, finding.get("fixed_versions", []))) or "Not listed",
                })
            order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "None": 4, "Unknown": 5}
            priority_rows.sort(key=lambda row: (order.get(row["Severity"], 5), -(row["CVSS"] if isinstance(row["CVSS"], (int, float)) else -1)))
            st.dataframe(pd.DataFrame(priority_rows[:8]), use_container_width=True, hide_index=True)
        elif failed_scans:
            st.warning("Some checks failed. Review the Dependencies tab for errors before treating this scan as clean.")
        else:
            st.success("No known vulnerability records were returned for the checked dependencies.")

        with st.expander("Scan metadata"):
            st.write({"Successful checks": successful_scans, "Failed or incomplete checks": failed_scans, "Dependencies checked": total_dependencies})
            if summary:
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
        """
        <div class="rr-hero">
            <div class="rr-eyebrow">Scanner / 01 · PyPI</div>
            <div class="rr-hero-title">Python package scan</div>
            <p class="rr-hero-copy">Check exact package versions against known OSV advisories. Enter one dependency per line using package==version syntax.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    input_col, guide_col = st.columns([1.65, 1], gap="large")
    with input_col:
        st.markdown("### Dependency input")
        with st.form("python_scan_form"):
            package_input = st.text_area(
                "Package specifications",
                placeholder="requests==2.31.0\nflask==3.0.0\npandas==2.2.0",
                height=210,
                help="Include exact versions so the scanner can check version-specific advisories.",
            )
            submitted = st.form_submit_button("Run Python security scan", type="primary", use_container_width=True)
    with guide_col:
        st.markdown(
            '<div class="rr-card"><div class="rr-card-top">Input format</div><div style="color:#eff5fc;font-weight:760;margin-bottom:8px">One package per line</div><div class="rr-card-note" style="font-family:monospace;line-height:2">requests==2.31.0<br>flask==3.0.0<br>pandas==2.2.0</div><hr><div style="color:#eff5fc;font-weight:760;margin-bottom:7px">Before you scan</div><div class="rr-card-note">Use the versions installed in your environment. Missing or invalid versions can prevent a precise check.</div></div>',
            unsafe_allow_html=True,
        )
        st.markdown(
            '<div class="rr-card" style="margin-top:12px"><div class="rr-card-top">What you get</div><div class="rr-card-note">Vulnerability IDs, severity and CVSS where available, affected version information, known fixed versions, and downloadable reports.</div></div>',
            unsafe_allow_html=True,
        )

    if submitted:
        packages = [line.strip() for line in package_input.splitlines() if line.strip()]
        if not packages:
            st.warning("Enter at least one package specification.")
        else:
            clear_previous_results()
            results = []
            progress = st.progress(0, text="Preparing scan...")
            for index, package in enumerate(packages):
                progress.progress((index + 1) / len(packages), text=f"Checking {package}...")
                results.extend(run_python_scan([package]))
            progress.empty()
            st.session_state.python_scan_results = results
            st.session_state.python_scan_name = "Python Package Scan"
            st.success(f"Scan completed for {len(results)} package specification(s).")

    if st.session_state.python_scan_results is not None:
        display_security_dashboard(st.session_state.python_scan_results, st.session_state.python_scan_name or "Python Package Scan")


# =========================================================
# NODE.JS SCANNER PAGE
# =========================================================

def render_node_scanner():
    st.markdown(
        """
        <div class="rr-hero">
            <div class="rr-eyebrow">Scanner / 02 · npm</div>
            <div class="rr-hero-title">Node.js project scan</div>
            <p class="rr-hero-copy">Inspect the resolved npm dependency tree from package-lock.json, including transitive packages, and match versions against OSV vulnerability records.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    upload_col, guide_col = st.columns([1.55, 1], gap="large")
    with upload_col:
        st.markdown("### Project lockfile")
        uploaded_file = st.file_uploader(
            "Upload package-lock.json",
            type=["json"],
            key="node_lockfile_uploader",
            help="Supported lockfile versions: 2 and 3.",
        )
        if uploaded_file is not None:
            st.markdown(
                f'<div class="rr-card"><div class="rr-card-top">Selected file</div><div style="color:#eff5fc;font-weight:760;overflow-wrap:anywhere">{uploaded_file.name}</div><div class="rr-card-note">{uploaded_file.size:,} bytes · Ready for parsing</div></div>',
                unsafe_allow_html=True,
            )
        run_node = st.button(
            "Run Node.js security scan",
            type="primary",
            use_container_width=True,
            disabled=uploaded_file is None,
            key="run_node_security_scan",
        )
    with guide_col:
        st.markdown(
            '<div class="rr-card"><div class="rr-card-top">Supported input</div><div style="color:#eff5fc;font-size:1.05rem;font-weight:780;margin-bottom:8px">package-lock.json</div><div class="rr-card-note">Use the lockfile generated by npm install or npm ci. It records the concrete dependency versions resolved for the project.</div><hr><div style="color:#eff5fc;font-weight:760;margin-bottom:7px">Included in the scan</div><div class="rr-card-note">Direct dependencies, transitive dependencies, vulnerability matches, severity details, and available remediation metadata.</div></div>',
            unsafe_allow_html=True,
        )

    if run_node and uploaded_file is not None:
        clear_previous_results()
        try:
            lockfile_content = uploaded_file.getvalue().decode("utf-8")
            with st.spinner("Parsing lockfile and querying OSV..."):
                results = run_node_scan(lockfile_content)
            st.session_state.node_scan_results = results
            st.session_state.node_scan_name = uploaded_file.name
            st.success(f"Scan processed {len(results)} dependencies.")
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            st.error(f"Unable to process package-lock.json: {exc}")
        except Exception as exc:
            st.error(f"Node.js scan failed: {exc}")

    if st.session_state.node_scan_results is not None:
        display_security_dashboard(st.session_state.node_scan_results, st.session_state.node_scan_name or "Node.js Project Scan")


# =========================================================
# OVERVIEW PAGE
# =========================================================

def render_overview():
    """Render the product landing page and recent scan snapshots."""
    st.markdown(
        """
        <div class="rr-hero">
            <div class="rr-eyebrow">Dependency security workspace</div>
            <div class="rr-hero-title">Know what is inside your software.</div>
            <p class="rr-hero-copy">Scan Python and Node.js dependencies against known vulnerability intelligence. Review severity, inspect affected versions, find available fixes, and export a clear report for your team.</p>
            <div style="margin-top:16px"><span class="rr-pill">OSV vulnerability data</span><span class="rr-pill">CVSS severity</span><span class="rr-pill">Remediation guidance</span><span class="rr-pill">JSON / CSV reports</span></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        '<div class="rr-section-head"><div><div class="rr-section-title">Choose your scan type</div><div class="rr-section-sub">Start with a specific Python package list or scan an npm project lockfile.</div></div></div>',
        unsafe_allow_html=True,
    )
    py_col, node_col = st.columns(2, gap="large")
    with py_col:
        st.markdown(
            '<div class="rr-card"><div class="rr-card-top">01 / Python · PyPI</div><div style="color:#f2f7fd;font-size:1.2rem;font-weight:790;margin-bottom:8px">Package version scan</div><div class="rr-card-note">Check exact versions such as requests==2.31.0. Best for quick checks, bug triage, and verifying a single dependency.</div><div style="margin-top:14px"><span class="rr-pill">Exact versions</span><span class="rr-pill">Multi-package input</span></div></div>',
            unsafe_allow_html=True,
        )
        if st.button("Open Python scanner", type="primary", use_container_width=True, key="overview_open_python"):
            st.session_state.selected_scanner = "Python Package Scan"
            st.rerun()
    with node_col:
        st.markdown(
            '<div class="rr-card"><div class="rr-card-top">02 / Node.js · npm</div><div style="color:#f2f7fd;font-size:1.2rem;font-weight:790;margin-bottom:8px">Project lockfile scan</div><div class="rr-card-note">Upload package-lock.json to inspect resolved direct and transitive dependency versions in one scan.</div><div style="margin-top:14px"><span class="rr-pill">package-lock.json</span><span class="rr-pill">Transitive packages</span></div></div>',
            unsafe_allow_html=True,
        )
        if st.button("Open Node.js scanner", type="primary", use_container_width=True, key="overview_open_node"):
            st.session_state.selected_scanner = "Node.js Project Scan"
            st.rerun()

    st.markdown(
        '<div class="rr-section-head"><div><div class="rr-section-title">How the analysis works</div><div class="rr-section-sub">A simple, traceable workflow from dependency input to actionable report.</div></div></div>',
        unsafe_allow_html=True,
    )
    step_cols = st.columns(4, gap="medium")
    steps = [
        ("01", "Inventory", "Read package names and exact versions from your input or lockfile."),
        ("02", "Match advisories", "Query OSV for known vulnerability records associated with each dependency."),
        ("03", "Prioritize", "Review CVSS severity, affected ranges, and fixed versions when supplied."),
        ("04", "Act and report", "Inspect remediation guidance and export findings as JSON or CSV."),
    ]
    for col, (num, title, description) in zip(step_cols, steps):
        with col:
            st.markdown(
                f'<div class="rr-step"><div class="rr-step-num">STEP {num}</div><div class="rr-step-title">{title}</div><div class="rr-step-copy">{description}</div></div>',
                unsafe_allow_html=True,
            )

    # Show a compact snapshot of the latest completed scans, without duplicating full dashboards.
    scan_cards = []
    for label, results_key, name_key in [
        ("Python", "python_scan_results", "python_scan_name"),
        ("Node.js", "node_scan_results", "node_scan_name"),
    ]:
        results = st.session_state.get(results_key)
        if results is not None:
            findings = enrich_findings(results)
            counts = calculate_severity_counts(findings)
            scan_cards.append((label, st.session_state.get(name_key) or f"{label} scan", len(results), len(findings), counts))

    if scan_cards:
        st.markdown(
            '<div class="rr-section-head"><div><div class="rr-section-title">Recent scan snapshots</div><div class="rr-section-sub">The latest results retained in this session.</div></div></div>',
            unsafe_allow_html=True,
        )
        cols = st.columns(len(scan_cards), gap="large")
        for col, (label, scan_name, dep_count, finding_count, counts) in zip(cols, scan_cards):
            with col:
                st.markdown(
                    f'<div class="rr-card"><div class="rr-card-top">{label} scan</div><div style="color:#f2f7fd;font-size:1.05rem;font-weight:780;margin-bottom:12px">{scan_name}</div><div style="display:flex;gap:24px;flex-wrap:wrap"><div><div class="rr-card-value" style="font-size:1.55rem">{dep_count}</div><div class="rr-card-note">Dependencies</div></div><div><div class="rr-card-value" style="font-size:1.55rem">{finding_count}</div><div class="rr-card-note">Findings</div></div></div><div style="margin-top:12px"><span class="rr-pill">Critical {counts["Critical"]}</span><span class="rr-pill">High {counts["High"]}</span><span class="rr-pill">Medium {counts["Medium"]}</span></div></div>',
                    unsafe_allow_html=True,
                )
                if st.button(f"Review {label} results", use_container_width=True, key=f"overview_review_{label.lower()}"):
                    st.session_state.selected_scanner = "Python Package Scan" if label == "Python" else "Node.js Project Scan"
                    st.rerun()


# =========================================================
# SIDEBAR AND NAVIGATION
# =========================================================

with st.sidebar:
    st.markdown("## Dependency Risk Radar")
    st.markdown('<div class="rr-eyebrow">SECURITY WORKSPACE</div>', unsafe_allow_html=True)
    st.caption("Known vulnerability detection and remediation")
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

    st.markdown(
        """
        <div class="rr-ecosystem-heading">
            <div>
                <div class="rr-ecosystem-kicker">COVERAGE</div>
                <div class="rr-ecosystem-title">Supported ecosystems</div>
            </div>
            <div class="rr-ecosystem-count">02</div>
        </div>
        <div class="rr-ecosystem-summary">
            Scan packages against known vulnerability advisories.
        </div>

        <div class="rr-ecosystem-card">
            <div class="rr-ecosystem-card-head">
                <div class="rr-ecosystem-monogram rr-python-mark">Py</div>
                <div class="rr-ecosystem-identity">
                    <div class="rr-ecosystem-name">Python</div>
                    <div class="rr-ecosystem-registry">PACKAGE REGISTRY</div>
                </div>
                <div class="rr-ecosystem-status">SUPPORTED</div>
            </div>
            <div class="rr-ecosystem-rule"></div>
            <div class="rr-ecosystem-detail"><span>Registry</span><strong>PyPI</strong></div>
            <div class="rr-ecosystem-detail"><span>Scan input</span><strong>Package + version</strong></div>
            <div class="rr-ecosystem-capability">Version-specific vulnerability checks</div>
        </div>

        <div class="rr-ecosystem-card">
            <div class="rr-ecosystem-card-head">
                <div class="rr-ecosystem-monogram rr-node-mark">JS</div>
                <div class="rr-ecosystem-identity">
                    <div class="rr-ecosystem-name">Node.js</div>
                    <div class="rr-ecosystem-registry">PACKAGE ECOSYSTEM</div>
                </div>
                <div class="rr-ecosystem-status">SUPPORTED</div>
            </div>
            <div class="rr-ecosystem-rule"></div>
            <div class="rr-ecosystem-detail"><span>Registry</span><strong>npm</strong></div>
            <div class="rr-ecosystem-detail"><span>Scan input</span><strong>package-lock.json</strong></div>
            <div class="rr-ecosystem-capability">Direct and transitive dependency analysis</div>
        </div>

        <div class="rr-ecosystem-source">
            <span class="rr-source-indicator"></span>
            <span>Vulnerability intelligence</span>
            <strong>OSV database</strong>
        </div>
        """,
        unsafe_allow_html=True,
    )

if st.session_state.selected_scanner and selected_page == "Overview":
    selected_page = st.session_state.selected_scanner
    st.session_state.selected_scanner = None

if selected_page == "Overview":
    render_overview()
elif selected_page == "Python Package Scan":
    render_python_scanner()
elif selected_page == "Node.js Project Scan":
    render_node_scanner()
