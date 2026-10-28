import json

import requests
import streamlit as st

from node_scanner import parse_package_lock
from osv_client import check_package_vulnerabilities
from report_generator import (
    generate_summary,
    generate_json_report,
    generate_csv_report,
)


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="Dependency Risk Radar",
    page_icon="🛡️",
    layout="wide",
)

st.title("Dependency Risk Radar")
st.write(
    "Identify known vulnerabilities in software dependencies "
    "using the Open Source Vulnerabilities (OSV) database."
)

st.caption(
    "Supported ecosystems: Python (PyPI) and Node.js (npm)"
)

st.divider()


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def scan_dependency(package_name, package_version, ecosystem):
    """Query OSV for vulnerabilities affecting a package version."""

    return check_package_vulnerabilities(
        package_name,
        package_version,
        ecosystem,
    )


def display_vulnerabilities(
    package_name,
    package_version,
    vulnerabilities,
):
    """Display the vulnerability records returned by OSV."""

    if not vulnerabilities:
        st.success(
            f"No matching OSV vulnerability records found for "
            f"{package_name} {package_version}."
        )
        return

    st.warning(
        f"{len(vulnerabilities)} matching vulnerability record(s) "
        f"found for {package_name} {package_version}."
    )

    for vulnerability in vulnerabilities:

        vulnerability_id = vulnerability.get(
            "id",
            "Unknown vulnerability",
        )

        with st.expander(vulnerability_id):

            st.write(
                "**Summary:**",
                vulnerability.get("summary") or "No summary available",
            )

            aliases = vulnerability.get("aliases", [])

            if aliases:
                st.write("**Aliases:**", ", ".join(aliases))

            details = vulnerability.get("details")

            if details:
                st.write("**Details:**", details)

            references = vulnerability.get("references", [])

            if references:
                st.write("**References:**")

                for reference in references[:5]:
                    url = reference.get("url")

                    if url:
                        st.markdown(f"- [View reference]({url})")


def display_security_dashboard(results, ecosystem):
    """Display summary metrics and downloadable reports."""

    if not results:
        st.info("No scan results are available.")
        return

    summary = generate_summary(results)

    st.divider()
    st.header("Security Overview")

    # Summary metrics
    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Total Dependencies",
        summary["total_dependencies"],
    )

    col2.metric(
        "Successfully Scanned",
        summary["successfully_scanned"],
    )

    col3.metric(
        "Failed Scans",
        summary["failed_scans"],
    )

    col4, col5 = st.columns(2)

    col4.metric(
        "Packages with Findings",
        summary["vulnerable_packages"],
    )

    col5.metric(
        "Vulnerability Records",
        summary["vulnerability_records"],
    )

    st.caption(
        "Counts represent matching OSV records. They do not necessarily "
        "represent unique security issues. Failed scans have unknown "
        "security status."
    )

    # Dependency table
    st.subheader("Dependency Results")

    table_data = [
        {
            "Package": result.get("Package", "Unknown"),
            "Version": result.get("Version", "Unknown"),
            "Scan Status": result.get("Status", "Unknown"),
            "Vulnerability Records": result.get("Vulnerabilities"),
        }
        for result in results
    ]

    st.dataframe(
        table_data,
        use_container_width=True,
        hide_index=True,
    )

    # Detailed vulnerability information
    st.subheader("Scan Details")

    for result in results:

        package_name = result.get("Package", "Unknown")
        package_version = result.get("Version", "Unknown")

        with st.expander(
            f"{package_name} — {package_version}"
        ):

            if result.get("Status") != "Completed":
                st.error(
                    "This dependency could not be scanned successfully. "
                    "Its security status is unknown."
                )
                continue

            display_vulnerabilities(
                package_name,
                package_version,
                result.get("Details", []),
            )

    # Downloadable reports
    st.subheader("Download Security Report")

    json_report = generate_json_report(
        results,
        ecosystem=ecosystem,
    )

    csv_report = generate_csv_report(results)

    col_json, col_csv = st.columns(2)

    with col_json:
        st.download_button(
            label="Download JSON Report",
            data=json_report,
            file_name="dependency-risk-report.json",
            mime="application/json",
            key=f"download_json_{ecosystem}",
        )

    with col_csv:
        st.download_button(
            label="Download CSV Report",
            data=csv_report,
            file_name="dependency-risk-report.csv",
            mime="text/csv",
            key=f"download_csv_{ecosystem}",
        )

    st.info(
        "No matching vulnerability records does not guarantee that "
        "a dependency is secure. Review scan failures and the advisory "
        "references before making security decisions."
    )


def clear_previous_results():
    """Remove previous scan results when a new scan starts."""

    st.session_state.pop("python_scan_results", None)
    st.session_state.pop("node_scan_results", None)


# ============================================================
# SCAN MODE
# ============================================================

scan_mode = st.radio(
    "Choose scanning mode",
    options=[
        "Python Package Scan",
        "Node.js Project Scan",
    ],
    horizontal=True,
)


# ============================================================
# PYTHON PACKAGE SCANNER
# ============================================================

if scan_mode == "Python Package Scan":

    st.subheader("Python Package Vulnerability Scan")

    st.write(
        "Enter the package name and exact installed version "
        "to check for known vulnerabilities."
    )

    with st.form("python_scan_form"):

        package_name = st.text_input(
            "Package name",
            placeholder="Example: requests",
        )

        package_version = st.text_input(
            "Installed version",
            placeholder="Example: 2.31.0",
        )

        submitted = st.form_submit_button(
            "Analyze Dependency",
            type="primary",
        )

    if submitted:

        clear_previous_results()

        package_name = package_name.strip()
        package_version = package_version.strip()

        if not package_name or not package_version:

            st.warning(
                "Please enter both the package name and installed version."
            )

        else:

            with st.spinner("Checking OSV vulnerability records..."):

                try:
                    vulnerabilities = scan_dependency(
                        package_name,
                        package_version,
                        "PyPI",
                    )

                    st.session_state["python_scan_results"] = [
                        {
                            "Package": package_name,
                            "Version": package_version,
                            "Vulnerabilities": len(vulnerabilities),
                            "Details": vulnerabilities,
                            "Status": "Completed",
                        }
                    ]

                except requests.RequestException as error:

                    st.error(
                        f"Could not contact the OSV API: {error}"
                    )

                except (ValueError, json.JSONDecodeError) as error:

                    st.error(
                        f"Could not process the OSV response: {error}"
                    )

    python_results = st.session_state.get("python_scan_results")

    if python_results:
        display_security_dashboard(
            python_results,
            ecosystem="PyPI",
        )


# ============================================================
# NODE.JS PROJECT SCANNER
# ============================================================

elif scan_mode == "Node.js Project Scan":

    st.subheader("Node.js Project Vulnerability Scan")

    st.write(
        "Upload a package-lock.json file to scan the project's "
        "resolved npm dependencies, including transitive dependencies "
        "represented in the lockfile."
    )

    uploaded_file = st.file_uploader(
        "Upload package-lock.json",
        type=["json"],
        key="node_lockfile_uploader",
    )

    if uploaded_file is not None:

        if st.button(
            "Scan Node.js Project",
            type="primary",
        ):

            clear_previous_results()

            try:
                file_content = uploaded_file.getvalue().decode("utf-8")

                dependencies = parse_package_lock(file_content)

                if not dependencies:

                    st.warning(
                        "No supported resolved dependencies were found "
                        "in this lockfile."
                    )

                else:

                    st.write(
                        f"**Dependencies discovered:** {len(dependencies)}"
                    )

                    progress_bar = st.progress(0)
                    status_text = st.empty()

                    results = []

                    for index, dependency in enumerate(dependencies):

                        package_name = dependency["name"]
                        package_version = dependency["version"]

                        status_text.text(
                            f"Scanning {package_name} "
                            f"{package_version} "
                            f"({index + 1}/{len(dependencies)})"
                        )

                        try:
                            vulnerabilities = scan_dependency(
                                package_name,
                                package_version,
                                "npm",
                            )

                            results.append(
                                {
                                    "Package": package_name,
                                    "Version": package_version,
                                    "Vulnerabilities": len(vulnerabilities),
                                    "Details": vulnerabilities,
                                    "Status": "Completed",
                                }
                            )

                        except requests.RequestException as error:

                            results.append(
                                {
                                    "Package": package_name,
                                    "Version": package_version,
                                    "Vulnerabilities": None,
                                    "Details": [],
                                    "Status": "Scan failed",
                                    "Error": str(error),
                                }
                            )

                        except (ValueError, json.JSONDecodeError) as error:

                            results.append(
                                {
                                    "Package": package_name,
                                    "Version": package_version,
                                    "Vulnerabilities": None,
                                    "Details": [],
                                    "Status": "Scan failed",
                                    "Error": str(error),
                                }
                            )

                        progress_bar.progress(
                            (index + 1) / len(dependencies)
                        )

                    st.session_state["node_scan_results"] = results

                    status_text.text("Dependency scan completed.")

            except (
                ValueError,
                UnicodeDecodeError,
                json.JSONDecodeError,
            ) as error:

                st.error(
                    f"Could not process the uploaded lockfile: {error}"
                )

    node_results = st.session_state.get("node_scan_results")

    if node_results:
        display_security_dashboard(
            node_results,
            ecosystem="npm",
        )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "Dependency Risk Radar | Vulnerability intelligence from OSV"
)