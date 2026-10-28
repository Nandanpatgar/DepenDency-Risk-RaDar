import json

import requests
import streamlit as st

from node_scanner import parse_package_lock
from osv_client import check_package_vulnerabilities


st.set_page_config(
    page_title="Dependency Risk Radar",
    page_icon="🛡️",
    layout="wide"
)


# -------------------- Helper Functions --------------------

def scan_dependency(package_name, package_version, ecosystem):
    """Scan one package using the OSV vulnerability database."""
    return check_package_vulnerabilities(
        package_name,
        package_version,
        ecosystem
    )


def display_vulnerabilities(package_name, package_version, vulnerabilities):
    """Display vulnerability information for one package."""

    if not vulnerabilities:
        st.success(
            f"No matching OSV vulnerability records found for "
            f"{package_name} {package_version}."
        )
        return

    st.error(
        f"{len(vulnerabilities)} matching vulnerability record(s) "
        f"found for {package_name} {package_version}."
    )

    for vulnerability in vulnerabilities:
        with st.expander(
            vulnerability.get("id", "Unknown vulnerability")
        ):
            st.write(
                "**Summary:**",
                vulnerability.get("summary") or "No summary available"
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


# -------------------- Application Header --------------------

st.title("Dependency Risk Radar")

st.write(
    "Identify known vulnerabilities in software dependencies "
    "using the OSV vulnerability database."
)

st.caption(
    "Current support: Python packages (PyPI) and Node.js packages (npm)."
)

st.divider()


# -------------------- Scan Mode --------------------

scan_mode = st.radio(
    "Choose scanning mode",
    ["Python Package Scan", "Node.js Project Scan"],
    horizontal=True
)


# -------------------- Python Scanner --------------------

if scan_mode == "Python Package Scan":

    st.subheader("Python Package Vulnerability Scan")

    st.write(
        "Enter a Python package name and its installed version."
    )

    with st.form("python_scan_form"):

        package_name = st.text_input(
            "Package name",
            placeholder="Example: requests"
        )

        package_version = st.text_input(
            "Installed version",
            placeholder="Example: 2.31.0"
        )

        submitted = st.form_submit_button(
            "Analyze Dependency",
            type="primary"
        )

    if submitted:

        if not package_name.strip() or not package_version.strip():
            st.warning(
                "Please enter both the package name and installed version."
            )

        else:
            with st.spinner("Checking the OSV vulnerability database..."):

                try:
                    vulnerabilities = scan_dependency(
                        package_name.strip(),
                        package_version.strip(),
                        "PyPI"
                    )

                    display_vulnerabilities(
                        package_name.strip(),
                        package_version.strip(),
                        vulnerabilities
                    )

                except requests.RequestException as error:
                    st.error(
                        f"Could not contact the OSV API: {error}"
                    )

                except ValueError as error:
                    st.error(f"Invalid API response: {error}")


# -------------------- Node.js Scanner --------------------

elif scan_mode == "Node.js Project Scan":

    st.subheader("Node.js Project Vulnerability Scan")

    st.write(
        "Upload a package-lock.json file to scan the project's "
        "resolved npm dependencies."
    )

    uploaded_file = st.file_uploader(
        "Upload package-lock.json",
        type=["json"]
    )

    if uploaded_file is not None:

        if st.button("Scan Node.js Project", type="primary"):

            try:
                file_content = uploaded_file.getvalue().decode("utf-8")

                dependencies = parse_package_lock(file_content)

                if not dependencies:
                    st.warning(
                        "No resolved dependencies were found in this lockfile."
                    )

                else:
                    st.write(
                        f"**Dependencies discovered:** {len(dependencies)}"
                    )

                    progress_bar = st.progress(0)
                    results = []
                    failures = []

                    for index, dependency in enumerate(dependencies):

                        package_name = dependency["name"]
                        package_version = dependency["version"]

                        try:
                            vulnerabilities = scan_dependency(
                                package_name,
                                package_version,
                                "npm"
                            )

                            results.append({
                                "Package": package_name,
                                "Version": package_version,
                                "Vulnerabilities": len(vulnerabilities),
                                "Details": vulnerabilities,
                                "Status": "Completed"
                            })

                        except requests.RequestException as error:
                            failures.append({
                                "Package": package_name,
                                "Version": package_version,
                                "Error": str(error)
                            })

                            results.append({
                                "Package": package_name,
                                "Version": package_version,
                                "Vulnerabilities": None,
                                "Details": [],
                                "Status": "Scan failed"
                            })

                        progress_bar.progress(
                            (index + 1) / len(dependencies)
                        )

                    st.session_state["node_scan_results"] = results
                    st.session_state["node_scan_failures"] = failures

            except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
                st.error(f"Could not process the lockfile: {error}")

    # Display the most recent results while this session is active.
    results = st.session_state.get("node_scan_results")

    if results:
        st.divider()
        st.subheader("Node.js Scan Report")

        completed_results = [
            result for result in results
            if result["Status"] == "Completed"
        ]

        failed_results = [
            result for result in results
            if result["Status"] == "Scan failed"
        ]

        vulnerable_results = [
            result for result in completed_results
            if result["Vulnerabilities"] > 0
        ]

        total_findings = sum(
            result["Vulnerabilities"]
            for result in completed_results
        )

        col1, col2, col3, col4 = st.columns(4)

        col1.metric(
            "Dependencies",
            len(results)
        )

        col2.metric(
            "Successfully scanned",
            len(completed_results)
        )

        col3.metric(
            "Packages with findings",
            len(vulnerable_results)
        )

        col4.metric(
            "Vulnerability records",
            total_findings
        )

        st.caption(
            "These are counts of matching OSV records, not necessarily "
            "unique underlying security issues. Severity is not inferred."
        )

        st.subheader("Dependency Results")

        for result in results:

            package_name = result["Package"]
            package_version = result["Version"]

            with st.expander(
                f"{package_name} {package_version}"
            ):

                if result["Status"] == "Scan failed":
                    st.warning(
                        "The scan failed for this package. "
                        "Its security status is unknown."
                    )

                else:
                    display_vulnerabilities(
                        package_name,
                        package_version,
                        result["Details"]
                    )

        if failed_results:
            st.warning(
                f"{len(failed_results)} package(s) could not be scanned. "
                "Review these failures before relying on the report."
            )

            with st.expander("Failed package scans"):
                for failure in st.session_state.get(
                    "node_scan_failures", []
                ):
                    st.write(
                        f"**{failure['Package']} "
                        f"{failure['Version']}**"
                    )
                    st.caption(failure["Error"])

        st.info(
            "A scan with zero matching vulnerability records does not "
            "guarantee that the dependencies are secure."
        )


# -------------------- Footer --------------------

st.divider()

st.caption(
    "Dependency Risk Radar | Evidence from the OSV vulnerability database"
)