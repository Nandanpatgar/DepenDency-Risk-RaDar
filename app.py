
import requests
import streamlit as st

# --------------------------------------------------
# 1. Page configuration
# --------------------------------------------------

st.set_page_config(
    page_title="Dependency Risk Radar",
    page_icon="🛡️",
    layout="centered"
)

OSV_API_URL = "https://api.osv.dev/v1/query"


# --------------------------------------------------
# 2. Vulnerability lookup service
# --------------------------------------------------

def check_vulnerabilities(package_name, package_version):
    """
    Query OSV for known vulnerabilities affecting
    a specific package version in the PyPI ecosystem.
    """

    payload = {
        "package": {
            "name": package_name,
            "ecosystem": "PyPI"
        },
        "version": package_version
    }

    response = requests.post(
        OSV_API_URL,
        json=payload,
        timeout=15
    )

    response.raise_for_status()

    data = response.json()

    return data.get("vulns", [])


# --------------------------------------------------
# 3. Application interface
# --------------------------------------------------

st.title("Dependency Risk Radar")

st.write(
    "Identify known security vulnerabilities in "
    "your software dependencies."
)

st.divider()

st.subheader("Dependency Risk Analysis")

st.write(
    "Enter a Python package and its installed version "
    "to check for known vulnerabilities."
)

package_name = st.text_input(
    "Package name",
    placeholder="Example: requests"
)

package_version = st.text_input(
    "Installed version",
    placeholder="Example: 2.19.1"
)


# --------------------------------------------------
# 4. Run vulnerability analysis
# --------------------------------------------------

if st.button("Scan Dependency", type="primary"):

    package_name = package_name.strip()
    package_version = package_version.strip()

    if not package_name or not package_version:
        st.warning(
            "Please enter both a package name and version."
        )

    else:
        with st.spinner(
            "Checking the OSV vulnerability database..."
        ):
            try:
                vulnerabilities = check_vulnerabilities(
                    package_name,
                    package_version
                )

                st.divider()

                st.subheader("Scan Results")

                st.write(
                    f"**Package:** {package_name}"
                )

                st.write(
                    f"**Installed version:** {package_version}"
                )

                st.write("**Ecosystem:** PyPI")

                if vulnerabilities:

                    st.error(
                        f"Found {len(vulnerabilities)} "
                        "known vulnerability record(s)."
                    )

                    for vulnerability in vulnerabilities:

                        vulnerability_id = vulnerability.get(
                            "id",
                            "Unknown ID"
                        )

                        summary = vulnerability.get(
                            "summary"
                        ) or "No summary provided."

                        with st.expander(
                            f"{vulnerability_id}: {summary}"
                        ):
                            st.write("**Vulnerability ID:**")
                            st.write(vulnerability_id)

                            st.write("**Summary:**")
                            st.write(summary)

                            details = vulnerability.get(
                                "details"
                            )

                            if details:
                                st.write("**Details:**")
                                st.write(details)

                            aliases = vulnerability.get(
                                "aliases", []
                            )

                            if aliases:
                                st.write("**Aliases:**")
                                st.write(", ".join(aliases))

                            references = vulnerability.get(
                                "references", []
                            )

                            if references:
                                st.write("**References:**")

                                for reference in references:
                                    url = reference.get("url")

                                    if url:
                                        st.markdown(
                                            f"- [{url}]({url})"
                                        )

                    st.caption(
                        "Review the vulnerability records and "
                        "affected-version ranges before deciding "
                        "whether remediation is required."
                    )

                else:
                    st.success(
                        "No known vulnerability records were "
                        "returned for this package version."
                    )

                    st.info(
                        "This does not guarantee that the package "
                        "is secure. The result depends on the "
                        "coverage and current state of the "
                        "vulnerability database."
                    )

            except requests.Timeout:
                st.error(
                    "The vulnerability service took too long "
                    "to respond. Please try again."
                )

            except requests.RequestException as error:
                st.error(
                    "Unable to retrieve vulnerability data. "
                    "Check your internet connection and try again."
                )

                st.caption(
                    f"Technical details: {error}"
                )

            except ValueError:
                st.error(
                    "The vulnerability service returned "
                    "an invalid response."
                )


# --------------------------------------------------
# 5. Footer
# --------------------------------------------------

st.divider()

st.caption(
    "Dependency Risk Radar | Known Vulnerability Scanner"
)

