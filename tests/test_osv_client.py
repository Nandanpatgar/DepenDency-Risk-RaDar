from osv_client import check_package_vulnerabilities


def main():
    package_name = "lodash"
    package_version = "4.17.20"
    ecosystem = "npm"

    try:
        vulnerabilities = check_package_vulnerabilities(
            package_name,
            package_version,
            ecosystem
        )

        print(f"Package: {package_name}")
        print(f"Version: {package_version}")
        print(f"Ecosystem: {ecosystem}")
        print(f"Matching vulnerability records: {len(vulnerabilities)}")

        for vulnerability in vulnerabilities:
            print("\nVulnerability ID:", vulnerability.get("id"))
            print(
                "Summary:",
                vulnerability.get("summary", "No summary available")
            )

    except Exception as error:
        print("Test failed:", error)


if __name__ == "__main__":
    main()