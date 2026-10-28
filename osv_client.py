import requests

OSV_API_URL = "https://api.osv.dev/v1/query"


def check_package_vulnerabilities(package_name, package_version, ecosystem):
    """
    Query the OSV API for known vulnerabilities
    affecting a specific package version.
    """

    payload = {
        "package": {
            "name": package_name,
            "ecosystem": ecosystem
        },
        "version": package_version
    }

    response = requests.post(
        OSV_API_URL,
        json=payload,
        timeout=20
    )

    response.raise_for_status()

    data = response.json()

    return data.get("vulns", [])