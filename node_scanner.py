import json


def parse_package_lock(file_content):
    """
    Extract resolved npm package names and versions
    from a package-lock.json file.

    Supports package-lock versions 2 and 3.
    """

    try:
        lock_data = json.loads(file_content)

    except (json.JSONDecodeError, TypeError) as error:
        raise ValueError(
            "Invalid package-lock.json file."
        ) from error

    lockfile_version = lock_data.get("lockfileVersion")

    if lockfile_version not in (2, 3):
        raise ValueError(
            "This scanner currently supports "
            "package-lock.json versions 2 and 3."
        )

    packages = lock_data.get("packages")

    if not isinstance(packages, dict):
        raise ValueError(
            "The lockfile does not contain a valid packages section."
        )

    dependencies = []

    for package_path, package_info in packages.items():

        # Skip the root project entry.
        if not package_path.startswith("node_modules/"):
            continue

        if not isinstance(package_info, dict):
            continue

        package_name = package_path.split("node_modules/")[-1]
        package_version = package_info.get("version")

        # Skip entries without a resolved version.
        if not package_version:
            continue

        dependencies.append({
            "name": package_name,
            "version": package_version
        })

    # Remove duplicate package-name/version combinations.
    unique_dependencies = {
        (dependency["name"], dependency["version"])
        for dependency in dependencies
    }

    return [
        {"name": name, "version": version}
        for name, version in sorted(unique_dependencies)
    ]