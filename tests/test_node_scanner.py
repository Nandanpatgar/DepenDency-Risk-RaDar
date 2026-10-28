import json

from node_scanner import parse_package_lock


def test_parse_valid_lockfile():
    lockfile = {
        "name": "test-project",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "test-project",
                "version": "1.0.0"
            },
            "node_modules/lodash": {
                "version": "4.17.20"
            },
            "node_modules/express": {
                "version": "4.17.1"
            },
            "node_modules/@types/node": {
                "version": "20.0.0"
            },
            "node_modules/express/node_modules/debug": {
                "version": "2.6.9"
            }
        }
    }

    result = parse_package_lock(json.dumps(lockfile))

    assert len(result) == 4

    names = {dependency["name"] for dependency in result}

    assert "lodash" in names
    assert "express" in names
    assert "@types/node" in names
    assert "debug" in names

    print("PASS: Dependencies extracted successfully.")


def test_invalid_json():
    try:
        parse_package_lock("{invalid json")

    except ValueError:
        print("PASS: Invalid JSON handled correctly.")

    else:
        raise AssertionError(
            "Expected invalid JSON to raise ValueError."
        )


def test_unsupported_lockfile_version():
    lockfile = {
        "lockfileVersion": 1,
        "packages": {}
    }

    try:
        parse_package_lock(json.dumps(lockfile))

    except ValueError:
        print("PASS: Unsupported lockfile version handled.")

    else:
        raise AssertionError(
            "Expected unsupported version to raise ValueError."
        )


if __name__ == "__main__":
    test_parse_valid_lockfile()
    test_invalid_json()
    test_unsupported_lockfile_version()

    print("\nAll parser tests passed.")