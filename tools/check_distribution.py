#!/usr/bin/env python3
"""Verify source resources, synthetic tests and license notices in distributions."""

import argparse
from email.parser import BytesParser
from pathlib import Path
import tarfile
import zipfile


PACKAGE = "labview_vi_to_ghidra"
LICENSE_FILES = ("LICENSE", "licenses/pylabview-MIT.txt")


def source_files(directory, suffixes):
    """Read each selected source once and retain its relative path."""
    return {
        path.relative_to(directory).as_posix(): path.read_bytes()
        for path in sorted(directory.rglob("*"))
        if path.is_file() and path.suffix in suffixes
    }


def require_equal(actual, expected, description):
    if actual != expected:
        raise ValueError(f"{description}: expected {expected!r}, got {actual!r}")


def verify_bytes(read_file, path, expected):
    if read_file(path) != expected:
        raise ValueError(f"Source bytes differ: {path}")


def verify_license_metadata(data):
    metadata = BytesParser().parsebytes(data)
    require_equal(metadata["License-Expression"], "MIT", "License expression")
    require_equal(
        set(metadata.get_all("License-File", [])), set(LICENSE_FILES), "License notices"
    )


def verify_wheel(path, java, licenses):
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        expected_java = {f"{PACKAGE}/ghidra/{name}" for name in java}
        actual_java = {name for name in names if name.endswith(".java")}
        require_equal(actual_java, expected_java, "Wheel Java resources")
        for name, data in java.items():
            verify_bytes(archive.read, f"{PACKAGE}/ghidra/{name}", data)

        metadata_paths = [
            name for name in names if name.endswith(".dist-info/METADATA")
        ]
        require_equal(len(metadata_paths), 1, "Wheel metadata file count")
        metadata_path = metadata_paths[0]
        verify_license_metadata(archive.read(metadata_path))
        dist_info = metadata_path.rsplit("/", 1)[0]
        for name, data in licenses.items():
            verify_bytes(archive.read, f"{dist_info}/licenses/{name}", data)


def read_tar_file(archive, path):
    member = archive.getmember(path)
    if not member.isfile():
        raise ValueError(f"Expected a regular source file: {path}")
    file = archive.extractfile(member)
    if file is None:
        raise ValueError(f"Cannot read source file: {path}")
    with file:
        return file.read()


def verify_sdist(path, java, licenses, tests, tools):
    with tarfile.open(path, "r:gz") as archive:
        names = archive.getnames()
        roots = {name.split("/", 1)[0] for name in names}
        require_equal(len(roots), 1, "Source distribution root count")
        root = roots.pop()
        relative_files = {
            member.name.removeprefix(root + "/")
            for member in archive.getmembers()
            if member.isfile()
        }
        java_prefix = f"src/{PACKAGE}/"
        expected_java = {f"{java_prefix}ghidra/{name}" for name in java}
        actual_java = {
            name
            for name in relative_files
            if name.endswith(".java") and not name.startswith("tests/")
        }
        require_equal(actual_java, expected_java, "Source distribution Java resources")
        expected_tests = {f"tests/{name}" for name in tests}
        actual_tests = {
            name
            for name in relative_files
            if name.startswith("tests/") and Path(name).suffix in {".py", ".java"}
        }
        require_equal(
            actual_tests, expected_tests, "Source distribution synthetic tests"
        )

        expected_tools = {f"tools/{name}" for name in tools}
        actual_tools = {
            name
            for name in relative_files
            if name.startswith("tools/") and Path(name).suffix == ".py"
        }
        require_equal(
            actual_tools, expected_tools, "Source distribution development tools"
        )

        expected = {
            **{f"{java_prefix}ghidra/{name}": data for name, data in java.items()},
            **licenses,
            **{f"tests/{name}": data for name, data in tests.items()},
            **{f"tools/{name}": data for name, data in tools.items()},
        }
        for name, data in expected.items():
            verify_bytes(
                lambda item: read_tar_file(archive, item), f"{root}/{name}", data
            )
        verify_license_metadata(read_tar_file(archive, f"{root}/PKG-INFO"))


def verify_distribution(directory, source):
    wheels = sorted(directory.glob("*.whl"))
    archives = sorted(directory.glob("*.tar.gz"))
    require_equal(len(wheels), 1, "Wheel count")
    require_equal(len(archives), 1, "Source distribution count")
    java = source_files(source / "src" / PACKAGE / "ghidra", {".java"})
    tests = source_files(source / "tests", {".py", ".java"})
    if not java or not tests:
        raise ValueError("Source Java resources and synthetic tests must be present")
    licenses = {name: (source / name).read_bytes() for name in LICENSE_FILES}
    tools = source_files(source / "tools", {".py"})
    verify_wheel(wheels[0], java, licenses)
    verify_sdist(archives[0], java, licenses, tests, tools)
    return len(java), len(tests)


def main():
    source = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dist",
        type=Path,
        default=source / "dist",
        help="directory with one wheel and one source distribution",
    )
    args = parser.parse_args()
    java_count, test_count = verify_distribution(args.dist, source)
    print(
        f"Verified {java_count} Java resources, {test_count} synthetic test sources "
        "and both license notices in the distributions"
    )


if __name__ == "__main__":
    main()
