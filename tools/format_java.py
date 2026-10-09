#!/usr/bin/env python3
"""Format repository Java sources with pinned google-java-format and JDK 21 or newer."""

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from urllib.request import urlopen


VERSION = "1.37.0"
JAR_NAME = f"google-java-format-{VERSION}-all-deps.jar"
JAR_URL = (
    f"https://github.com/google/google-java-format/releases/download/v{VERSION}/"
    f"{JAR_NAME}"
)
# Official release asset digest:
# https://api.github.com/repos/google/google-java-format/releases/tags/v1.37.0
JAR_SHA256 = "834b2a0c38cb774953322a84b5ca3f2f40dd3156650b3cd44d3b744345962f7a"


def verify_jar(path):
    if not path.is_file():
        raise ValueError(f"Formatter jar is not a regular file: {path}")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != JAR_SHA256:
        raise ValueError(
            f"Formatter jar SHA-256 differs from the pinned release: {path}"
        )
    return path


def download_jar(path):
    """Verify a temporary download before publishing it in the user cache."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        dir=path.parent, prefix=f".{JAR_NAME}.", suffix=".tmp", delete=False
    ) as temporary:
        temporary_path = Path(temporary.name)
    try:
        with (
            urlopen(JAR_URL, timeout=30) as response,
            temporary_path.open("wb") as output,
        ):
            shutil.copyfileobj(response, output)
        verify_jar(temporary_path)
        try:
            os.link(temporary_path, path)
        except FileExistsError:
            # Another invocation may have populated the cache during the download.
            verify_jar(path)
    finally:
        temporary_path.unlink(missing_ok=True)
    return verify_jar(path)


def formatter_jar(provided):
    if provided is not None:
        return verify_jar(provided.expanduser().resolve())
    cache = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    path = cache.expanduser() / "google-java-format" / JAR_NAME
    if path.exists() or path.is_symlink():
        return verify_jar(path)
    return download_jar(path)


def java_executable(provided):
    candidate = provided
    if candidate is None and os.environ.get("JAVA_HOME"):
        candidate = str(Path(os.environ["JAVA_HOME"]) / "bin" / "java")
    if candidate is None:
        candidate = "java"
    executable = shutil.which(candidate)
    if executable is None:
        raise ValueError(f"Java executable not found or not executable: {candidate}")
    return executable


def java_sources(root):
    paths = sorted(
        path
        for directory in ("src", "tests", "tools")
        for path in (root / directory).rglob("*.java")
        if path.is_file()
    )
    if not paths:
        raise ValueError("No Java sources found under src, tests or tools")
    return paths


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="report files that need formatting and fail",
    )
    parser.add_argument(
        "--jar", type=Path, help="existing jar matching the pinned version and SHA-256"
    )
    parser.add_argument(
        "--java",
        help="java executable from JDK 21 or newer, defaults to JAVA_HOME/bin/java or PATH",
    )
    args = parser.parse_args()
    try:
        root = Path(__file__).resolve().parent.parent
        sources = java_sources(root)
        java = java_executable(args.java)
        jar = formatter_jar(args.jar)
        options = (
            ["--dry-run", "--set-exit-if-changed"] if args.check else ["--replace"]
        )
        command = [java, "-jar", str(jar), *options, *map(str, sources)]
        return subprocess.run(command, check=False).returncode
    except (OSError, ValueError) as error:
        parser.exit(2, f"Java formatter failed: {error}\n")


if __name__ == "__main__":
    sys.exit(main())
