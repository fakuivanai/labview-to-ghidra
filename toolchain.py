"""Explicit runtime inputs and Ghidra backends for static VI analysis."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess

RUNTIME_SHA256 = "2dcb88ecdec6bac366530cb28fc760060a13def9da72ffb7ed2d35985101e74e"
RUNTIME_VERSION = "13.0.0.4046"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def validate_runtime(runtime, runtime_map):
    runtime = Path(runtime).expanduser().resolve()
    if digest(runtime) != RUNTIME_SHA256:
        raise ValueError("Unsupported runtime build; expected LV13.0.0.4046 SHA-256 " + RUNTIME_SHA256)
    result = json.loads(Path(runtime_map).read_text())
    if result.get("sha256") != RUNTIME_SHA256 or result.get("version") != RUNTIME_VERSION:
        raise ValueError("Runtime map does not describe the supported runtime build")
    if result.get("machine") != 0x14c or result.get("image_base") != 0x30000000:
        raise ValueError("Runtime map has an unsupported architecture or image base")
    if not result.get("modules"):
        raise ValueError("Runtime map has no callback modules")
    result["runtime"] = str(runtime)
    return result


def acquire_job():
    """Hold one analysis job per user, outside the installed source tree."""
    cache = Path(os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache")))
    directory = cache / "labview-vi-to-ghidra"
    directory.mkdir(parents=True, exist_ok=True)
    handle = (directory / "analysis.lock").open("a+b")
    try:
        import fcntl
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (OSError, BlockingIOError):
        handle.close()
        raise ValueError("Another VI analysis job is running; wait for it to finish") from None
    os.nice(max(0, 19 - os.getpriority(os.PRIO_PROCESS, 0)))
    cpu = min(os.sched_getaffinity(0))
    os.sched_setaffinity(0, {cpu})
    limits = {
        "cpu_affinity": [cpu],
        "nice": os.getpriority(os.PRIO_PROCESS, 0),
        "ghidra_max_cpu": 1,
        "concurrent_converters": 1,
        "note": "One analysis job on one low-priority CPU. Existing memory settings preserved.",
    }
    return handle, limits


def analysis_environment():
    env = dict(os.environ)
    env["_JAVA_OPTIONS"] = env.get("_JAVA_OPTIONS", "") + " -XX:ActiveProcessorCount=1"
    return env


def resolve_ghidra_installation(selector=None, *, required=True):
    """Record an installation independently of the caller's working directory."""
    selected = selector or os.environ.get("GHIDRA_HOME")
    if selected == "flatpak":
        return "flatpak"
    if selected:
        return str(Path(selected).expanduser().resolve())
    located = shutil.which("analyzeHeadless")
    if located:
        return str(Path(located).resolve().parent.parent)
    if required:
        raise ValueError("Set GHIDRA_HOME, pass --ghidra /path/to/ghidra, or select --ghidra flatpak")
    return None


def ghidra_backend(selector, output, *, source=None, runtime=None):
    """Return the headless command, environment and exact language/version files."""
    selector = resolve_ghidra_installation(selector)
    output = Path(output).resolve()
    temporary = output / ".ghidra-tmp"
    temporary.mkdir(exist_ok=True)
    env = analysis_environment()
    env["JAVA_TOOL_OPTIONS"] = env.get("JAVA_TOOL_OPTIONS", "") + ' -XX:-UsePerfData -Djava.io.tmpdir="' + str(temporary) + '"'
    if selector == "flatpak":
        command = ["flatpak", "run", "--env=_JAVA_OPTIONS=" + env["_JAVA_OPTIONS"],
                   "--env=JAVA_TOOL_OPTIONS=" + env["JAVA_TOOL_OPTIONS"], "--filesystem=" + str(output)]
        for path in (source, runtime):
            if path is not None:
                command.append("--filesystem=" + str(Path(path).resolve()) + ":ro")
        command += ["--env=JAVA_HOME=/app/jdk", "--command=/app/lib/ghidra/support/analyzeHeadless", "org.ghidra_sre.Ghidra"]
        version = subprocess.check_output(
            ["flatpak", "run", "--command=cat", "org.ghidra_sre.Ghidra",
             "/app/lib/ghidra/Ghidra/application.properties",
             "/app/lib/ghidra/Ghidra/Processors/x86/data/languages/x86.ldefs"], text=True)
        return command, env, version
    home = Path(selector)
    executable = home / "support" / "analyzeHeadless"
    if not executable.is_file():
        raise ValueError("Ghidra headless launcher not found: " + str(executable))
    version = (home / "Ghidra/application.properties").read_text() + (home / "Ghidra/Processors/x86/data/languages/x86.ldefs").read_text()
    return [str(executable)], env, version
