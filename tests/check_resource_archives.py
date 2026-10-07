#!/usr/bin/env python3
"""Run synthetic archive preservation and rejection checks in a fresh Ghidra project."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ghidra', required=True, help='Ghidra installation directory, or flatpak')
    parser.add_argument('--output', required=True, type=Path, help='new or empty test output directory')
    args = parser.parse_args()
    output = args.output.expanduser().resolve()
    if output.exists() and any(output.iterdir()):
        parser.error('Output must be new or empty')
    output.mkdir(parents=True, exist_ok=True)
    sources = Path(__file__).resolve().parents[1]
    scripts = output / 'scripts'
    scripts.mkdir()
    names = {}
    for source in [sources / 'ImportLabVIEW13.java', sources / 'ValidateExportLabVIEW13.java', sources / 'tests/TestResourceArchives.java']:
        text = source.read_text()
        name = source.stem + '_' + digest(source.read_bytes())[:12]
        (scripts / (name + '.java')).write_text(text.replace('public class ' + source.stem + ' ', 'public class ' + name + ' '))
        names[source.stem] = name + '.java'
    code = b'\xc3' + b'\x90' * 63
    (output / 'native-code.bin').write_bytes(code)
    runtime = output / 'runtime.bin'
    runtime.write_bytes(b'Synthetic runtime fingerprint, no runtime callbacks')
    resources = []
    address = 0x50000000
    for label, data in [('Original_VI', b'RSRC synthetic archive bytes\x00\xff'), ('VI_Metadata_XML', b'<VI><Version Major="13"/></VI>'), ('FrontPanel_XML', b'<Panel><Control name="Example"/></Panel>')]:
        path = output / (label + '.bin')
        path.write_bytes(data)
        resources.append(dict(label=label, path=str(path), size=len(data), address=address, sha256=digest(data)))
        address = (address + len(data) + 0xfffff) & ~0xfffff
    plan = dict(schema=1, vi='synthetic.vi', base=0x10000000, code_size=len(code), source_sha256=digest(code), patched_sha256=digest(code), runtime=str(runtime), runtime_sha256=digest(runtime.read_bytes()), changes=[], targets=[], entries=[], unresolved=[], dispatchers=[], resources=resources, portable_export=str(output / 'analysis.gzf'))
    plan_path = output / 'plan.json'
    plan_path.write_text(json.dumps(plan, indent=2))
    if args.ghidra == 'flatpak':
        temporary = output / 'tmp'
        temporary.mkdir()
        head = ['flatpak', 'run', '--filesystem=' + str(output), '--env=JAVA_TOOL_OPTIONS=-XX:-UsePerfData -XX:ActiveProcessorCount=1 -Djava.io.tmpdir=' + str(temporary), '--command=/app/lib/ghidra/support/analyzeHeadless', 'org.ghidra_sre.Ghidra']
    else:
        head = [str(Path(args.ghidra).expanduser().resolve() / 'support/analyzeHeadless')]
    projects = output / 'projects'
    projects.mkdir()
    flags = ['-max-cpu', '1', '-noanalysis', '-scriptPath', str(scripts)]
    commands = []

    def run(stage, command, markers):
        commands.append(dict(stage=stage, argv=command))
        with (output / (stage + '.log')).open('w') as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
        text = (output / (stage + '.log')).read_text(errors='replace')
        if result.returncode or any(marker not in text for marker in markers):
            raise RuntimeError(stage + ' failed; see ' + str(output / (stage + '.log')))

    try:
        run('apply', head + [str(projects), 'ResourceArchives', '-import', str(output / 'native-code.bin'), '-loader', 'BinaryLoader', '-loader-baseAddr', hex(plan['base']), '-processor', 'x86:LE:32:default', '-cspec', 'windows'] + flags + ['-postScript', names['ImportLabVIEW13'], str(plan_path), '-postScript', names['ValidateExportLabVIEW13'], str(plan_path), 'audit-only'], ['failed=0', 'LABVIEW_AUDIT_OK'])
        run('export', head + [str(projects), 'ResourceArchives', '-process', 'native-code.bin'] + flags + ['-postScript', names['ValidateExportLabVIEW13'], str(plan_path), '-postScript', names['TestResourceArchives'], str(plan_path), names['ValidateExportLabVIEW13'], 'legacy'], ['LABVIEW_AUDIT_OK', 'RESOURCE_LEGACY_OK', 'RESOURCE_ARCHIVES_TEST_OK 7'])
        # New plans must remain verifiable from the exported archive after all
        # original resource files and the runtime fingerprint file are gone.
        for resource in resources:
            Path(resource['path']).unlink()
        runtime.unlink()
        run('roundtrip', head + [str(projects), 'ResourceRoundTrip', '-import', str(output / 'analysis.gzf')] + flags + ['-postScript', names['ValidateExportLabVIEW13'], str(plan_path), 'audit-only', '-postScript', names['TestResourceArchives'], str(plan_path), names['ValidateExportLabVIEW13']], ['LABVIEW_AUDIT_OK', 'RESOURCE_ARCHIVES_TEST_OK 7'])
        audit = json.loads((output / 'ghidra-audit.json').read_text())
        assert audit['resource_archives_verified'] == 3
        assert [r['sha256'] for r in audit['resource_archives']] == [r['sha256'] for r in resources]
        (output / 'result.json').write_text(json.dumps(dict(status='passed', resources=3, negative_checks_per_project=7, source_files_required_after_import=False), indent=2))
        print('RESOURCE_ARCHIVES_CHECK_OK')
    finally:
        (output / 'commands.json').write_text(json.dumps(commands, indent=2))


if __name__ == '__main__':
    main()
