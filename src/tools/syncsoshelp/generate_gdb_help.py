#!/usr/bin/env python3
import argparse
import json
import os
from typing import Dict, Any, List


def load_json(path: str) -> Any:
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def merge_manifest(manifest: Dict[str, Any], overrides: Dict[str, Any]) -> Dict[str, Any]:
    # Simple merge: start with manifest commands; add/override by name from overrides
    by_name = {c['name'].lower(): c for c in manifest.get('commands', [])}
    for oc in overrides.get('commands', []):
        by_name[oc['name'].lower()] = {**by_name.get(oc['name'].lower(), {}), **oc}
    merged = list(by_name.values())
    alias_safety = overrides.get('aliasSafety', {})
    return {
        'commands': merged,
        'aliasSafety': alias_safety,
    }


def generate_py(merged: Dict[str, Any]) -> str:
    # Build COMMAND_HELP
    cmd_help_items = []
    for c in merged['commands']:
        name = c['name']
        help_text = c.get('help', f"Run SOS command '{name}'.")
        cmd_help_items.append((name, help_text))
    cmd_help_items.sort(key=lambda x: x[0])

    # Build static block lines in order when staticList
    static_entries = [c for c in merged['commands'] if c.get('staticList')]
    static_entries.sort(key=lambda x: x.get('staticOrder', 10_000))
    static_lines: List[str] = []
    for c in static_entries:
        names = [c['name']] + c.get('aliases', [])
        head = ', '.join(names)
        static_lines.append(f"{head} -- {c.get('help', '')}")

    # MANUAL_EXPORTS is left empty here (we rely on existing mapping in sos.py unless later fed in overrides)
    py = []
    py.append('# Generated file: do not edit by hand\n')
    py.append('GENERATED_COMMAND_HELP = {\n')
    for k, v in cmd_help_items:
        py.append(f"    '{k}': {v!r},\n")
    py.append('}\n\n')
    py.append('GENERATED_EXPORTS = {\n}\n\n')
    py.append('GENERATED_STATIC_BLOCK = [\n')
    for ln in static_lines:
        py.append(f"    {ln!r},\n")
    py.append(']\n')
    return ''.join(py)


def main():
    ap = argparse.ArgumentParser(description='Generate _generated_help.py from manifest + overrides')
    ap.add_argument('--manifest', required=True)
    ap.add_argument('--overrides', required=True)
    ap.add_argument('--out', default='src/gdbplugin/sos/_generated_help.py')
    args = ap.parse_args()

    manifest = load_json(args.manifest)
    overrides = load_json(args.overrides)
    merged = merge_manifest(manifest, overrides)
    code = generate_py(merged)
    out_path = args.out
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(code)
    print(f"Wrote {out_path}")


if __name__ == '__main__':
    main()
