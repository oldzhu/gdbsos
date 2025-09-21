#!/usr/bin/env python3
import argparse
import json
import os
import re
from typing import List, Dict, Any, Tuple


def read_text(path: str) -> str:
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        return f.read()


def _extract_soshelp_block(text: str) -> str:
    """Extract the soshelp output block from an LLDB log: lines printed after '(lldb) soshelp'
    up to the next LLDB prompt '(lldb) '. Returns just the inner block text.
    """
    lines = text.splitlines()
    out: List[str] = []
    capture = False
    for ln in lines:
        if '(lldb) soshelp' in ln:
            capture = True
            continue
        if capture and ln.startswith('(lldb) '):
            break
        if capture:
            out.append(ln)
    return '\n'.join(out)


def parse_lldb_soshelp_block(text: str) -> List[Dict[str, Any]]:
    """Parse the LLDB-style soshelp static block lines with format like:
    'd, readmemory <address>                   Dumps memory contents.'
    Use a regex to split on 2+ spaces between left (names/usage) and right (description).
    Return entries with {names: [...], help: str, order: int}.
    """
    entries: List[Dict[str, Any]] = []
    order = 0
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line:
            continue
        m = re.match(r'^\s*(?P<left>.+?)\s{2,}(?P<right>.+)\s*$', line)
        if not m:
            continue
        left = m.group('left').strip()
        right = m.group('right').strip()
        # split aliases by comma in left column; drop any usage suffix like '<address>'
        names: List[str] = []
        for seg in left.split(','):
            seg = seg.strip()
            # take first token as command name (up to whitespace)
            seg_name = seg.split()[0] if seg else ''
            if seg_name:
                names.append(seg_name)
        names = [n for n in [n.strip() for n in names] if n]
        if not names:
            continue
        entries.append({'names': names, 'help': right, 'order': order})
        order += 1
    return entries


def build_manifest(pre_text: str, post_text: str) -> Dict[str, Any]:
    pre_block = _extract_soshelp_block(pre_text)
    post_block = _extract_soshelp_block(post_text)
    pre_entries = parse_lldb_soshelp_block(pre_block)
    commands = []
    seen = set()
    for e in pre_entries:
        help_text = e['help']
        for i, name in enumerate(e['names']):
            key = name.lower()
            if key in seen:
                continue
            seen.add(key)
            commands.append({
                'name': key,
                'aliases': [n.lower() for n in e['names'] if n.lower() != key],
                'help': help_text,
                'origin': 'lldb',
                'staticList': True,
                'staticOrder': e['order'],
            })
    manifest = {
        'source': 'lldb-capture',
        'commands': commands,
        'meta': {
            'preRunCaptured': bool(pre_block.strip()),
            'postRunCaptured': bool(post_block.strip()),
        }
    }
    return manifest


def main():
    ap = argparse.ArgumentParser(description='Parse LLDB soshelp capture into manifest.json')
    ap.add_argument('--in', dest='indir', required=True, help='Directory with pre_lldb.log and post_lldb.log')
    ap.add_argument('--out', dest='outfile', required=True, help='Output manifest.json path')
    args = ap.parse_args()

    pre_log = os.path.join(args.indir, 'pre_lldb.log')
    post_log = os.path.join(args.indir, 'post_lldb.log')
    pre_text = read_text(pre_log) if os.path.exists(pre_log) else ''
    post_text = read_text(post_log) if os.path.exists(post_log) else ''

    manifest = build_manifest(pre_text, post_text)
    os.makedirs(os.path.dirname(args.outfile), exist_ok=True)
    with open(args.outfile, 'w', encoding='utf-8') as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
    print(f"Wrote manifest: {args.outfile}")


if __name__ == '__main__':
    main()
