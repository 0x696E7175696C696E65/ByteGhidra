#!/usr/bin/env python3
"""Summarize readability signals in decompiler datatest output.

This helper is intentionally lightweight: pipe decompiler C output into it to
track whether quality work reduces noisy constructs without hiding semantics.
"""

from __future__ import annotations

import re
import sys


METRICS = {
    "casts": re.compile(r"\([A-Za-z_][A-Za-z0-9_ \*]*\)"),
    "copy_temps": re.compile(r"\b(?:uVar|iVar|bVar|cVar|lVar|local)\d+\b"),
    "gotos": re.compile(r"\bgoto\b"),
    "switches": re.compile(r"\bswitch\s*\("),
    "loops": re.compile(r"\b(?:for|while|do)\b"),
    "semantic_comments": re.compile(r"/\*\s*(?:xor|checksum|key|password|ascii|hex)", re.I),
}


def main() -> int:
    text = sys.stdin.read()
    if not text:
        print("No input received. Pipe decompiler C output into this script.", file=sys.stderr)
        return 1

    for name, pattern in METRICS.items():
        print(f"{name}: {len(pattern.findall(text))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
