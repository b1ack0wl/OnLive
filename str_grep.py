#!/usr/bin/env python3
"""Extract printable strings from a binary, optionally filtered by patterns."""
import re, sys

def strings(path, min_len=6):
    with open(path, 'rb') as f:
        data = f.read()
    pattern = re.compile(rb'[\x20-\x7E]{%d,}' % min_len)
    for m in pattern.finditer(data):
        yield m.start(), m.group().decode('latin-1')

def main():
    if len(sys.argv) < 2:
        print("usage: str_grep.py <file> [pattern1 pattern2 ...]")
        sys.exit(1)
    path = sys.argv[1]
    patterns = [p.lower() for p in sys.argv[2:]]
    if not patterns:
        for off, s in strings(path):
            print(f"{off:08X}  {s}")
    else:
        for off, s in strings(path):
            sl = s.lower()
            if any(p in sl for p in patterns):
                print(f"{off:08X}  {s}")

if __name__ == '__main__':
    main()
