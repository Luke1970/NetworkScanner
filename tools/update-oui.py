#!/usr/bin/env python3
"""Rebuild app/src/main/assets/oui.dat from the IEEE MA-L registry.

Usage: tools/update-oui.py [path/to/oui.csv]   (downloads it when no path is given)
Output lines: "AABBCC<TAB>Organization", sorted by prefix.
"""
import csv, gzip, io, pathlib, re, sys, urllib.request

URL = "https://standards-oui.ieee.org/oui/oui.csv"
OUT = pathlib.Path(__file__).resolve().parent.parent / "app/src/main/assets/oui.dat"

def main():
    if len(sys.argv) > 1:
        raw = pathlib.Path(sys.argv[1]).read_bytes()
    else:
        req = urllib.request.Request(URL, headers={"User-Agent": "networkscanner-oui-update"})
        raw = urllib.request.urlopen(req, timeout=60).read()
    rows = {}
    for row in csv.DictReader(io.StringIO(raw.decode("utf-8", "replace"))):
        prefix = row["Assignment"].strip().upper()
        org = re.sub(r"\s+", " ", row["Organization Name"]).strip()
        if re.fullmatch(r"[0-9A-F]{6}", prefix) and org:
            rows[prefix] = org
    text = "".join(f"{p}\t{rows[p]}\n" for p in sorted(rows))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(OUT, "wt", encoding="utf-8", compresslevel=9) as f:
        f.write(text)
    print(f"{len(rows)} prefixes -> {OUT} ({OUT.stat().st_size // 1024} KiB)")

if __name__ == "__main__":
    main()
