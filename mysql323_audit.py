#!/usr/bin/env python3
import argparse
import csv
import sys
import time
from collections import defaultdict
from pathlib import Path

MASK = 0xFFFFFFFF


def mysql323(password):
    if password == "":
        return ""
    nr = 1345345333
    add = 7
    nr2 = 0x12345671
    for ch in password:
        if ch == " " or ch == "\t":
            continue
        c = ord(ch)
        nr ^= ((((nr & 63) + add) * c) + ((nr << 8) & MASK)) & MASK
        nr2 = (nr2 + (((nr2 << 8) & MASK) ^ nr)) & MASK
        add += c
    return "%08x%08x" % (nr & 0x7FFFFFFF, nr2 & 0x7FFFFFFF)


VECTORS = [
    ("password", "5d2e19393cc5ef67"),
    ("abc", "7cd2b5942be28759"),
    ("", ""),
]


def self_test():
    ok = True
    for pw, expected in VECTORS:
        got = mysql323(pw)
        if got != expected:
            ok = False
        print("%s  mysql323(%r) = %s  expected %s" %
            ("ok  " if got == expected else "FAIL", pw, got, expected))
    print("passed" if ok else "FAILED")
    return 0 if ok else 1


def load_hashes(path, id_col, hash_col, delimiter, has_header):
    table = defaultdict(list)
    with path.open(encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.reader(fh, delimiter=delimiter)
        for lineno, row in enumerate(reader, 1):
            if has_header and lineno == 1:
                continue
            if not row or row[0].lstrip().startswith("#"):
                continue
            if hash_col >= len(row):
                continue
            h = row[hash_col].strip().lower()
            ident = row[id_col].strip() if id_col < len(row) else ""
            table[h].append(ident or "line%d" % lineno)
    return dict(table)


def mutations(word, enable):
    seen = set()
    if word not in seen:
        seen.add(word)
        yield word
    if not enable:
        return
    bases = {word, word.lower(), word.upper(), word.capitalize()}
    suffixes = ["1", "2", "12", "123", "1234", "01", "123456", "!", "@", "#"]
    suffixes += [str(y) for y in range(1990, 2031)]
    leet = str.maketrans({"a": "@", "e": "3", "i": "1", "o": "0", "s": "$"})
    for base in bases:
        for suf in suffixes:
            w = base + suf
            if w not in seen:
                seen.add(w)
                yield w
        w = base.translate(leet)
        if w != base and w not in seen:
            seen.add(w)
            yield w


def iter_wordlist(path):
    if path == "-":
        for line in sys.stdin:
            yield line.rstrip("\r\n")
    else:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                yield line.rstrip("\r\n")


def count_lines(path):
    n = 0
    with open(path, "rb") as fh:
        for _ in fh:
            n += 1
    return n


def progress(done, total, cracked, naccts, start):
    el = time.time() - start
    rate = done / el if el > 0 else 0
    if total:
        pct = 100.0 * done / total
        filled = int(pct // 5)
        bar = "#" * filled + "-" * (20 - filled)
        eta = (total - done) / rate if rate > 0 else 0
        sys.stderr.write("\r[%s] %5.1f%%  %d/%d  %.0f/s  cracked %d/%d  eta %ds   "
            % (bar, pct, done, total, rate, cracked, naccts, eta))
    else:
        sys.stderr.write("\r%d words  %.0f/s  cracked %d/%d   "
            % (done, rate, cracked, naccts))
    sys.stderr.flush()


def run(args):
    path = Path(args.hashes)
    if not path.exists():
        print("hashes file not found: %s" % path, file=sys.stderr)
        return 2

    if args.wordlist == "-" and sys.stdin.isatty():
        print("no wordlist given. pass --wordlist FILE or pipe one into stdin",
            file=sys.stderr)
        return 2

    table = load_hashes(path, args.id_col, args.hash_col,
                        args.delimiter, args.has_header)
    total = sum(len(v) for v in table.values())
    if not total:
        print("no hashes loaded (check --hash-col / --delimiter)", file=sys.stderr)
        return 2

    blank = table.pop("", [])
    cracked = {}
    remaining = set(table)

    show = sys.stderr.isatty()
    wl_total = count_lines(args.wordlist) if show and args.wordlist != "-" else 0

    start = time.time()
    tried = 0
    done = 0
    last = 0.0
    for raw in iter_wordlist(args.wordlist):
        if not remaining:
            break
        done += 1
        for cand in mutations(raw, args.mutations):
            tried += 1
            h = mysql323(cand)
            if h in remaining:
                cracked[h] = cand
                remaining.discard(h)
                if not remaining:
                    break
        if show and time.time() - last > 0.2:
            last = time.time()
            progress(done, wl_total, len(cracked), len(table), start)
    if show:
        progress(done, wl_total, len(cracked), len(table), start)
        sys.stderr.write("\n")
    elapsed = max(time.time() - start, 1e-9)

    rows = []
    for h, pw in cracked.items():
        for ident in table[h]:
            rows.append((ident, pw, h))
    rows.sort(key=lambda r: r[0].lower())

    out = open(args.output, "w", encoding="utf-8") if args.output else sys.stdout
    try:
        for ident, pw, h in rows:
            out.write("%s\t%s\t%s\n" % (ident, pw, h))
        for ident in sorted(blank, key=str.lower):
            out.write("%s\t<BLANK>\t\n" % ident)
    finally:
        if args.output:
            out.close()

    weak = len(rows) + len(blank)
    e = sys.stderr
    print("", file=e)
    print("accounts audited : %d" % total, file=e)
    print("candidates tried : %d" % tried, file=e)
    print("blank passwords  : %d" % len(blank), file=e)
    print("cracked          : %d" % len(rows), file=e)
    print("weak total       : %d (%.1f%%)" % (weak, 100.0 * weak / total), file=e)
    print("elapsed          : %.1fs (%.0f h/s)" % (elapsed, tried / elapsed), file=e)
    if args.show_dupes:
        dupes = {h: ids for h, ids in table.items() if len(ids) > 1}
        reused = sum(len(ids) for ids in dupes.values())
        print("shared passwords : %d accounts, %d hashes" % (reused, len(dupes)), file=e)
    if args.output:
        print("written to       : %s" % args.output, file=e)
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="mysql323-audit",
        description="Offline dictionary auditor for MySQL323 / OLD_PASSWORD() hashes.")
    p.add_argument("--hashes")
    p.add_argument("--wordlist", default="-")
    p.add_argument("--id-col", type=int, default=0)
    p.add_argument("--hash-col", type=int, default=1)
    p.add_argument("--delimiter", default=",")
    p.add_argument("--has-header", action="store_true")
    p.add_argument("--mutations", action="store_true")
    p.add_argument("--show-dupes", action="store_true")
    p.add_argument("--output")
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args(argv)
    if args.self_test:
        return self_test()
    if not args.hashes:
        p.error("--hashes is required (or use --self-test)")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
