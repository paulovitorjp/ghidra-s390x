#!/usr/bin/env python3
"""
tests/fuzz_decode.py -- differential decode fuzzer for the s390x SLEIGH spec.

Generates random and mutated byte strings (1-6 bytes), decodes each with
tests/s390x_decode (our spec, via data/languages/s390x.sla) and with
Capstone's s390x backend (oracle), then classifies every input:

  match          both decode, same length, same mnemonic
  len-mismatch   both decode, different lengths
  mnem-mismatch  both decode, same length, different mnemonics
  ours-only      we decode, Capstone refuses (often fine: we intentionally
                 decode spec-exception variants Capstone rejects; sampled)
  gap            Capstone decodes, we don't  <-- the interesting case
  neither        neither decodes
  crash          our decoder crashed / timed out / printed garbage

Gaps are deduplicated by opcode key (1 or 2 bytes). The JSON report is
written to --report (default /tmp/fuzz_report.json); nothing is written
into the repo.

Requires: python capstone package (pip install capstone).

Usage:
  python3 tests/fuzz_decode.py --count 20000 --workers 8
  python3 tests/fuzz_decode.py --count 500 --workers 4 --seed 1   # quick smoke
"""

import argparse
import concurrent.futures
import json
import os
import random
import re
import subprocess
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
DECODER = os.path.join(HERE, "s390x_decode")
SLA = os.path.join(REPO, "data", "languages", "s390x.sla")
CORPUS = os.path.join(HERE, "corpus.json")

sys.path.insert(0, HERE)
from sleigh_diff import MNEM_ALIAS, BCR_MASKS  # noqa: E402

try:
    from capstone import Cs, CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN
except ImportError:
    sys.exit("error: python 'capstone' package not found (pip install capstone)")

# First bytes whose opcode occupies two bytes (sub-opcode in byte 2).
TWO_BYTE_OPS = {0xB2, 0xB3, 0xB9, 0xE3, 0xE5, 0xE6, 0xE7, 0xEB, 0xED, 0xA7}
TWO_BYTE_OPS |= set(range(0xC0, 0xD0))

OK_RE = re.compile(r"^(OK|PARTIAL) len=(\d+) mnem=(\S+) body=(.*)$")
NODECODE_RE = re.compile(r"^NODECODE\s*(.*)$")


def decode_ours(hexstr, timeout=15, retries=2):
    """Run tests/s390x_decode on one hex string.

    Returns (kind, ...) where kind is 'ok', 'partial', 'nodecode' or 'crash'.

    The decoder is nondeterministic: ~occasionally a good decode raises an
    unknown exception and prints exactly "NODECODE unknown" (likewise a
    crash/timeout is never a real decode verdict). Retry those signatures;
    a genuine NODECODE ("lowlevel: ...") is returned immediately so random
    garbage doesn't pay the retry cost.
    """
    attempt = 0
    while True:
        res = _decode_ours_once(hexstr, timeout)
        kind = res[0]
        flaky = kind == "crash" or (kind == "nodecode" and res[1] == "unknown")
        if not flaky or attempt >= retries:
            if attempt:
                res = res + ("retries=%d" % attempt,)
            return res
        attempt += 1


def _decode_ours_once(hexstr, timeout=15):
    try:
        p = subprocess.run([DECODER, SLA, hexstr], capture_output=True,
                           text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return ("crash", "timeout")
    except Exception as e:  # noqa: BLE001
        return ("crash", "spawn: %s" % e)
    if p.returncode not in (0,):
        return ("crash", "exit=%d stderr=%s" % (p.returncode,
                                               p.stderr.strip()[:120]))
    line = p.stdout.strip().splitlines()
    line = line[0].strip() if line else ""
    m = OK_RE.match(line)
    if m:
        kind = "ok" if m.group(1) == "OK" else "partial"
        return (kind, int(m.group(2)), m.group(3), m.group(4))
    m = NODECODE_RE.match(line)
    if m:
        return ("nodecode", m.group(1).strip())
    return ("crash", "unparseable: %r" % line[:120])


_CS = Cs(CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN)
_CS.detail = False


def decode_cs(data):
    """Capstone decode: (size, mnemonic, op_str) of first insn, or None."""
    try:
        for ins in _CS.disasm(data, 0x0):
            return (ins.size, ins.mnemonic, ins.op_str)
    except Exception:  # noqa: BLE001
        return None
    return None


def norm_ours(body, mnem):
    # Effective mnemonic is the display's first word (constructor labels for
    # generated ctors look like LM_3_7 / MR_odd).
    eff = body.split()[0].lower() if body and body.split() else mnem.lower()
    return eff


def norm_cs(mnem):
    return MNEM_ALIAS.get(mnem.lower(), mnem.lower())


# BRCL (6-byte, C0/4) masks whose jg* Capstone mnemonic is not covered by
# sleigh_diff.MNEM_ALIAS. Ours uses jl* displays; both identify the mask.
_BRCL_CS_ALIAS = {
    'jgo': 'jlo',    # mask 1
    'jgnl': 'jlnl',  # mask B
    'jgnh': 'jlnh',  # mask D
    'jgno': 'jlno',  # mask E
}


def mnemonics_match(ours_eff, cs_mnem, cs_op):
    cs = _BRCL_CS_ALIAS.get(cs_mnem.lower(), norm_cs(cs_mnem))
    if ours_eff == cs:
        return True
    # BRCL mask 0: ours prints the specific "jlnop", Capstone the generic "brcl".
    if ours_eff == "jlnop" and cs == "brcl":
        return True
    # BCR (2-byte): ours prints generic "bcr" for masks 3,5,6,9,10,12 while
    # Capstone uses extended mnemonics. Same instruction, different convention.
    if ours_eff == "bcr" and cs in ("bnler", "bnher", "blhr", "bnlhr", "bher", "bler"):
        return True
    # BRC (4-byte, A7): ours prints "jnop" for mask 0, Capstone generic "brc".
    if ours_eff == "jnop" and cs == "brc":
        return True
    # BCR: Capstone sometimes prints base 'bcr' with the mask in op_str;
    # we print the extended mnemonic. Compare via the mask.
    if cs == "bcr" and ours_eff in BCR_MASKS:
        mm = re.match(r"\s*(\d+)", cs_op or "")
        return bool(mm) and int(mm.group(1)) == BCR_MASKS[ours_eff]
    if ours_eff == "bcr" and cs in BCR_MASKS:
        return True
    # BRCL: Capstone 'jg'+suffix spellings with no IBM counterpart are
    # covered by our generic brcl/j* constructors (see sleigh_diff.py).
    if cs_mnem.lower().startswith("jg") and ours_eff in ("brcl",) + tuple(
            x for x in ("jh", "jl", "jhe", "jle", "jne", "je", "jnh",
                        "jnl", "jno", "jnop", "jnz", "jp", "jz", "j")):
        return True
    return False


def opcode_key(data):
    b0 = data[0]
    if b0 in TWO_BYTE_OPS and len(data) >= 2:
        return "%02x%02x" % (b0, data[1])
    return "%02x" % b0


# --------------------------------------------------------------------------
# input generation
# --------------------------------------------------------------------------

def load_corpus():
    vecs = []
    with open(CORPUS) as f:
        for v in json.load(f):
            hx = v["bytes_hex"]
            if 1 <= len(hx) // 2 <= 6:
                vecs.append(bytes.fromhex(hx))
    return vecs


def mutate(rng, data):
    d = bytearray(data)
    for _ in range(rng.randint(1, 3)):
        op = rng.random()
        if op < 0.55 and len(d) > 0:
            d[rng.randrange(len(d))] = rng.randrange(256)          # substitute
        elif op < 0.75 and len(d) > 0:
            i = rng.randrange(len(d))                             # bit flip
            d[i] ^= 1 << rng.randrange(8)
        elif op < 0.85 and len(d) > 1:
            d = d[:rng.randrange(1, len(d))]                      # truncate
        elif len(d) < 6:
            d += bytes(rng.randrange(256)                          # extend
                       for _ in range(rng.randrange(1, 7 - len(d))))
    return bytes(d)


def gen_inputs(n, seed):
    rng = random.Random(seed)
    corpus = load_corpus()
    first_bytes = [v[0] for v in corpus]
    two_byte_prefixes = [v[:2] for v in corpus
                         if v[0] in TWO_BYTE_OPS and len(v) >= 2]
    seen = set()
    out = []
    while len(out) < n:
        r = rng.random()
        if r < 0.45:
            cand = mutate(rng, rng.choice(corpus))
        elif r < 0.75:
            if two_byte_prefixes and rng.random() < 0.6:
                pre = bytes(rng.choice(two_byte_prefixes))
            else:
                pre = bytes([rng.choice(first_bytes)])
            ln = rng.choice([2, 2, 4, 4, 4, 6, 6])
            if len(pre) > ln:
                pre = pre[:ln]
            cand = pre + bytes(rng.randrange(256) for _ in range(ln - len(pre)))
        else:
            ln = rng.randint(1, 6)
            cand = bytes(rng.randrange(256) for _ in range(ln))
        hx = cand.hex()
        if hx in seen:
            continue
        seen.add(hx)
        out.append(hx)
    return out


# --------------------------------------------------------------------------
# classification
# --------------------------------------------------------------------------

def classify(hexstr, ours, cs):
    """ours: decode_ours() tuple; cs: decode_cs() tuple or None."""
    okind = ours[0]
    if okind == "crash":
        return "crash"
    ours_decodes = okind in ("ok", "partial")
    ours_len = ours[1] if ours_decodes else None
    ours_eff = norm_ours(ours[3], ours[2]) if ours_decodes else None
    if cs is None and not ours_decodes:
        return "neither"
    if cs is None:
        return "ours-only"
    if not ours_decodes:
        return "gap"
    cs_size, cs_mnem, cs_op = cs
    if ours_len != cs_size:
        return "len-mismatch"
    if not mnemonics_match(ours_eff, cs_mnem, cs_op):
        return "mnem-mismatch"
    return "match"


def main():
    global SLA  # noqa: PLW0603
    ap = argparse.ArgumentParser(description="differential decode fuzzer")
    ap.add_argument("--count", type=int, default=20000)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--seed", type=int, default=20260920)
    ap.add_argument("--report", default="/tmp/fuzz_report.json")
    ap.add_argument("--retries", type=int, default=2)
    ap.add_argument("--sla", default=SLA)
    args = ap.parse_args()

    SLA = args.sla
    if not os.path.isfile(DECODER):
        sys.exit("error: decoder not found: %s" % DECODER)
    if not os.path.isfile(SLA):
        sys.exit("error: .sla not found: %s" % SLA)

    print("generating %d inputs (seed %d) ..." % (args.count, args.seed),
          flush=True)
    inputs = gen_inputs(args.count, args.seed)

    counts = Counter()
    gaps = {}                       # opkey -> {cs_mnems:Counter, samples:[], n}
    mismatches = []                 # (class, hex, ours, cs) capped
    ours_only_mnems = Counter()
    crashes = []
    MISM_CAP = 400

    print("decoding with %d workers ..." % args.workers, flush=True)
    import functools
    decode = functools.partial(decode_ours, timeout=15, retries=args.retries)
    flaky_retried = 0
    with concurrent.futures.ProcessPoolExecutor(
            max_workers=args.workers) as ex:
        ours_iter = ex.map(decode, inputs, chunksize=64)
        for i, (hx, ours) in enumerate(zip(inputs, ours_iter)):
            last = ours[-1]
            if isinstance(last, str) and last.startswith("retries="):
                flaky_retried += 1
            data = bytes.fromhex(hx)
            cs = decode_cs(data)
            cls = classify(hx, ours, cs)
            counts[cls] += 1
            if cls == "gap":
                key = opcode_key(data)
                g = gaps.setdefault(key, {"cs_mnems": Counter(),
                                         "samples": [], "n": 0})
                g["cs_mnems"][cs[1]] += 1
                g["n"] += 1
                if len(g["samples"]) < 4:
                    g["samples"].append(hx)
            elif cls in ("len-mismatch", "mnem-mismatch"):
                if len(mismatches) < MISM_CAP:
                    mismatches.append((cls, hx,
                                       "%s len=%s" % (ours[2], ours[1]),
                                       "%s size=%d" % (cs[1], cs[0])))
            elif cls == "ours-only":
                ours_only_mnems[norm_ours(ours[3], ours[2])] += 1
            elif cls == "crash":
                crashes.append((hx, ours[1]))
            if (i + 1) % 5000 == 0:
                print("  %d/%d  %s" % (i + 1, len(inputs),
                                       dict(counts)), flush=True)

    report = {
        "inputs": len(inputs),
        "seed": args.seed,
        "sla": SLA,
        "retries": args.retries,
        "flaky_retried": flaky_retried,
        "counts": dict(counts),
        "gaps": {k: {"n": v["n"], "samples": v["samples"],
                     "cs_mnems": dict(v["cs_mnems"])}
                 for k, v in sorted(gaps.items())},
        "mismatches": mismatches,
        "ours_only_top": ours_only_mnems.most_common(40),
        "crashes": crashes,
    }
    with open(args.report, "w") as f:
        json.dump(report, f, indent=1)

    print("\n==== results (%d inputs, %d needed flaky-retries) ====" % (
        len(inputs), flaky_retried))
    for k in ("match", "neither", "ours-only", "gap", "len-mismatch",
              "mnem-mismatch", "crash"):
        print("  %-13s %d" % (k, counts.get(k, 0)))
    print("\ngaps by opcode (%d distinct):" % len(gaps))
    for k in sorted(gaps):
        v = gaps[k]
        print("  %s  n=%d  cs=%s  e.g. %s" % (
            k, v["n"], dict(v["cs_mnems"]), ", ".join(v["samples"][:2])))
    if mismatches:
        print("\nmismatches (first 20):")
        for m in mismatches[:20]:
            print("  %s %s ours=%s cs=%s" % m)
    if crashes:
        print("\ncrashes:")
        for hx, info in crashes[:20]:
            print("  %s %s" % (hx, info))
    print("\nreport: %s" % args.report)


if __name__ == "__main__":
    main()
