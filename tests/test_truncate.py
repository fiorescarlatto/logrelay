"""Truncation unit test for both implementations."""
import importlib.util

CASES = []


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def make_msg(builder):
    """Build a message through the real encoder so both are tested as shipped."""
    raise NotImplementedError


def check(mod, name, msg, max_len, expect_full):
    out = mod.truncate_message(msg, max_len)
    # base = header + sd is the floor: a valid message is never cut into it
    header, sd, _ = mod._split_message(msg)
    floor = len(header) + (1 if sd else 0) + len(sd)
    if max_len and max_len >= floor:
        ok = len(out) <= max_len
    elif max_len:
        ok = out == header + b" " + sd  # below floor: send header+sd intact
    else:
        ok = out == msg
    if expect_full:
        ok = ok and out == msg
    try:
        out.decode("utf-8")
        utf8_ok = True
    except UnicodeDecodeError:
        utf8_ok = False
    status = "OK  " if ok and utf8_ok else "FAIL"
    print(f"{status} {name} max={max_len:3d} len={len(out):3d} {out!r}")
    return ok and utf8_ok


def main():
    sc = load("sc", "logrelay.py")
    lib = load("lib", "tests/logrelay_library.py")

    all_ok = True
    for mod, name in ((sc, "sc "), (lib, "lib")):
        # truncated-message input exercising SD, BOM and multibyte chars
        msg = (b'<14>1 2026-09-01T00:00:00.000000+02:00 h a 1 - '
               b'[x@1 k="v"] \xef\xbb\xbf' + "héllo wörld".encode("utf-8"))
        for ml in (0, 999, 70, 60, 55, 54, 40):
            all_ok &= check(mod, name, msg, ml, expect_full=ml in (0, 999))
        # no-SD variant
        msg2 = b"<14>1 2026-09-01T00:00:00.000000+02:00 h a 1 - - " + b"\xef\xbb\xbf" + "abcdef".encode()
        for ml in (0, 60, 50, 49, 30):
            all_ok &= check(mod, name, msg2, ml, expect_full=ml in (0, 60))
    print("ALL OK" if all_ok else "FAILURES PRESENT")
    sys_code = 0 if all_ok else 1
    raise SystemExit(sys_code)


import sys  # noqa: E402

if __name__ == "__main__":
    main()
