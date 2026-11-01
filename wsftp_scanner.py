#!/usr/bin/env python3
"""Detection-only local triage for the Progress WS_FTP Server
October 2026 patch batch (15 CVEs, published 2026-10-29).

Headline flaw: CVE-2026-84295, improper authentication, CVSS 10.0,
unauthenticated access to sensitive information including
administrative credentials. The batch also includes OS command
injection (CVE-2026-90868, 9.9; CVE-2026-90865, 9.0), missing
authorisation and path traversal flaws at 9.1 (CVE-2026-90863,
CVE-2026-90864, CVE-2026-90866), and nine further flaws down to
medium severity. No active exploitation and no public proof of
concept had been reported as of 2026-10-31; this tool grades
exposure, it does not claim exploitation.

The grading trap is the split fix table. Three CVEs
(CVE-2026-84294, CVE-2026-84295, CVE-2026-84296) are fixed in
2024.0.6 / 2025.0.3, while the other twelve are fixed only in
2024.0.7 / 2025.0.4. A host on 2024.0.6 or 2025.0.3 has closed the
10.0 flaw and is still open to the 9.9 command injection flaw.
Upgrading to the first patched build is not enough; this tool
grades the two groups separately and says so plainly.

This tool never touches the network, never probes a server, never
sends a payload. WS_FTP Server runs on Windows, and remote banner
fingerprinting is unreliable (the login banner can be hidden and
SSH identification can be suppressed), so the scanner grades a
version you supply or one it reads on the Windows host itself:
the Programs and Features uninstall entries, via winreg. On any
other platform, pass --version (from WS_FTP Manager, About, or
Programs and Features) or --registry-json (an exported list of
uninstall entries) instead.

Version numbering: Progress sells the same releases under two
numberings. 2024.0 is 9.0 and 2025.0 is 10.0, so 9.0.6 means
2024.0.6 and 10.0.4 means 2025.0.4. This tool accepts both and
normalises to the 2024.0 / 2025.0 form before grading. Releases
older than 2024.0 (9.0), including 2022.0 (8.8.x), have no patched
build in their branch: they grade VULNERABLE for both groups and
the fix is an upgrade to 2024.0.7 or 2025.0.4.

Exit codes: 0 = nothing vulnerable found, 2 = vulnerable finding,
1 = scan error. UNKNOWN does not change the exit code, but it is
not clean.
"""

import argparse
import json
import sys

# Group A: fixed in 2024.0.6 / 2025.0.3.
# Scores shown only where a CVE record was checked: 84295 is 10.0,
# 84294 is 7.7. 84296's individual score was not confirmed in the
# sources checked; its group and fixed version are confirmed, and
# the batch write-up describes it as a multi-factor authentication
# bypass. The tool grades it by group, not by an asserted score.
GROUP_A = (
    ("CVE-2026-84294", "7.7", "path traversal"),
    ("CVE-2026-84295", "10.0", "improper authentication, admin credentials exposed"),
    ("CVE-2026-84296", None, "multi-factor authentication bypass (score not individually confirmed)"),
)

# Group B: fixed in 2024.0.7 / 2025.0.4.
# Scores shown only where a CVE record was checked. 90861, 90862
# and 90870 sit in this group by the batch count (3 + 12 = 15) and
# the "remaining twelve" fixed-version statement; their individual
# scores and flaw types were not confirmed in the sources checked,
# so they are listed without an asserted score or type.
GROUP_B = (
    ("CVE-2026-90861", None, None),
    ("CVE-2026-90862", None, "multi-factor authentication bypass"),
    ("CVE-2026-90863", "9.1", "missing authorisation in the administrative interface"),
    ("CVE-2026-90864", "9.1", "path traversal"),
    ("CVE-2026-90865", "9.0", "OS command injection"),
    ("CVE-2026-90866", "9.1", "path traversal"),
    ("CVE-2026-90867", "8.1", "improper access control in the Web Admin console"),
    ("CVE-2026-90868", "9.9", "OS command injection"),
    ("CVE-2026-90869", "7.5", "SSH service denial of service"),
    ("CVE-2026-90870", None, None),
    ("CVE-2026-90871", "5.3", "path traversal"),
    ("CVE-2026-90872", "6.6", "code injection in the Manager web console"),
)

# Branch -> (group A fixed, group B fixed), as (year, minor, patch).
FIXED = {
    (2024, 0): ((2024, 0, 6), (2024, 0, 7)),
    (2025, 0): ((2025, 0, 3), (2025, 0, 4)),
}

VULNERABLE = "VULNERABLE"
FIXED_VERDICT = "FIXED"
UNKNOWN = "UNKNOWN"
NO_FIX = "NO_FIX_IN_BRANCH"


def parse_version(raw):
    """Parse a WS_FTP Server version string.

    Accepts '2024.0.6', '2025.0.4', legacy '9.0.6' (= 2024.0.6)
    and '10.0.4' (= 2025.0.4), with optional build suffixes after
    a space or dash. Returns a (year, minor, patch) tuple, or None
    when unparseable.
    """
    if raw is None:
        return None
    text = str(raw).strip()
    if not text:
        return None
    # Drop build suffixes: '2024.0.6 (build 123)' or '2024.0.6-123'.
    text = text.split()[0].split("-")[0]
    parts = text.split(".")
    if len(parts) < 2 or not all(p.isdigit() for p in parts):
        return None
    nums = tuple(int(p) for p in parts)
    while len(nums) < 3:
        nums = nums + (0,)
    nums = nums[:3]
    if nums[0] == 9:
        # Marketing 9.0.x is the 2024.0 branch.
        return (2024, 0, nums[2])
    if nums[0] == 10:
        # Marketing 10.0.x is the 2025.0 branch.
        return (2025, 0, nums[2])
    return nums


def fmt_version(version):
    return ".".join(str(n) for n in version)


def grade(version):
    """Grade one parsed version. Returns a result dict.

    Groups are graded independently against their own fixed build
    in the same branch, so the 2024.0.6 / 2025.0.3 trap (group A
    fixed, group B still open) is visible instead of averaged away.
    """
    if version is None:
        return {
            "version": None,
            "verdict": UNKNOWN,
            "detail": "unparseable version string",
            "groups": [],
            "notes": [],
        }
    branch = version[:2]
    notes = []
    if branch not in FIXED:
        if version < (2024, 0, 0):
            return {
                "version": fmt_version(version),
                "verdict": VULNERABLE,
                "detail": (
                    "version %s predates the 2024.0 branch and has no "
                    "patched build in its branch; upgrade to 2024.0.7 "
                    "or 2025.0.4" % fmt_version(version)
                ),
                "groups": [
                    {"group": "A", "cves": [c[0] for c in GROUP_A],
                     "verdict": NO_FIX, "fixed": "2024.0.6 / 2025.0.3"},
                    {"group": "B", "cves": [c[0] for c in GROUP_B],
                     "verdict": NO_FIX, "fixed": "2024.0.7 / 2025.0.4"},
                ],
                "notes": [
                    "Progress lifecycle notes say versions older than "
                    "2024.0 (9.0) are no longer being patched; the fix "
                    "is a branch upgrade, not a patch in place",
                ],
            }
        return {
            "version": fmt_version(version),
            "verdict": UNKNOWN,
            "detail": (
                "branch %s is not in this tool's fixed-version table "
                "(2024.0 and 2025.0 only); check the Progress advisory "
                "before calling this host fixed" % ".".join(str(n) for n in branch)
            ),
            "groups": [],
            "notes": [],
        }
    fixed_a, fixed_b = FIXED[branch]
    groups = []
    for label, cves, fixed in (
        ("A", GROUP_A, fixed_a),
        ("B", GROUP_B, fixed_b),
    ):
        if version < fixed:
            groups.append({
                "group": label,
                "cves": [c[0] for c in cves],
                "verdict": VULNERABLE,
                "fixed": fmt_version(fixed),
            })
        else:
            groups.append({
                "group": label,
                "cves": [c[0] for c in cves],
                "verdict": FIXED_VERDICT,
                "fixed": fmt_version(fixed),
            })
    verdicts = [g["verdict"] for g in groups]
    if VULNERABLE in verdicts:
        if groups[0]["verdict"] == FIXED_VERDICT and groups[1]["verdict"] == VULNERABLE:
            detail = (
                "TRAP: %s closes group A (fixed %s) but is still open "
                "to group B, including CVE-2026-90868 (9.9); upgrade "
                "to %s" % (fmt_version(version), fmt_version(fixed_a), fmt_version(fixed_b))
            )
            notes.append(
                "do not stop at the first patched build: 2024.0.6 / "
                "2025.0.3 fixes only three of the fifteen CVEs"
            )
        else:
            detail = "%s is below the fixed build for at least one group" % fmt_version(version)
        verdict = VULNERABLE
    else:
        verdict = FIXED_VERDICT
        detail = "%s is at or above both fixed builds (%s, %s)" % (
            fmt_version(version), fmt_version(fixed_a), fmt_version(fixed_b))
    return {
        "version": fmt_version(version),
        "verdict": verdict,
        "detail": detail,
        "groups": groups,
        "notes": notes,
    }


def find_wsftp(entries):
    """Pick the WS_FTP Server entry from uninstall-entry dicts.

    Each entry needs DisplayName and DisplayVersion. Returns the
    matching entry, preferring an exact 'WS_FTP Server' name over
    a looser match (e.g. a client install), or None.
    """
    exact = None
    loose = None
    for entry in entries or []:
        name = str(entry.get("DisplayName") or "")
        version = str(entry.get("DisplayVersion") or "")
        if not name or not version:
            continue
        lowered = name.lower()
        if "ws_ftp" not in lowered and "ws ftp" not in lowered:
            continue
        if name.strip().lower() in ("ws_ftp server", "ws ftp server", "progress ws_ftp server"):
            exact = entry
            break
        if loose is None and "server" in lowered:
            loose = entry
    return exact or loose


def read_windows_uninstall():
    """Read Programs and Features entries on a Windows host.

    Returns (entries, error). Only winreg is used, only the local
    uninstall keys, nothing leaves the host.
    """
    try:
        import winreg
    except ImportError as exc:
        return None, "winreg is unavailable: run --local on the Windows host itself (%s)" % exc
    entries = []
    roots = (
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    )
    for root, path in roots:
        try:
            key = winreg.OpenKey(root, path)
        except OSError:
            continue
        index = 0
        while True:
            try:
                sub = winreg.EnumKey(key, index)
            except OSError:
                break
            index += 1
            try:
                subkey = winreg.OpenKey(key, sub)
                name, _ = winreg.QueryValueEx(subkey, "DisplayName")
                version, _ = winreg.QueryValueEx(subkey, "DisplayVersion")
                entries.append({"DisplayName": name, "DisplayVersion": version})
            except OSError:
                continue
    return entries, None


def render_text(result):
    lines = []
    lines.append("version: %s" % (result.get("version") or "?"))
    if result.get("source"):
        lines.append("source: %s" % result["source"])
    lines.append("verdict: %s (%s)" % (result["verdict"], result["detail"]))
    for group in result.get("groups", []):
        lines.append("group %s: %s (fixed %s)" % (group["group"], group["verdict"], group["fixed"]))
        lines.append("  CVEs: %s" % ", ".join(group["cves"]))
    for note in result.get("notes", []):
        lines.append("Note: %s" % note)
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Detection-only WS_FTP Server October 2026 patch-batch triage.")
    parser.add_argument("--version", help="Installed WS_FTP Server version, e.g. 2024.0.6 or 9.0.6")
    parser.add_argument("--local", action="store_true",
                        help="Read the installed version from Windows Programs and Features (winreg) on this host")
    parser.add_argument("--registry-json", metavar="PATH",
                        help="JSON list of uninstall entries ({DisplayName, DisplayVersion}) to grade, e.g. an offline Programs and Features export")
    parser.add_argument("--list", action="store_true", help="Print the full 15-CVE table and exit")
    parser.add_argument("--json", action="store_true", help="Machine-readable JSON output")
    args = parser.parse_args(argv)

    if args.list:
        table = []
        for cve, score, flaw in GROUP_A:
            table.append({"cve": cve, "score": score, "flaw": flaw, "group": "A", "fixed": "2024.0.6 / 2025.0.3"})
        for cve, score, flaw in GROUP_B:
            table.append({"cve": cve, "score": score, "flaw": flaw, "group": "B", "fixed": "2024.0.7 / 2025.0.4"})
        if args.json:
            print(json.dumps(table, indent=2))
        else:
            for row in table:
                print("%s | score %s | group %s | fixed %s | %s" % (
                    row["cve"], row["score"] or "not individually confirmed",
                    row["group"], row["fixed"], row["flaw"] or "type not individually confirmed"))
        return 0

    raw = args.version
    source = None
    if args.local:
        entries, error = read_windows_uninstall()
        if error:
            print("error: %s" % error, file=sys.stderr)
            return 1
        entry = find_wsftp(entries)
        if entry is None:
            print("error: no WS_FTP Server entry found in Programs and Features; pass --version instead", file=sys.stderr)
            return 1
        raw = entry["DisplayVersion"]
        source = "Windows uninstall entry: %s" % entry["DisplayName"]
    elif args.registry_json:
        try:
            with open(args.registry_json) as handle:
                entries = json.load(handle)
        except (OSError, ValueError) as exc:
            print("error: cannot read registry JSON: %s" % exc, file=sys.stderr)
            return 1
        entry = find_wsftp(entries)
        if entry is None:
            print("error: no WS_FTP Server entry in %s; pass --version instead" % args.registry_json, file=sys.stderr)
            return 1
        raw = entry["DisplayVersion"]
        source = "registry JSON: %s" % entry["DisplayName"]
    elif not raw:
        parser.print_usage(sys.stderr)
        print("error: pass --version, --local (Windows host), or --registry-json", file=sys.stderr)
        return 1

    result = grade(parse_version(raw))
    if source:
        result["source"] = source
    if result["verdict"] == UNKNOWN and result["version"] is None:
        print("error: unparseable version %r" % raw, file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(render_text(result))

    if result["verdict"] in (VULNERABLE, NO_FIX):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
