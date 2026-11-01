# `wsftp-server-scanner`

Local triage for the `Progress WS_FTP Server` patch batch of `29 October 2026`: `15` vulnerabilities, one of them a `10.0`. Give it a version you own, it tells you whether that install is still open, and it catches the trap that makes the first patched build lie. It never touches the network, never probes a server, never sends a payload.

## `The batch`

| `Detail` | `Value` |
| --- | --- |
| `Headline` | `CVE-2026-84295`, improper authentication, `10.0` critical: an unauthenticated remote attacker can access sensitive information, including administrative credentials |
| `Next worst` | `CVE-2026-90868`, OS command injection, `9.9`; `CVE-2026-90864`, `CVE-2026-90863`, `CVE-2026-90866` at `9.1`; `CVE-2026-90865`, OS command injection, `9.0` |
| `Total` | `15` CVEs: `6` critical, `3` high, `6` medium, per the batch write-up |
| `Exploitation` | None confirmed, no public proof of concept reported, as of `31 October 2026`. That is a statement about what was reported, not a reason to wait: a `10.0` unauthenticated credential flaw in a file-transfer gateway does not need a long fuse |
| `Product` | `Progress WS_FTP Server` on `Windows` only |

## `The trap: two fixed builds, not one`

| `Group` | `CVEs` | `Fixed in` |
| --- | --- | --- |
| `A` | `CVE-2026-84294`, `CVE-2026-84295`, `CVE-2026-84296` | `2024.0.6` / `2025.0.3` |
| `B` | `CVE-2026-90861` through `CVE-2026-90872` (`12` CVEs) | `2024.0.7` / `2025.0.4` |

A host on `2024.0.6` or `2025.0.3` has closed the `10.0` flaw and is still open to the `9.9` command injection flaw. Patching to the first patched build feels done and is not done. This tool grades the two groups separately and prints `TRAP` for exactly that case. The only fully patched builds in the table are `2024.0.7` and `2025.0.4` (and later builds in those branches).

## `Why local, not remote`

`WS_FTP Server` runs on `Windows`, and remote version fingerprinting is unreliable here: the login banner can be hidden and `SSH` identification can be suppressed. So this tool does not probe anything. Run it on the `Windows` host itself (`--local` reads the `Programs and Features` uninstall entries via `winreg`), or feed it a version from `WS_FTP Manager`, `About`, or `Programs and Features` (`--version`), or an exported uninstall list (`--registry-json`).

## `Version numbering, both forms accepted`

`Progress` sells the same releases under two numberings: `2024.0` is `9.0` and `2025.0` is `10.0`. So `9.0.6` means `2024.0.6` and `10.0.4` means `2025.0.4`, and this tool grades them the same. Releases older than `2024.0` (`9.0`), including `2022.0` (`8.8.x`), have no patched build in their branch: they grade `VULNERABLE` for both groups, and the fix is a branch upgrade to `2024.0.7` or `2025.0.4`, not a patch in place.

## `What it checks`

- `A version you supply` (`--version 2024.0.6`), graded per group against the split fix table
- `This Windows host` (`--local`): the `WS_FTP Server` uninstall entry, matched by name so a `WS_FTP Pro` client install does not get graded as the server
- `An offline inventory` (`--registry-json entries.json`): a `JSON` list of `{DisplayName, DisplayVersion}` entries, for fleets that export `Programs and Features` centrally
- `The full table` (`--list`): all `15` CVEs with their group and fixed build

## `Usage`

```sh
# grade one version, trap case
python3 wsftp_scanner.py --version 2024.0.6

# fully patched build
python3 wsftp_scanner.py --version 2025.0.4

# legacy marketing numbering, same grade
python3 wsftp_scanner.py --version 9.0.6

# on the Windows host itself
python3 wsftp_scanner.py --local

# from an exported uninstall list
python3 wsftp_scanner.py --registry-json entries.json

# machine-readable output for fleets
python3 wsftp_scanner.py --version 2024.0.5 --json

# the full 15-CVE table
python3 wsftp_scanner.py --list
```

Exit codes: `0` = nothing vulnerable found, `2` = vulnerable finding, `1` = scan error. `UNKNOWN` does not change the exit code, but it is not clean: a branch outside `2024.0` / `2025.0` (other than a pre-`2024.0` release) grades `UNKNOWN` because no fixed build for it is in this tool's table.

## `Where sources disagree, and what is still unverified`

One thing first: the primary `Progress` knowledge article for this batch sits behind a `Progress ID` sign-in, so it could not be opened directly for this build. The split fix table above is corroborated across independent `CVE` records (`CVE` project records via `cvefeed`, `SecurityFocus` entries, and the batch write-up), all citing the same `Progress` advisory, and the group split (`3` + `12` = `15`) is consistent across them. If you hold a `Progress` login, confirm the article against this table and open an `issue` if anything differs.

Second, individual scores are only printed where a `CVE` record was checked: `84295` at `10.0`, `90868` at `9.9`, `90864` / `90863` / `90866` at `9.1`, `90865` at `9.0`, `90867` at `8.1`, `84294` at `7.7`, `90869` at `7.5`, `90872` at `6.6`, `90871` at `5.3`. The scores for `84296`, `90861`, `90862` and `90870` were not individually confirmed in the sources checked, so the tool lists them by group without asserting a score. That changes nothing about the grade: group membership, not the individual score, decides the fixed build.

## `Mitigation if you cannot patch today`

Upgrade is the fix; there is no patch in place for the pre-`2024.0` branches and no partial patch that closes group `B`. Until you can upgrade, restrict the administrative web consoles behind internal networks only, and treat any internet-facing `WS_FTP Server` below `2024.0.7` / `2025.0.4` as exposed to an unauthenticated credential flaw. Rotate administrative credentials on any host that was internet-facing while unpatched: the headline flaw exposes them, and a patch does not un-expose them.

## `Tests`

```sh
python3 -m unittest discover -s tests -v
```

`17` tests: version parsing in both numberings, the trap in both branches, fully patched builds, legacy `9.0` / `10.0` equivalence, pre-`2024.0` no-fix grading, unlisted-branch `UNKNOWN`, registry-entry matching, and `CLI` exit codes plus the `15`-CVE list count.

## `Thanks to`

- `Progress Software`, for the patch batch and the split fix table this tool grades against
- The `CVE` project and `CNA` records, for the per-`CVE` descriptions and scores
- `SecurityOnline`, `SecurityFocus` and `cvefeed`, whose records corroborated the table while the primary article stayed login-walled

## `Disclaimer`

Defensive triage only. This tool checks version strings and reports whether an install is below a fixed build. It sends no traffic, probes no server, and is not a substitute for the vendor advisory. Use it on systems you own or are authorised to audit.

> Research by `Vineeth Kumar` (`foxcornlab`). Found a bug or want a feature, open an `issue`.
