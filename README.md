# misbar

**A read-only Linux forensic-artifact TUI for incident triage.** Think *btop for
forensic artifacts*: drop a single static binary on a host over SSH and get an
interactive dashboard of its forensic health — log anomalies, persistence
mechanisms, auth traces, network drift, and filesystem red flags.

misbar **observes only**. It never writes to the target, makes no network
connections, forces no installs, and uses no CGO.

```
┌─ 1 System Logs ──┐ ┌─ 2 Network ──────┐ ┌─ 3 Auth & Users ─┐
│ 🟡 1 warning     │ │ 🟢 6 checks ok   │ │ 🔴 rogue UID-0   │
└──────────────────┘ └──────────────────┘ └──────────────────┘
┌─ 4 Filesystem ───┐ ┌─ 5 Persistence ──┐ ┌─ 6 Services ─────┐
│ 🟢 no exec /tmp  │ │ 🔴 ld.so.preload!│ │ 🟡 2 cron changes│
└──────────────────┘ └──────────────────┘ └──────────────────┘
 Toolbox: dd ✓  sha256sum ✓  sleuthkit ✗  volatility ✗
```

## Install

**Download a release** (static, stripped, < 15 MB):

```sh
# linux/amd64 or linux/arm64
curl -fsSL https://github.com/medunes/misbar/releases/latest/download/misbar_linux_amd64.tar.gz | tar xz
sudo mv misbar /usr/local/bin/
```

**Build from source** (Go 1.25+):

```sh
git clone https://github.com/medunes/misbar && cd misbar
make build            # → ./misbar  (CGO_ENABLED=0, -ldflags="-s -w")
sudo make install     # → /usr/local/bin/misbar
```

## Usage

```sh
sudo misbar                 # full access — all artifacts readable
misbar                      # runs as the current user, degrading gracefully
```

Running as root reads everything; as a normal user, restricted artifacts
(`/etc/shadow`, `/var/log/btmp`, …) show a 🔒 instead of crashing.

### Flags

```
--category <N>      Launch directly into category N (1-6)
--no-live           Disable live tailing (static scan only)
--json              Dump scan results as JSON to stdout and exit
--report            Dump a human-readable report to stdout and exit
--since <duration>  Time window for anomaly detection (default: 1h)
--verbose           Include OK artifacts in the report; log to stderr
--version           Show version
--help              Show help
```

`--json` and `--report` share the exact scan core the TUI uses, so headless
output always matches the interactive view:

```sh
misbar --json | jq '.categories[] | select(.health=="CRIT")'
misbar --report                 # readable summary of everything flagged
sudo misbar --category 5        # jump straight into Persistence
```

## Keybindings

| Key | Action |
|---|---|
| `1`–`6` | Open a category drilldown |
| `Tab` / `Shift+Tab` | Cycle panel focus · switch list/detail pane |
| `↑↓←→` / `hjkl` | Move focus (overview) · scroll (drilldown) |
| `Enter` | Drill in · open the full-screen artifact view |
| `/` , `n` , `N` | Search within content · next / previous match |
| `y` | Yank the current line to the clipboard (OSC-52) |
| `f` | Toggle live-tail follow for the selected log |
| `r` | Rescan static artifacts |
| `t` | Toolbox — forensic-tool availability + install hints |
| `?` | Help overlay |
| `Esc` | Back |
| `q` / `Ctrl+C` | Quit |

## What it checks

Seven categories, mapped 1:1 to the Linux Forensic Artifacts reference:

1. **System Logs** — syslog / kern.log / auth.log / dmesg / journal / boot /
   package logs, with live tailing and severity highlighting.
2. **Network** — `/etc/hosts` hijacks, DNS config, listening ports (`ss`),
   firewall logs.
3. **Auth & Users** — passwd/shadow/group, sudoers (NOPASSWD), SSH keys,
   wtmp/btmp login history, shell-history red flags.
4. **Filesystem** — executables in `/tmp` · `/var/tmp` · `/dev/shm`, mount
   drift, recent changes to sensitive dirs.
5. **Persistence** — `ld.so.preload` (instant 🔴), rc.local, init.d, systemd
   units, `/usr/local/bin`, sshd_config, cron.
6. **Services & Cron** — web/db logs, browser profiles on servers, mail spools,
   cron jobs.
7. **Toolbox** — availability of `dd`, `sha256sum`, sleuthkit, volatility,
   plaso, foremost, … with distro-appropriate install hints. misbar never
   installs anything.

**Anomaly detection** includes per-artifact rules (regex + structural) and
cross-artifact detectors: SSH brute-force (N failed logins from one IP) and
system-log error-rate spikes.

## Distro support

Debian/Ubuntu and RHEL/CentOS/Fedora families are auto-detected from
`/etc/os-release`, selecting the right paths (`syslog`↔`messages`,
`auth.log`↔`secure`, `apt`↔`dnf`, …).

## Build & test

```sh
make build        # static binary
make test         # go test -race ./...
make lint         # golangci-lint
make build-all    # linux/amd64 + linux/arm64
```

## License

MIT.
