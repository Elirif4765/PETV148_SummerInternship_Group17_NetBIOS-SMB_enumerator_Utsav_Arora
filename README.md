# NetBIOS Host Discoverer & SMB Shares Enumerator

A lightweight, dependency-free Python network reconnaissance tool that scans a local subnet to identify live hosts, extract NetBIOS metadata, and flag anonymously accessible SMB file shares.

## Overview

Legacy or misconfigured network devices often expose internal file shares over TCP ports 139/445 via NULL (unauthenticated) SMB sessions, and leak hostnames/workgroups over UDP port 137 (NetBIOS Name Service). This tool automates the discovery of both issues across an entire subnet without relying on heavyweight frameworks like Nmap NSE scripts or Metasploit.

## Features

- **Auto subnet detection** — parses the active `eth0` interface to determine the local CIDR block automatically
- **Ghost Host filtering** — drops dead/firewalled IPs early (both port 139 and 445 filtered) to avoid wasting time on unresponsive hosts
- **NetBIOS metadata extraction** — wraps `nbtscan` to pull hostname and workgroup info, even when TCP ports are closed
- **Anonymous SMB share detection** — wraps `smbclient -N` to enumerate readable disk shares, filtering out administrative shares like `print$`
- **Fault-tolerant logging** — streams results directly to a timestamped report file as each host completes, instead of buffering everything in memory
- **Dual output** — concise live summary on stdout, detailed forensic report on disk

## Requirements

- Python 3.x
- Linux (tested on Kali Linux / Ubuntu)
- `nbtscan` and `smbclient` binaries

```bash
sudo apt update && sudo apt install nbtscan smbclient -y
```

## Usage

```bash
python3 scanner.py
```

The script auto-detects the local subnet from `eth0`, scans all hosts, prints live results to the terminal, and writes a full audit log to `report_<timestamp>.txt` in the working directory.

## Example Output

```
192.168.56.130 - Host:METASPLOITABLE Workgroup:METASPLOITABLE - PORT 139: Open | PORT 445: Open
     [!] WARNING: ANONYMOUS SHARES FOUND!
      -> tmp
      -> opt
```

## How It Works

1. **Discovery** – Parse local interface config to get the CIDR range
2. **Port Check** – TCP connect scan on 139/445 with a 0.5s timeout, classifying each as Open / Closed / Filtered
3. **Ghost Host Drop** – Skip hosts where both ports are Filtered
4. **Deep Enumeration** – Run `nbtscan` (NetBIOS) and, if a port is open, `smbclient -N` (anonymous share listing)
5. **Dual Output** – Print a live summary and append a detailed record to the forensic log

## Tested Scenarios

| Target State | Result |
|---|---|
| Both ports closed, no NetBIOS response | Correctly skipped as a Ghost Host |
| Both ports open, anonymous shares present | Flagged HIGH RISK, shares listed |
| Ports closed but NetBIOS reachable (UDP 137) | Host still identified via nbtscan |

## Remediation Guidance

For any host flagged with anonymous shares:
- Disable guest/anonymous SMB access (`restrict anonymous = 2`, `guest ok = no` in `smb.conf`)
- Block ports 137/139/445 at the perimeter firewall for untrusted subnets
- Migrate to SMBv3 with mandatory signed sessions

## Future Work

The current scanner is intentionally sequential for simplicity and log-write safety. Planned Version 2.0 work involves a concurrent worker-pool architecture to scale to larger subnets (e.g. full /16 ranges), which requires solving:
- Bounded, latency-aware worker pool sizing
- Per-host state isolation between workers
- Serialized/locked writes to the shared report file
- Deterministic shutdown so partial scans don't corrupt the log

## Disclaimer

This tool is intended for authorized security auditing and educational use in environments you own or have explicit permission to test (e.g. isolated lab subnets). Do not run it against networks without authorization.
