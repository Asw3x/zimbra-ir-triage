# Zimbra Collaboration Suite (ZCS) — Incident Response & Forensic Triage Tool

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Bash](https://img.shields.io/badge/Shell-Bash-green.svg)](https://www.gnu.org/software/bash/)
[![Security: Read--Only](https://img.shields.io/badge/Security-100%25%20Read--Only-brightgreen.svg)]()

An autonomous, high-performance Bash script for digital evidence collection (**Triage & Digital Forensics**), compromise scope assessment (SMTP/Spam abuse, Web vulnerabilities, RCE), persistence hunting, and security misconfiguration auditing on **Zimbra Collaboration Suite (ZCS 8.x / 9.x / 10.x)** mail servers.

---

## 🎯 Key Features

- **Read-Only (Non-destructive):** Operates strictly in passive audit mode. It does not modify configurations, alter user passwords, delete emails, or restart services.
- **Prod Ready (Self-Throttling):** Automatically lowers CPU and I/O scheduling priority (`renice -n 15` and `ionice -c 2 -n 7`), guaranteeing zero disruption to active production email traffic.
- **Compressed Log Processing (.gz):** Streams rotated log archives over the last 30 days without extracting large files to disk.
- **LDAP Audit:** High-speed bulk directory inspection using native `ldapsearch` instead of heavy JVM processes.
- **Dual Output:** Formatted interactive terminal output (ANSI colors) alongside a clean, plain-text triage report saved to `/tmp/zimbra_triage_report_YYYYMMDD_HHMMSS.txt`.

---

## 🔍 Forensic & Investigation Modules

1. **MODULE 1: System Environment & Live RBL Reputation**
   - Host metrics (OS distribution, kernel, uptime, load averages).
   - Real-time queries across **8 major DNSBL/RBL spam blacklists** (*Spamhaus ZEN, Barracuda, SpamCop, SORBS, Mailspike, Manitu, UCEPROTECT*) with strict 2s timeouts.
   - Core service health checks (`zmcontrol status`) and package inventory.
2. **MODULE 2: Postfix Mail Queue Inspection**
   - Current queue size (`mailq`) and alerts for abnormal volume ($>500$ messages).
   - Breakdown of active and deferred queues using `qshape` to identify stalled domains.
   - Top-10 senders and recipient domains currently queued.
3. **MODULE 3: Postfix & SASL Log Analysis (Compromised Account Hunting)**
   - Identifies accounts with abnormal outbound SASL authentication volume.
   - Correlates authenticated mailboxes with attacker client IP addresses.
   - Daily outbound message volume graph (`status=sent`) over 30 days to pinpoint spam burst dates.
   - Top-10 source IP addresses responsible for authentication failures and password spraying.
4. **MODULE 4: Zimbra Configuration, Mail Forwarding & Sieve Rules**
   - Open Relay detection (`zimbraMtaMyNetworks`, alerting on `0.0.0.0/0` or WAN ranges).
   - Global Postfix mail interception audit (`always_bcc`, `sender_bcc_maps`, `recipient_bcc_maps`).
   - Domain & Global Administrator account listing (`zmprov gaaa`).
   - Fast LDAP search for unauthorized auto-forwarding rules (`zimbraPrefMailForwardingAddress`).
   - Audit of backdoor Sieve filters (`zimbraMailSieveRule`) suppressing NDRs or redirecting financial emails.
5. **MODULE 4.1: Security Misconfigurations & Hardening Posture**
   - Exposure check of the Admin Console port `7071` on public interfaces (`0.0.0.0`).
   - Internal sender spoofing protection audit (`reject_authenticated_sender_login_mismatch`).
   - Account Lockout policy verification in the default COS (`zimbraPasswordLockoutEnabled`).
   - Outbound rate-limiting daemon status (`cbpolicyd`).
   - DNS validation for **SPF, DMARC, and DKIM** records.
6. **MODULE 5: Web Logs, CVE Exploitation & Zimbra Audit Logs**
   - Scans web logs for known exploit patterns & CVEs (*CVE-2019-9670, CVE-2022-27925, CVE-2022-37042, CVE-2022-41352, CVE-2024-45519, CVE-2026 RCE/0-day patterns*): `mboximport`, `/service/admin/soap`, `Autodiscover`, `zmFilterClient.jsp`, `upload?fmt=raw`, etc.
   - Zimbra `audit.log*` forensics: unauthorized password resets (`SetPasswordRequest`), Global Address List harvesting (`SearchGalRequest`), and auth spike telemetry.
7. **MODULE 6: Persistence Hunting, Web Shells & Memory Forensics**
   - **Memory Forensics (RAM):** Detects running processes spawned from deleted executables (`/proc/*/exe (deleted)`).
   - **Web Shell Hunting:** Inspects `.jsp`, `.jspx`, `.sh`, `.py`, `.php`, `.war` files created/modified in the last 60 days across Jetty webapps and `/tmp`, with static signature matching (`Runtime.getRuntime`, `ProcessBuilder`, `eval`).
   - Crontab audit for `root`, `zimbra`, and `/etc/cron*` directories.
   - SSH `authorized_keys` inspection across system accounts.
   - Systemd unit/timer modifications within 30 days.
   - Suspicious interactive shells and network binaries running under the `zimbra` user.
8. **MODULE 7: Summary Matrix & Incident Response Playbook**
   - High-level 10-point threat and misconfiguration matrix.
   - Actionable remediation playbook for incident responders.
   - Output saved to `/tmp/zimbra_triage_report_YYYYMMDD_HHMMSS.txt`.

---

## 🚀 Quick Start

### 1. Clone or Download the Script
```bash
git clone https://github.com/Asw3x/zimbra-ir-triage.git
cd zimbra-ir-triage
```

### 2. Run as Root on the Zimbra Server
```bash
chmod +x zimbra_ir_triage.sh
./zimbra_ir_triage.sh
```

---

## 🛡️ Requirements

- **OS:** RHEL / CentOS / Rocky Linux / AlmaLinux / Debian / Ubuntu.
- **ZCS:** Zimbra Collaboration Suite 8.x, 9.x, 10.x.
- **Privileges:** Must be executed as `root` (the script securely drops privileges to the `zimbra` user when running Zimbra-specific CLI utilities).

---

## 📄 License

Distributed under the [MIT License](LICENSE).
