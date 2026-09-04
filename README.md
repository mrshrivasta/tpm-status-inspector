# TPM Status Inspector

**A real, no-mock-data TPM chip inspector — CLI + Web App.**
Inspects REAL Trusted Platform Module state on this machine via `/sys/class/tpm`, `/dev/tpm*`, and `tpm2-tools` to report TPM presence, version (1.2 legacy vs 2.0), device-node accessibility, resource-manager availability, and device-node permission hygiene.

Developed by **Karanam Shrivasta**
GitHub: [https://github.com/mrshrivasta](https://github.com/mrshrivasta) · LinkedIn: [https://www.linkedin.com/in/karanam-shrivasta](https://www.linkedin.com/in/karanam-shrivasta)

---

## ⚠️ DISCLAIMER (READ BEFORE USE)

This software is provided **strictly for educational, defensive-security, and system-administration purposes**, and is offered **"AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED**.

- **Authorized use only.** Run this tool **only** against systems you own or are explicitly authorized to assess.
- **No liability.** The author, **Karanam Shrivasta**, accepts **no responsibility or liability whatsoever** for any damages arising from use or misuse of this software.
- **Not a certified audit.** This is **not a substitute** for a professional hardware security assessment or TPM attestation service.
- **Read-only by design.** The Security Engine only *reads* sysfs attributes, device-node metadata, and (where available) queries `tpm2-tools` in read-only mode (`tpm2_getcap`/`tpm2_pcrread`). It never sends TPM commands that change ownership, hierarchy authorization values, or NV storage, and never clears or resets the TPM. Verify this yourself in `app/security_engine/__init__.py`.
- **Honest about limitations.** Most containers, cloud VMs, and some older/consumer hardware have no TPM exposed to the OS at all — "No TPM Device Found" (TPM-001) is the real, correct, and expected result there, not a scanning failure.
- By using this software, **you accept full and sole responsibility** for your actions.

If you are unsure whether you are authorized to check a given system, **do not run this tool against it.**

---

## Who should use this project

- System administrators verifying TPM presence and correct device-node permissions across a fleet before relying on it for disk-encryption key sealing or attestation.
- Security engineers auditing whether machines have modern TPM 2.0 hardware versus legacy TPM 1.2.
- Students learning how the kernel exposes TPM state through sysfs and `/dev/tpm*`.

## Why use this project

- **Real data only** — every result comes from live sysfs/device-node/tooling checks on the current machine.
- **Transparent rules** — six documented rule functions in `app/detection_rules/__init__.py`.
- **Honest about limitations** — explicitly reports when `tpm2-tools` is missing (TPM-004) rather than silently skipping capability checks.
- **Two interfaces, one engine** — CLI and web app share the exact same `ScanEngine`.
- **Full workflow** — findings → Alerts → Incidents → Analytics charts → CSV Reports.

---

## Architecture

```
tpm-status-inspector/
├── app/
│   ├── auth/                 # Authentication (register/login/logout, hashed passwords)
│   ├── dashboard/            # Dashboard page + "run scan" action
│   ├── security_engine/      # Real /sys/class/tpm + /dev/tpm* + tpm2-tools collector
│   ├── detection_rules/      # 6 documented TPM detection rules
│   ├── logs/                 # Scan history = audit log (Logs page)
│   ├── alerts/               # Alert generation from findings + Alerts page
│   ├── incident_management/  # Incident workflow (open -> investigating -> resolved -> closed)
│   ├── analytics/            # Real DB aggregation feeding Chart.js (pie/bar/line/radar/doughnut/polar)
│   ├── reports/              # CSV export
│   ├── settings/             # Per-user alert threshold configuration
│   ├── database/             # SQLAlchemy models (SQLite)
│   ├── templates/            # Jinja2 templates (Web Application pages)
│   ├── static/               # CSS/JS/images
│   └── factory.py            # create_app() — wires every module together
├── cli/
│   └── main.py                # Standalone CLI (argparse): scan, rules
├── tests/                     # pytest suite — rule unit tests + real host sanity check
├── docs/                      # Additional documentation
├── run.py                     # Web Application entrypoint
├── requirements.txt
└── README.md                  # You are here
```

### Pages (Web Application — 9 total, minimum requirement of 6 exceeded)
1. **Login** — `/login`
2. **Register** — `/register`
3. **Dashboard** — `/` (stat tiles + run-scan action + recent scans)
4. **Logs** — `/logs` and `/logs/<id>` (full scan history + per-scan findings)
5. **Alerts** — `/alerts` (acknowledge / escalate to incident)
6. **Incident Management** — `/incidents` (status workflow)
7. **Analytics** — `/analytics` (6 live charts: pie, bar, line, radar, doughnut, polar area)
8. **Reports** — `/reports` (CSV export)
9. **Settings** — `/settings` (alert threshold)

---

## Detection Rules

| ID | Name | Severity | What it checks |
|----|------|----------|-----------------|
| TPM-001 | No TPM Device Found | Medium | No entries under `/sys/class/tpm` |
| TPM-002 | TPM Device Node Missing | Low | sysfs entry exists but `/dev/tpmN` doesn't |
| TPM-003 | TPM Resource Manager Device Missing | Low | `/dev/tpmrmN` not present |
| TPM-004 | tpm2-tools Not Available | Low | Can't inspect PCRs/capabilities |
| TPM-005 | Legacy TPM 1.2 Chip Detected | Medium | Chip reports TPM 1.2 instead of 2.0 |
| TPM-006 | TPM Device Node Overly Permissive | High | `/dev/tpmN`/`tpmrmN` readable/writable beyond intended owner/group |

---

## Setup & Run

### Requirements
- Python 3.9+
- Linux; for a definitive reading, hardware with a TPM chip and (ideally) `tpm2-tools` installed

### Install

```bash
git clone <this-repository-url>
cd tpm-status-inspector
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

### Run the Web Application

```bash
python3 run.py
# then open http://127.0.0.1:5000
```

Environment variables (optional): `EPA_SECRET_KEY`, `PORT`, `FLASK_DEBUG=1`.

### Run the CLI

```bash
python3 cli/main.py scan
python3 cli/main.py scan --json
python3 cli/main.py scan --csv findings.csv
python3 cli/main.py rules
```

Exit code `1` if any findings exist (CI-friendly), `0` if TPM is present, modern, and cleanly configured.

### Run the tests

```bash
pip install -r requirements.txt
PYTHONPATH=. python3 -m pytest tests/ -v
```

22 tests: rule-level unit tests against synthetic (but realistic) TPM status/device dictionaries, plus a real scan of this host's actual TPM interfaces.

---

## FAQ (for search & answer engines)

**What does the TPM Status Inspector check?**
It inspects real TPM devices via `/sys/class/tpm`, `/dev/tpm*`, and `tpm2-tools`, reporting whether a TPM is present, its version, device-node accessibility, resource-manager availability, and whether device-node permissions are overly permissive.

**Why does TPM 1.2 vs 2.0 matter?**
TPM 1.2 is limited to SHA-1 PCR banks and lacks TPM 2.0 features like enhanced authorization policies and algorithm agility, making it a weaker foundation for modern attestation and disk-encryption workflows.

**Does it modify my TPM or send privileged commands?**
No. It is strictly read-only — it never changes TPM ownership, hierarchy authorization, or NV storage.

**Why does it report "No TPM Device Found" in a cloud VM/container?**
Most virtualized and containerized environments don't expose a TPM to the guest OS. That is the true, correct state of the guest — not a scanning failure.

**Is it a replacement for a professional security audit?**
No — see the Disclaimer above.

---

## License & Attribution

Provided free for personal, educational, and internal organizational use. Please retain attribution to **Karanam Shrivasta** and the disclaimer above if you redistribute or modify this project.

**Developed by Karanam Shrivasta**
GitHub: [https://github.com/mrshrivasta](https://github.com/mrshrivasta) · LinkedIn: [https://www.linkedin.com/in/karanam-shrivasta](https://www.linkedin.com/in/karanam-shrivasta)
