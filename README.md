# LobsterGuard v6.1 — Security Auditor for OpenClaw

> **[Leer en Español](README.es.md)**

Security plugin for OpenClaw controllable from Telegram. Scans, detects and fixes security issues on your server.

## What it does

- **68 security checks** across 6 categories
- **13 auto-fixes** executable from Telegram
- **Skill scanner** with 4-layer deep analysis
- **Quarantine watcher** monitors suspicious skills 24/7
- **Auto-scan every 6 hours** with Telegram alerts
- **31 real-time threat patterns**
- **Automatic ghost process cleanup** (post-command + cron)
- **Bilingual** (English / Spanish) — language selected during install
- **Auto-detects Telegram credentials** from OpenClaw config

## Check Categories

| Category | Checks | What it reviews |
|----------|--------|-----------------|
| OpenClaw | 5 | Gateway, authentication, version, credentials, skills |
| Server | 10 | SSH, firewall, fail2ban, ports, docker, disk |
| Advanced | 13 | Permissions, SSL, backups, supply chain, CORS, sandbox |
| Agentic AI | 22 | Prompt injection, exfiltration, MCP, typosquatting, memory |
| Forensic | 7 | Rootkits, reverse shells, cryptominers, DNS tunneling |
| Hardening | 11 | Kernel, systemd, auditd, core dumps, swap, namespaces |

## Telegram Commands

### Scanning
- `/scan` — Full scan with 0-100 score
- `/checkskill [name|all]` — Scan skills with 4-layer analysis
- `/lgsetup` — Verify LobsterGuard installation
- `/fixlist` — List all available fixes
- `/cleanup` — Kill ghost OpenClaw processes

### Auto-fixes
| Command | What it fixes |
|---------|---------------|
| `/fixfw` | Install and configure UFW firewall |
| `/fixbackup` | Set up automatic daily backups |
| `/fixkernel` | Harden kernel parameters |
| `/fixcore` | Disable core dumps |
| `/fixaudit` | Install and configure auditd |
| `/fixsandbox` | Configure sandbox and permissions |
| `/fixsystemd` | Create/harden systemd service for OpenClaw |
| `/fixenv` | Protect environment variables with secrets |
| `/fixtmp` | Clean and secure /tmp |
| `/fixcode` | Code execution restrictions |
| `/runuser` | Migrate OpenClaw from root to dedicated user |
| `/runall` | Run all fixes at once |

## Installation

```bash
git clone https://github.com/jarb02/lobsterguard.git
cd lobsterguard
sudo bash install.sh
```

The installer will:
1. Detect your OpenClaw installation and user
2. Ask you to select a language (English or Spanish)
3. Install dependencies (ufw, auditd)
4. Configure sudo permissions (NOPASSWD for security commands)
5. Copy scripts and register the plugin
6. Set up automatic ghost process cleanup (cron every 5 minutes)
7. Verify the installation

Telegram credentials are auto-detected from your OpenClaw config — no manual setup needed.

To uninstall:
```bash
sudo bash install.sh --uninstall
```

## Requirements

- OpenClaw installed and running
- Python 3
- Telegram configured in OpenClaw
- Root access (for install only)

## Project Structure

```
lobsterguard/
├── scripts/
│   ├── check.py              # 68 security checks
│   ├── fix_engine.py          # 13 auto-fixes with rollback
│   ├── skill_scanner.py       # Skill scanner (4 layers)
│   ├── autoscan.py            # Periodic auto-scan
│   ├── quarantine_watcher.py  # Quarantine folder monitor
│   ├── cleanup.py             # Ghost process cleanup
│   ├── telegram_utils.py      # Shared Telegram utilities
│   └── lgsetup.py             # Setup assistant
├── extension/
│   └── dist/
│       ├── index.js           # OpenClaw plugin (24 commands)
│       ├── interceptor.js     # 31 threat patterns
│       ├── watcher.js         # File watcher
│       ├── fix_tool.js        # Remediation tool
│       └── types.js           # Types
├── data/
│   └── config.json            # Language preference
└── install.sh                 # Automatic installer
```

## License

MIT
