# LobsterGuard v6.0 — Security Auditor for OpenClaw

> **[Leer en Español](README.es.md)**

Security plugin for OpenClaw controllable from Telegram. Scans, detects and fixes security issues on your server.

## What it does

- **70 security checks** across 6 categories
- **12 auto-fixes** executable from Telegram
- **Skill scanner** with 4-layer deep analysis
- **Quarantine watcher** monitors suspicious skills 24/7
- **Auto-scan every 6 hours** with Telegram alerts
- **31 real-time threat patterns**

## Check Categories

| Category | Checks | What it reviews |
|----------|--------|-----------------|
| OpenClaw | 5 | Gateway, authentication, version, credentials, skills |
| Server | 10 | SSH, firewall, fail2ban, ports, docker, disk |
| Advanced | 13 | Permissions, SSL, backups, supply chain, CORS, sandbox |
| Agentic AI | 22 | Prompt injection, exfiltration, MCP, typosquatting, memory |
| Forensic | 7 | Rootkits, reverse shells, cryptominers, DNS tunneling |
| Hardening | 13 | Kernel, systemd, auditd, core dumps, swap, namespaces |

## Telegram Commands

### Scanning
- `/scan` — Full scan with 0-100 score
- `/checkskill [name|all]` — Scan skills with 4-layer analysis
- `/lgsetup` — Verify LobsterGuard installation
- `/fixlist` — List all 12 available fixes

### Auto-fixes
| Command | What it fixes |
|---------|---------------|
| `/fixfw` | Install and configure UFW firewall |
| `/fixbackup` | Set up automatic daily backups |
| `/fixkernel` | Harden kernel parameters |
| `/fixcore` | Disable core dumps |
| `/fixaudit` | Install and configure auditd |
| `/fixsandbox` | Configure sandbox and permissions |
| `/fixenv` | Protect environment variables with secrets |
| `/fixtmp` | Clean and secure /tmp |
| `/fixcode` | Code execution restrictions |
| `/runuser` | Migrate OpenClaw from root to dedicated user |
| `/runall` | Run all fixes at once |

## Installation

```bash
git clone https://github.com/jarb02/lobsterguard.git
cd lobsterguard
bash install.sh
```

The installer:
1. Detects OpenClaw
2. Installs scripts to ~/.openclaw/skills/lobsterguard/
3. Registers the plugin in ~/.openclaw/extensions/
4. Configures systemd services (auto-scan + quarantine watcher)
5. Runs initial scan

## Requirements

- OpenClaw installed and running
- Python 3
- Telegram plugin configured in OpenClaw

## Project Structure

```
lobsterguard/
├── scripts/
│   ├── check.py              # 70 security checks
│   ├── fix_engine.py          # 12 auto-fixes with rollback
│   ├── skill_scanner.py       # Skill scanner (4 layers)
│   ├── autoscan.py            # Periodic auto-scan
│   ├── quarantine_watcher.py  # Quarantine folder monitor
│   └── runall_wrapper.sh      # Run all fixes
├── extension/
│   └── dist/
│       ├── index.js           # OpenClaw plugin (22 commands)
│       ├── interceptor.js     # 31 threat patterns
│       ├── watcher.js         # File watcher
│       ├── fix_tool.js        # Remediation tool
│       └── types.js           # Types
├── systemd/                   # Timer and services
├── data/                      # Blacklist and data
└── install.sh                 # Automatic installer
```

## License

MIT
