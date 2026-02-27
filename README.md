# LobsterGuard v6.1 — Security Auditor for OpenClaw

> **[Leer en Español](README.es.md)**

Security skill + plugin for OpenClaw controllable from Telegram. Scans, detects and fixes security issues on your server. Includes AppArmor sandboxing and hardened sudoers.

## What it does

- **68 security checks** across 6 categories
- **11 auto-fixes** executable from Telegram
- **AppArmor sandboxing** — enforce-mode profiles for scanner and fixer
- **Hardened sudoers** — no shell access, only specific commands allowed
- **Skill scanner** with 4-layer deep analysis
- **Quarantine watcher** monitors suspicious skills 24/7
- **Auto-scan every 6 hours** with Telegram alerts
- **31 real-time threat patterns** via gateway plugin
- **Automatic ghost process cleanup** via cron
- **Bilingual** — English / Spanish, selected during install
- **Auto-detects Telegram credentials** from OpenClaw config

## Security Architecture

LobsterGuard protects your server with multiple defense layers:

| Layer | Component | What it does |
|-------|-----------|--------------|
| 1 | **UFW Firewall** | Only allows SSH + OpenClaw localhost port |
| 2 | **AppArmor Sandbox** | check: broad READ, strict WRITE deny / fix: restricted writer, blocks shell |
| 3 | **Hardened Sudoers** | /bin/bash and /bin/sh REMOVED from NOPASSWD, only specific commands |
| 4 | **LobsterGuard Scanner** | 68 checks including OWASP Agentic AI Top 10 |
| 5 | **Gateway Plugin** | 31 threat patterns intercepted on every prompt in real-time |

### AppArmor Profiles

The installer creates two AppArmor profiles in **complain mode** — logs violations but doesn't block them. After 24 hours with no violations, activate enforce mode:

```bash
sudo aa-enforce /etc/apparmor.d/usr.local.bin.lobsterguard-check
sudo aa-enforce /etc/apparmor.d/usr.local.bin.lobsterguard-fix
```

**Check profile** — scanner, read-only:
- Full filesystem READ access — scanner must audit everything
- WRITE only to its own `data/` directory
- Blocks writes to `/etc/`, `/usr/`, `/boot/`, `.ssh/`, `SKILL.md`, `.env`
- Blocks read of `/etc/shadow`
- sudo runs unconfined, protected by sudoers rules

**Fix profile** — fixer, restricted writer:
- Can modify specific system config files: sshd, ufw, sysctl, auditd
- Blocks execution of bash, sh, curl, wget, pip, npm
- Cannot modify `/etc/passwd`, `/etc/shadow`, `/etc/hosts`

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

## Installation

```bash
git clone https://github.com/jarb02/lobsterguard.git
cd lobsterguard
sudo bash install.sh
```

The installer will:
1. Detect your OpenClaw installation and user
2. Ask you to select a language
3. Install dependencies: ufw, auditd, apparmor-utils
4. Configure hardened sudo permissions — no shell access
5. Copy scripts and register the plugin
6. Create AppArmor wrappers and load profiles in complain mode
7. Set up automatic ghost process cleanup
8. Verify the installation

Telegram credentials are auto-detected from your OpenClaw config.

To uninstall:
```bash
sudo bash install.sh --uninstall
```

## Requirements

- OpenClaw installed and running
- Ubuntu/Debian Linux with AppArmor
- Python 3
- Telegram configured in OpenClaw
- Root access for install only

## Project Structure

```
lobsterguard/
├── scripts/
│   ├── check.py              # 68 security checks
│   ├── fix_engine.py          # 11 auto-fixes with rollback
│   ├── skill_scanner.py       # Skill scanner, 4 layers
│   ├── autoscan.py            # Periodic auto-scan
│   ├── quarantine_watcher.py  # Quarantine folder monitor
│   ├── cleanup.py             # Ghost process cleanup
│   ├── telegram_utils.py      # Shared Telegram utilities
│   └── lgsetup.py             # Setup assistant
├── apparmor/
│   ├── usr.local.bin.lobsterguard-check   # Scanner profile
│   └── usr.local.bin.lobsterguard-fix     # Fixer profile
├── extension/
│   └── dist/
│       ├── index.js           # OpenClaw plugin, 16 commands
│       ├── interceptor.js     # 31 threat patterns
│       ├── watcher.js         # File watcher
│       ├── fix_tool.js        # Remediation tool
│       └── types.js           # Types
├── install.sh                 # Automatic installer v6.1
├── SKILL.md                   # OpenClaw skill definition
└── openclaw.plugin.json       # Plugin manifest
```

## License

MIT
