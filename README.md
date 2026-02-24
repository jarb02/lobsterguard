# LobsterGuard — Security Auditor for OpenClaw

**The first bilingual (Spanish/English) security skill for OpenClaw.**
Designed for normal people, not security experts.

## What it does

You write "revisa mi seguridad" or "check my security" in Telegram, and LobsterGuard gives you a clear security report with:

- What's OK and why it matters
- What's at risk with simple explanations (no jargon)
- Exact steps to fix each problem (copy-paste commands)

## 15 Security Checks

### OpenClaw (1-5)
| # | Check | Severity |
|---|-------|----------|
| 1 | Gateway exposed to internet | CRITICAL |
| 2 | Gateway authentication | CRITICAL |
| 3 | Version & known CVEs | HIGH |
| 4 | Credentials in plaintext | HIGH |
| 5 | Malicious skills installed | HIGH |

### Server (6-15)
| # | Check | Severity |
|---|-------|----------|
| 6 | SSH root login enabled | CRITICAL |
| 7 | SSH password authentication | HIGH |
| 8 | Firewall active | HIGH |
| 9 | Fail2ban installed | MEDIUM |
| 10 | Automatic security updates | MEDIUM |
| 11 | OpenClaw running as root | HIGH |
| 12 | Unnecessary open ports | MEDIUM |
| 13 | Disk space | MEDIUM |
| 14 | Docker security | MEDIUM |
| 15 | Active intrusion attempts | INFO |

## Installation

### One command:
```bash
bash install.sh
```

### Manual:
```bash
mkdir -p ~/.openclaw/skills/lobsterguard/scripts ~/.openclaw/skills/lobsterguard/references
# Copy SKILL.md, scripts/check.py, and references/risks.md to the folder
```

## SecureClaw Integration

LobsterGuard works WITH SecureClaw, not against it. If SecureClaw is installed, LobsterGuard uses its audit scripts as backend and adds a bilingual, non-technical interface on top.

If SecureClaw is not installed, LobsterGuard runs its own 15 checks and recommends SecureClaw for deeper analysis.

## Languages

LobsterGuard auto-detects the user's language:
- Spanish triggers: "revisa mi seguridad", "estoy protegido", "hay riesgos"
- English triggers: "check my security", "am I protected", "any risks"

## Requirements

- OpenClaw installed and running
- Python 3
- Telegram channel configured

## Security Score

LobsterGuard gives a score from 0-100:
- **80-100**: Well protected
- **50-79**: Room for improvement
- **20-49**: Important risks to fix
- **0-19**: In danger — fix now

## Built with

- Claude (Anthropic) for development
- Security data from SecurityScorecard, Kaspersky, Snyk, MITRE, OWASP

## License

MIT

---

*LobsterGuard — Making OpenClaw security accessible to everyone, in any language.*
