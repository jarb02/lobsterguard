# LobsterGuard v6.1 — Auditor de Seguridad para OpenClaw

> **[Read in English](README.md)**

Skill + plugin de seguridad para OpenClaw controlable desde Telegram. Escanea, detecta y corrige problemas de seguridad en tu servidor. Incluye sandboxing con AppArmor y sudoers endurecido.

## Que hace

- **68 checks de seguridad** en 6 categorias
- **11 auto-fixes** ejecutables desde Telegram
- **Sandboxing con AppArmor** — perfiles en modo enforce para scanner y fixer
- **Sudoers endurecido** — sin acceso a shell, solo comandos especificos
- **Scanner de skills** con 4 capas de analisis
- **Quarantine watcher** vigila skills sospechosas 24/7
- **Auto-scan cada 6 horas** con alertas por Telegram
- **31 patrones de amenazas** en tiempo real via plugin del gateway
- **Limpieza automatica de procesos fantasma** via cron
- **Bilingue** — Espanol / English, seleccionado durante instalacion
- **Auto-detecta credenciales de Telegram** desde la config de OpenClaw

## Arquitectura de Seguridad

LobsterGuard protege tu servidor con multiples capas de defensa:

| Capa | Componente | Que hace |
|------|-----------|----------|
| 1 | **Firewall UFW** | Solo permite SSH + puerto local de OpenClaw |
| 2 | **Sandbox AppArmor** | check: READ amplio, WRITE denegado / fix: escritor restringido, bloquea shell |
| 3 | **Sudoers Endurecido** | /bin/bash y /bin/sh REMOVIDOS de NOPASSWD, solo comandos especificos |
| 4 | **Scanner LobsterGuard** | 68 checks incluyendo OWASP Agentic AI Top 10 |
| 5 | **Plugin Gateway** | 31 patrones de amenazas interceptados en cada prompt en tiempo real |

### Perfiles AppArmor

El instalador crea dos perfiles AppArmor en **modo complain** — registra violaciones pero no las bloquea. Despues de 24 horas sin violaciones, activa el modo enforce:

```bash
sudo aa-enforce /etc/apparmor.d/usr.local.bin.lobsterguard-check
sudo aa-enforce /etc/apparmor.d/usr.local.bin.lobsterguard-fix
```

**Perfil check** — scanner, solo lectura:
- Acceso READ completo al filesystem — el scanner debe auditar todo
- WRITE solo a su propio directorio `data/`
- Bloquea escritura a `/etc/`, `/usr/`, `/boot/`, `.ssh/`, `SKILL.md`, `.env`
- Bloquea lectura de `/etc/shadow`
- sudo ejecuta sin restricciones, protegido por reglas de sudoers

**Perfil fix** — fixer, escritor restringido:
- Puede modificar archivos de config especificos: sshd, ufw, sysctl, auditd
- Bloquea ejecucion de bash, sh, curl, wget, pip, npm
- No puede modificar `/etc/passwd`, `/etc/shadow`, `/etc/hosts`

## Categorias de Checks

| Categoria | Checks | Que revisa |
|-----------|--------|------------|
| OpenClaw | 5 | Gateway, autenticacion, version, credenciales, skills |
| Servidor | 10 | SSH, firewall, fail2ban, puertos, docker, disco |
| Avanzado | 13 | Permisos, SSL, backups, supply chain, CORS, sandbox |
| IA Agental | 22 | Prompt injection, exfiltracion, MCP, typosquatting, memoria |
| Forense | 7 | Rootkits, reverse shells, cryptominers, DNS tunneling |
| Endurecimiento | 11 | Kernel, systemd, auditd, core dumps, swap, namespaces |

## Comandos de Telegram

### Escaneo
- `/scan` — Escaneo completo con score 0-100
- `/checkskill [nombre|all]` — Escanea skills con 4 capas de analisis
- `/lgsetup` — Verifica que LobsterGuard este bien instalado
- `/fixlist` — Lista todos los fixes disponibles
- `/cleanup` — Elimina procesos fantasma de OpenClaw

### Auto-fixes
| Comando | Que arregla |
|---------|-------------|
| `/fixfw` | Instala y configura firewall UFW |
| `/fixbackup` | Configura backups automaticos diarios |
| `/fixkernel` | Endurece parametros del kernel |
| `/fixcore` | Deshabilita core dumps |
| `/fixaudit` | Instala y configura auditd |
| `/fixsandbox` | Configura sandbox y permisos |
| `/fixsystemd` | Crea/endurece servicio systemd para OpenClaw |
| `/fixenv` | Protege variables de entorno con secrets |
| `/fixtmp` | Limpia y asegura /tmp |
| `/fixcode` | Restricciones de ejecucion de codigo |
| `/runuser` | Migra OpenClaw de root a usuario dedicado |

## Instalacion

```bash
git clone https://github.com/jarb02/lobsterguard.git
cd lobsterguard
sudo bash install.sh
```

El instalador:
1. Detecta tu instalacion de OpenClaw y el usuario
2. Te pide seleccionar un idioma
3. Instala dependencias: ufw, auditd, apparmor-utils
4. Configura permisos sudo endurecidos — sin acceso a shell
5. Copia scripts y registra el plugin
6. Crea wrappers de AppArmor y carga perfiles en modo complain
7. Configura limpieza automatica de procesos fantasma
8. Verifica la instalacion

Las credenciales de Telegram se detectan automaticamente desde tu config de OpenClaw.

Para desinstalar:
```bash
sudo bash install.sh --uninstall
```

## Requisitos

- OpenClaw instalado y corriendo
- Ubuntu/Debian Linux con AppArmor
- Python 3
- Telegram configurado en OpenClaw
- Acceso root solo para instalar

## Estructura del Proyecto

```
lobsterguard/
├── scripts/
│   ├── check.py              # 68 checks de seguridad
│   ├── fix_engine.py          # 11 auto-fixes con rollback
│   ├── skill_scanner.py       # Scanner de skills, 4 capas
│   ├── autoscan.py            # Auto-scan periodico
│   ├── quarantine_watcher.py  # Vigila carpeta quarantine
│   ├── cleanup.py             # Limpieza de procesos fantasma
│   ├── telegram_utils.py      # Utilidades compartidas de Telegram
│   └── lgsetup.py             # Asistente de configuracion
├── apparmor/
│   ├── usr.local.bin.lobsterguard-check   # Perfil del scanner
│   └── usr.local.bin.lobsterguard-fix     # Perfil del fixer
├── extension/
│   └── dist/
│       ├── index.js           # Plugin OpenClaw, 16 comandos
│       ├── interceptor.js     # 31 patrones de amenazas
│       ├── watcher.js         # File watcher
│       ├── fix_tool.js        # Tool de remediacion
│       └── types.js           # Tipos
├── install.sh                 # Instalador automatico v6.1
├── SKILL.md                   # Definicion del skill para OpenClaw
└── openclaw.plugin.json       # Manifiesto del plugin
```

## Licencia

MIT
