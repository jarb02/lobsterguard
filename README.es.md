# LobsterGuard v6.0 — Auditor de Seguridad para OpenClaw

> **[Read in English](README.md)**

Plugin de seguridad para OpenClaw controlable desde Telegram. Escanea, detecta y corrige problemas de seguridad en tu servidor.

## Qué hace

- **70 checks de seguridad** en 6 categorías
- **12 auto-fixes** ejecutables desde Telegram
- **Scanner de skills** con 4 capas de análisis
- **Quarantine watcher** que vigila skills sospechosas 24/7
- **Auto-scan cada 6 horas** con alertas por Telegram
- **31 patrones de amenazas** en tiempo real

## Categorías de Checks

| Categoría | Checks | Qué revisa |
|-----------|--------|------------|
| OpenClaw | 5 | Gateway, autenticación, versión, credenciales, skills |
| Servidor | 10 | SSH, firewall, fail2ban, puertos, docker, disco |
| Avanzado | 13 | Permisos, SSL, backups, supply chain, CORS, sandbox |
| IA Agental | 22 | Prompt injection, exfiltración, MCP, typosquatting, memoria |
| Forense | 7 | Rootkits, reverse shells, cryptominers, DNS tunneling |
| Endurecimiento | 13 | Kernel, systemd, auditd, core dumps, swap, namespaces |

## Comandos de Telegram

### Escaneo
- `/scan` — Escaneo completo con score 0-100
- `/checkskill [nombre|all]` — Escanea skills con 4 capas de análisis
- `/lgsetup` — Verifica que LobsterGuard esté bien instalado
- `/fixlist` — Lista los 12 fixes disponibles

### Auto-fixes
| Comando | Qué arregla |
|---------|-------------|
| `/fixfw` | Instala y configura firewall UFW |
| `/fixbackup` | Configura backups automáticos diarios |
| `/fixkernel` | Endurece parámetros del kernel |
| `/fixcore` | Deshabilita core dumps |
| `/fixaudit` | Instala y configura auditd |
| `/fixsandbox` | Configura sandbox y permisos |
| `/fixenv` | Protege variables de entorno con secrets |
| `/fixtmp` | Limpia y asegura /tmp |
| `/fixcode` | Restricciones de ejecución de código |
| `/runuser` | Migra OpenClaw de root a usuario dedicado |
| `/runall` | Ejecuta todos los fixes de una vez |

## Instalación

```bash
git clone https://github.com/jarb02/lobsterguard.git
cd lobsterguard
bash install.sh
```

El instalador:
1. Detecta OpenClaw
2. Instala scripts en ~/.openclaw/skills/lobsterguard/
3. Registra el plugin en ~/.openclaw/extensions/
4. Configura servicios systemd (auto-scan + quarantine watcher)
5. Ejecuta scan inicial

## Requisitos

- OpenClaw instalado y corriendo
- Python 3
- Plugin de Telegram configurado en OpenClaw

## Estructura del Proyecto

```
lobsterguard/
├── scripts/
│   ├── check.py              # 70 checks de seguridad
│   ├── fix_engine.py          # 12 auto-fixes con rollback
│   ├── skill_scanner.py       # Scanner de skills (4 capas)
│   ├── autoscan.py            # Auto-scan periódico
│   ├── quarantine_watcher.py  # Vigila carpeta quarantine
│   └── runall_wrapper.sh      # Ejecuta todos los fixes
├── extension/
│   └── dist/
│       ├── index.js           # Plugin OpenClaw (22 comandos)
│       ├── interceptor.js     # 31 patrones de amenazas
│       ├── watcher.js         # File watcher
│       ├── fix_tool.js        # Tool de remediación
│       └── types.js           # Tipos
├── systemd/                   # Timer y servicios
├── data/                      # Blacklist y datos
└── install.sh                 # Instalador automático
```

## Licencia

MIT
