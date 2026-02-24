#!/bin/bash
# LobsterGuard Installer v6.0
# Security Skill + Shield Plugin for OpenClaw — Bilingual (ES/EN)
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

LOBSTERGUARD_VERSION="6.0.0"
OPENCLAW_HOME="${HOME}/.openclaw"
SKILLS_DIR="${OPENCLAW_HOME}/skills"
LG_SKILL_DIR="${SKILLS_DIR}/lobsterguard"
QUARANTINE_DIR="${OPENCLAW_HOME}/quarantine"
SYSTEMD_DIR="${HOME}/.config/systemd/user"

echo -e "${CYAN}"
echo "  _        _       _             ____                     _ "
echo " | |   ___| |__ __| |_ ___ _ _ / ___|_   _  __ _ _ __ __| |"
echo " | |  / _ \\ '_ (_-<  _/ -_) '_| |  _| | | |/ _\` | '__/ _\` |"
echo " | |_|\\___/_.__/__/\\__\\___|_| | |_| | |_| | (_| | | | (_| |"
echo " |____|                        \\____|\\__,_|\\__,_|_|  \\__,_|"
echo -e "${NC}"
echo -e "${BLUE}LobsterGuard v${LOBSTERGUARD_VERSION} — Security Auditor for OpenClaw${NC}"
echo ""

# --- Step 1: Verify OpenClaw ---
echo -e "${YELLOW}[1/7]${NC} Verificando OpenClaw / Verifying OpenClaw..."
if [ \! -d "$OPENCLAW_HOME" ]; then
    echo -e "${RED}Error: OpenClaw no encontrado en $OPENCLAW_HOME${NC}"
    echo "Error: OpenClaw not found at $OPENCLAW_HOME"
    echo "Instale OpenClaw primero / Install OpenClaw first"
    exit 1
fi
echo -e "${GREEN}  ✅ OpenClaw encontrado / found${NC}"

# --- Step 2: Detect source (local or git) ---
echo -e "${YELLOW}[2/7]${NC} Detectando fuente / Detecting source..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/scripts/check.py" ]; then
    SOURCE_DIR="$SCRIPT_DIR"
    echo -e "${GREEN}  ✅ Instalación local / Local install${NC}"
else
    echo -e "${RED}Error: No se encontraron archivos fuente / Source files not found${NC}"
    echo "Ejecute desde el directorio de LobsterGuard / Run from LobsterGuard directory"
    exit 1
fi

# --- Step 3: Install skill ---
echo -e "${YELLOW}[3/7]${NC} Instalando skill / Installing skill..."
mkdir -p "$LG_SKILL_DIR"
cp -r "$SOURCE_DIR/scripts" "$LG_SKILL_DIR/"
cp -r "$SOURCE_DIR/data" "$LG_SKILL_DIR/"
cp -r "$SOURCE_DIR/references" "$LG_SKILL_DIR/" 2>/dev/null || true
cp "$SOURCE_DIR/SKILL.md" "$LG_SKILL_DIR/" 2>/dev/null || true
cp "$SOURCE_DIR/README.md" "$LG_SKILL_DIR/" 2>/dev/null || true
cp "$SOURCE_DIR/openclaw.plugin.json" "$LG_SKILL_DIR/" 2>/dev/null || true
chmod +x "$LG_SKILL_DIR/scripts/"*.py
chmod +x "$LG_SKILL_DIR/scripts/"*.sh 2>/dev/null || true
echo -e "${GREEN}  ✅ Skill instalado en / installed at: $LG_SKILL_DIR${NC}"

# --- Step 4: Install plugin/extension ---
echo -e "${YELLOW}[4/7]${NC} Instalando extension / Installing extension..."
LG_EXT_DIR="${OPENCLAW_HOME}/extensions/lobsterguard-shield"
mkdir -p "$LG_EXT_DIR/dist"
cp "$SOURCE_DIR/extension/dist/"*.js "$LG_EXT_DIR/dist/"
cp "$SOURCE_DIR/extension/package.json" "$LG_EXT_DIR/"

# Create openclaw.plugin.json manifest if not present
if [ ! -f "$LG_EXT_DIR/openclaw.plugin.json" ]; then
    cat > "$LG_EXT_DIR/openclaw.plugin.json" << 'MANIFEST'
{
  "id": "lobsterguard-shield",
  "configSchema": {
    "type": "object",
    "additionalProperties": false,
    "properties": {}
  }
}
MANIFEST
fi

echo -e "${GREEN}  ✅ Extension instalada en / installed at: $LG_EXT_DIR${NC}"

# Register plugin in OpenClaw config
echo -e "${YELLOW}[4b/7]${NC} Registrando plugin / Registering plugin..."
OPENCLAW_CONFIG="${OPENCLAW_HOME}/openclaw.json"
if [ -f "$OPENCLAW_CONFIG" ]; then
    python3 << 'PYEOF'
import json, os
from datetime import datetime, timezone

config_path = os.path.expanduser("~/.openclaw/openclaw.json")
ext_path = os.path.expanduser("~/.openclaw/extensions/lobsterguard-shield")

try:
    with open(config_path) as f:
        config = json.load(f)
except:
    config = {}

# Ensure plugins section exists
if "plugins" not in config:
    config["plugins"] = {}
if "entries" not in config["plugins"]:
    config["plugins"]["entries"] = {}
if "installs" not in config["plugins"]:
    config["plugins"]["installs"] = {}

# Add entry
config["plugins"]["entries"]["lobsterguard-shield"] = {"enabled": True}

# Add install record
config["plugins"]["installs"]["lobsterguard-shield"] = {
    "source": "path",
    "sourcePath": ext_path,
    "installPath": ext_path,
    "version": "4.0.0",
    "installedAt": datetime.now(timezone.utc).isoformat()
}

with open(config_path, "w") as f:
    json.dump(config, f, indent=2)

print("  Plugin registered in openclaw.json")
PYEOF
    echo -e "${GREEN}  ✅ Plugin registrado / Plugin registered${NC}"
else
    echo -e "${YELLOW}  ⚠️ openclaw.json no encontrado / not found — registro manual necesario${NC}"
fi

# --- Step 5: Create quarantine folder ---
echo -e "${YELLOW}[5/7]${NC} Creando carpeta cuarentena / Creating quarantine folder..."
mkdir -p "$QUARANTINE_DIR"
echo -e "${GREEN}  ✅ Carpeta cuarentena / Quarantine folder: $QUARANTINE_DIR${NC}"

# --- Step 6: Install systemd services ---
echo -e "${YELLOW}[6/7]${NC} Configurando servicios / Configuring services..."
mkdir -p "$SYSTEMD_DIR"
if [ -d "$SOURCE_DIR/systemd" ]; then
    cp "$SOURCE_DIR/systemd/"*.service "$SYSTEMD_DIR/" 2>/dev/null || true
    cp "$SOURCE_DIR/systemd/"*.timer "$SYSTEMD_DIR/" 2>/dev/null || true
    systemctl --user daemon-reload 2>/dev/null || true
    systemctl --user enable lobsterguard-autoscan.timer 2>/dev/null || true
    systemctl --user start lobsterguard-autoscan.timer 2>/dev/null || true
    systemctl --user enable lobsterguard-quarantine.service 2>/dev/null || true
    systemctl --user start lobsterguard-quarantine.service 2>/dev/null || true
    echo -e "${GREEN}  ✅ Servicios systemd configurados / Systemd services configured${NC}"
else
    echo -e "${YELLOW}  ⚠️ Archivos systemd no encontrados / Systemd files not found${NC}"
fi

# --- Step 7: Run initial scan ---
echo -e "${YELLOW}[7/7]${NC} Ejecutando escaneo inicial / Running initial scan..."
echo ""
SCAN_OUTPUT=$(python3 -W ignore "$LG_SKILL_DIR/scripts/check.py" --compact 2>&1) || true
SCORE=$(echo "$SCAN_OUTPUT" | grep -oP 'Score:\s*\K\d+' | head -1)
CHECKS=$(echo "$SCAN_OUTPUT" | grep -oP '\d+/\d+ checks' | head -1)

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}🛡 LobsterGuard v${LOBSTERGUARD_VERSION} instalado exitosamente${NC}"
echo -e "${GREEN}🛡 LobsterGuard v${LOBSTERGUARD_VERSION} installed successfully${NC}"
echo ""
if [ -n "$SCORE" ]; then
    echo -e "  Score: ${CYAN}${SCORE}/100${NC} — ${CHECKS}"
fi
echo ""
echo -e "  Comandos Telegram / Telegram commands:"
echo -e "  ${BLUE}/scan${NC} — Escaneo completo / Full scan"
echo -e "  ${BLUE}/fixlist${NC} — Ver problemas / View issues"
echo -e "  ${BLUE}/runall${NC} — Arreglar todo / Fix all"
echo -e "  ${BLUE}/checkskill${NC} — Escanear skills / Scan skills"
echo -e "  ${BLUE}/lgsetup${NC} — Verificar instalación / Verify install"
echo ""
echo -e "  Cuarentena / Quarantine: ${YELLOW}${QUARANTINE_DIR}${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
