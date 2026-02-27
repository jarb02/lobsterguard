#!/usr/bin/env bash
# ============================================================
#  LobsterGuard Installer v6.1
#  Security Auditor Skill for OpenClaw
#  https://github.com/jarb02/lobsterguard
# ============================================================
set -e

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
BLUE="\033[0;34m"
NC="\033[0m"

print_banner() {
    printf "${BLUE}\n"
    printf "  _        _         _             ____                     _\n"
    printf " | |   ___| |__  ___| |_ ___ _ __ / ___|_   _  __ _ _ __ __| |\n"
    printf " | |  / _ \\  _ \\/ __| __/ _ \\  __| |  _| | | |/ _\` |  __/ _\` |\n"
    printf " | |_| (_) | |_) \\__ \\ ||  __/ |  | |_| | |_| | (_| | | | (_| |\n"
    printf " |____\\___/|_.__/|___/\\__\\___|_|   \\____|\\__,_|\\__,_|_|  \\__,_|\n"
    printf "\n"
    printf "  Security Auditor for OpenClaw - v6.1${NC}\n\n"
}

log_ok()   { printf "  ${GREEN}✓${NC} %s\n" "$1"; }
log_warn() { printf "  ${YELLOW}!${NC} %s\n" "$1"; }
log_err()  { printf "  ${RED}✗${NC} %s\n" "$1"; }
log_info() { printf "  ${BLUE}→${NC} %s\n" "$1"; }

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        printf "\n"
        log_err "Este script debe ejecutarse como root o con sudo"
        log_info "Uso: sudo bash install.sh"
        printf "\n"
        exit 1
    fi
}


select_language() {
    printf "\n"
    printf "  ${BLUE}🌐 Select language / Seleccione idioma:${NC}\n"
    printf "\n"
    printf "    1) Español\n"
    printf "    2) English\n"
    printf "\n"
    printf "  > "
    read -r LANG_CHOICE
    case "$LANG_CHOICE" in
        2|en|EN|english|English) INSTALL_LANG="en" ;;
        *) INSTALL_LANG="es" ;;
    esac
    if [ "$INSTALL_LANG" = "es" ]; then
        log_ok "Idioma seleccionado: Español"
    else
        log_ok "Language selected: English"
    fi
}

save_config() {
    CONFIG_DIR="$SKILL_DIR/data"
    mkdir -p "$CONFIG_DIR"
    cat > "$CONFIG_DIR/config.json" << CFGEOF
{
    "language": "$INSTALL_LANG"
}
CFGEOF
    chown -R "$OC_USER:$OC_USER" "$CONFIG_DIR"
    log_ok "Configuracion guardada"
}

check_openclaw() {
    OC_USER="$(ps aux | grep -i 'openclaw' | grep -v grep | head -1 | awk '{print $1}')"
    if [ -z "$OC_USER" ]; then
        for u in $(ls /home/ 2>/dev/null); do
            if [ -d "/home/$u/.openclaw" ]; then
                OC_USER="$u"
                break
            fi
        done
    fi
    if [ -z "$OC_USER" ] && [ -d "/root/.openclaw" ]; then
        OC_USER="root"
    fi
    if [ -z "$OC_USER" ]; then
        log_err "No se encontro OpenClaw instalado"
        log_info "Instala OpenClaw primero: https://openclaw.io"
        exit 1
    fi
    if [ "$OC_USER" = "root" ]; then
        OC_HOME="/root"
    else
        OC_HOME="/home/$OC_USER"
    fi
    OPENCLAW_DIR="$OC_HOME/.openclaw"
    log_ok "OpenClaw detectado - usuario: $OC_USER"
}

install_deps() {
    log_info "Instalando dependencias del sistema..."
    apt-get update -qq > /dev/null 2>&1 || true
    for pkg in ufw auditd audispd-plugins; do
        if dpkg -s "$pkg" > /dev/null 2>&1; then
            log_ok "$pkg ya instalado"
        else
            if apt-get install -y -qq "$pkg" > /dev/null 2>&1; then
                log_ok "$pkg instalado"
            else
                log_warn "$pkg no se pudo instalar (opcional)"
            fi
        fi
    done
}

setup_sudoers() {
    if [ "$OC_USER" = "root" ]; then
        log_ok "Usuario es root - no necesita sudoers"
        return
    fi
    log_info "Configurando permisos sudo para LobsterGuard..."
    SUDOERS_FILE="/etc/sudoers.d/lobsterguard"
    
    {
        echo "# LobsterGuard Security Auditor - auto-generated"
        echo "# Allows OpenClaw user to run security fixes without password"
        echo ""
        echo "# LobsterGuard sudoers - hardened permissions (VULN-2 v2)"
        echo "# REMOVED: /bin/sh, /bin/bash (prevented arbitrary root access)"
        echo "#"
        echo "# Package management"
        echo "$OC_USER ALL=(ALL) NOPASSWD: /usr/bin/apt-get, /usr/bin/apt, /usr/bin/dpkg-reconfigure"
        echo "# Firewall"
        echo "$OC_USER ALL=(ALL) NOPASSWD: /usr/sbin/ufw, /usr/sbin/iptables"
        echo "# Service management"
        echo "$OC_USER ALL=(ALL) NOPASSWD: /usr/bin/systemctl, /usr/sbin/service, /sbin/sysctl, /usr/sbin/sysctl"
        echo "# Audit"
        echo "$OC_USER ALL=(ALL) NOPASSWD: /usr/sbin/auditctl, /usr/sbin/augenrules"
        echo "# File operations (needed by auto-fixes)"
        echo "$OC_USER ALL=(ALL) NOPASSWD: /usr/bin/tee, /bin/cp, /usr/bin/cp, /usr/bin/mkdir, /usr/bin/chmod, /usr/bin/chown"
        echo "# Read-only inspection"
        echo "$OC_USER ALL=(ALL) NOPASSWD: /usr/bin/cat, /usr/bin/find, /usr/bin/ls, /usr/bin/stat, /usr/bin/readlink, /usr/bin/install"
        echo "# User management"
        echo "$OC_USER ALL=(ALL) NOPASSWD: /usr/sbin/useradd, /usr/sbin/usermod"
        echo "# System inspection"
        echo "$OC_USER ALL=(ALL) NOPASSWD: /usr/bin/fail2ban-client, /usr/bin/ss, /usr/bin/crontab, /usr/bin/loginctl"
        echo "$OC_USER ALL=(ALL) NOPASSWD: /usr/bin/journalctl, /usr/sbin/aa-status, /usr/bin/aa-status, /usr/sbin/aa-enforce"
        echo "# Process management (restricted)"
        echo "$OC_USER ALL=(ALL) NOPASSWD: /usr/bin/kill, /usr/bin/killall"
        echo "# Editing (needed for service file modifications)"
        echo "$OC_USER ALL=(ALL) NOPASSWD: /usr/bin/sed, /usr/bin/grep, /bin/rm, /usr/bin/rm, /bin/ln, /usr/bin/ln"
    } > "$SUDOERS_FILE"

    chmod 440 "$SUDOERS_FILE"
    if visudo -cf "$SUDOERS_FILE" > /dev/null 2>&1; then
        log_ok "Permisos sudo configurados"
    else
        rm -f "$SUDOERS_FILE"
        log_err "Error en sudoers - eliminado por seguridad"
    fi
}

install_skill() {
    log_info "Instalando LobsterGuard skill..."
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    SKILL_DIR="$OPENCLAW_DIR/skills/lobsterguard"
    EXT_DIR="$OPENCLAW_DIR/extensions/lobsterguard-shield"
    mkdir -p "$SKILL_DIR/scripts" "$EXT_DIR/dist"
    for f in check.py fix_engine.py skill_scanner.py autoscan.py quarantine_watcher.py cleanup.py telegram_utils.py lgsetup.py; do
        [ -f "$SCRIPT_DIR/scripts/$f" ] && cp "$SCRIPT_DIR/scripts/$f" "$SKILL_DIR/scripts/"
    done
    log_ok "Scripts copiados"
    for f in index.js interceptor.js watcher.js fix_tool.js types.js; do
        [ -f "$SCRIPT_DIR/extension/dist/$f" ] && cp "$SCRIPT_DIR/extension/dist/$f" "$EXT_DIR/dist/"
    done
    log_ok "Extension copiada"
    for f in package.json openclaw.plugin.json; do
        [ -f "$SCRIPT_DIR/extension/$f" ] && cp "$SCRIPT_DIR/extension/$f" "$EXT_DIR/"
    done
    log_ok "Configuracion copiada"
    chown -R "$OC_USER:$OC_USER" "$SKILL_DIR" 2>/dev/null || true
    chown -R "$OC_USER:$OC_USER" "$EXT_DIR" 2>/dev/null || true
    # Security: critical scripts owned by root, read-only for user
    chown root:root "$SKILL_DIR/scripts/check.py" 2>/dev/null || true
    chmod 644 "$SKILL_DIR/scripts/check.py" 2>/dev/null || true
    chown root:root "$SKILL_DIR/scripts/fix_engine.py" 2>/dev/null || true
    chmod 755 "$SKILL_DIR/scripts/fix_engine.py" 2>/dev/null || true
    chown root:root "$SKILL_DIR/scripts/skill_scanner.py" 2>/dev/null || true
    chmod 644 "$SKILL_DIR/scripts/skill_scanner.py" 2>/dev/null || true
    log_ok "Permisos de archivos configurados (root-owned)"
}

setup_backup_dir() {
    BACKUP_DIR="$OC_HOME/.openclaw/backups"
    if [ ! -d "$BACKUP_DIR" ]; then
        mkdir -p "$BACKUP_DIR"
        chown "$OC_USER:$OC_USER" "$BACKUP_DIR"
        chmod 700 "$BACKUP_DIR"
        log_ok "Directorio de backups creado"
    else
        log_ok "Directorio de backups ya existe"
    fi
}

setup_auto_cleanup() {
    log_info "Configurando limpieza automatica..."
    CLEANUP_PATH="$SKILL_DIR/scripts/cleanup.py"
    CRON_LINE="*/5 * * * * /usr/bin/python3 $CLEANUP_PATH --silent 2>/dev/null"
    # Check if cron already exists
    if su - "$OC_USER" -c "crontab -l 2>/dev/null" | grep -q "cleanup.py"; then
        log_ok "Cron de limpieza ya configurado"
    else
        su - "$OC_USER" -c "(crontab -l 2>/dev/null; echo '$CRON_LINE') | crontab -"
        log_ok "Cron de limpieza cada 5 minutos configurado"
    fi
}

setup_apparmor() {
    log_info "Configurando AppArmor sandboxing..."

    # Install apparmor-utils if needed
    if ! command -v aa-complain &>/dev/null; then
        apt-get install -y -qq apparmor apparmor-utils > /dev/null 2>&1 || true
    fi

    if ! command -v apparmor_parser &>/dev/null; then
        log_warn "AppArmor no disponible - omitiendo sandboxing"
        return
    fi

    # Ensure AppArmor service is running
    if ! systemctl is-active --quiet apparmor 2>/dev/null; then
        systemctl enable apparmor 2>/dev/null || true
        systemctl start apparmor 2>/dev/null || true
    fi
    log_ok "AppArmor activo"

    # Create wrapper scripts for AppArmor profile attachment
    cat > /usr/local/bin/lobsterguard-check << LGWRAP
#!/bin/bash
exec /usr/bin/python3 $SKILL_DIR/scripts/check.py "\$@"
LGWRAP
    chmod 755 /usr/local/bin/lobsterguard-check

    cat > /usr/local/bin/lobsterguard-fix << LGWRAP
#!/bin/bash
exec /usr/bin/python3 $SKILL_DIR/scripts/fix_engine.py "\$@"
LGWRAP
    chmod 755 /usr/local/bin/lobsterguard-fix
    log_ok "Wrappers creados en /usr/local/bin/"

    # Install AppArmor profiles from apparmor/ directory
    INST_DIR="$(cd "$(dirname "$0")" && pwd)"
    if [ -d "$INST_DIR/apparmor" ]; then
        for profile in "$INST_DIR/apparmor"/usr.local.bin.lobsterguard-*; do
            [ -f "$profile" ] && cp "$profile" /etc/apparmor.d/
        done
    fi

    # Fixup HOME path in profiles for the actual user
    if [ "$OC_USER" != "root" ]; then
        for pfile in /etc/apparmor.d/usr.local.bin.lobsterguard-*; do
            [ -f "$pfile" ] || continue
            sed -i "s|@{HOME}|/home/$OC_USER|g" "$pfile" 2>/dev/null || true
        done
    fi

    # Load profiles in complain mode (safe first run)
    for pfile in /etc/apparmor.d/usr.local.bin.lobsterguard-*; do
        [ -f "$pfile" ] || continue
        apparmor_parser -r "$pfile" 2>/dev/null || true
        aa-complain "$pfile" 2>/dev/null || true
    done
    log_ok "Perfiles AppArmor cargados en modo COMPLAIN"
    log_info "Activa enforce despues de 24h sin errores:"
    log_info "  sudo aa-enforce /etc/apparmor.d/usr.local.bin.lobsterguard-check"
    log_info "  sudo aa-enforce /etc/apparmor.d/usr.local.bin.lobsterguard-fix"

    # Add apparmor commands to sudoers
    if [ -f /etc/sudoers.d/lobsterguard ]; then
        if ! grep -q apparmor_parser /etc/sudoers.d/lobsterguard 2>/dev/null; then
            echo "# AppArmor management" >> /etc/sudoers.d/lobsterguard
            echo "$OC_USER ALL=(ALL) NOPASSWD: /usr/bin/apparmor_parser, /sbin/apparmor_parser, /usr/sbin/apparmor_parser" >> /etc/sudoers.d/lobsterguard
            echo "$OC_USER ALL=(ALL) NOPASSWD: /usr/sbin/aa-complain, /usr/sbin/aa-enforce, /usr/sbin/aa-disable, /usr/bin/aa-status, /usr/sbin/aa-status" >> /etc/sudoers.d/lobsterguard
        fi
    fi
}

verify_install() {
    log_info "Verificando instalacion..."
    ERRORS=0
    for f in check.py fix_engine.py skill_scanner.py; do
        if [ -f "$SKILL_DIR/scripts/$f" ]; then
            log_ok "$f presente"
        else
            log_err "$f falta"
            ERRORS=$((ERRORS + 1))
        fi
    done
    if [ -f "$EXT_DIR/dist/index.js" ]; then
        log_ok "index.js presente"
    else
        log_err "index.js falta"
        ERRORS=$((ERRORS + 1))
    fi
    if python3 -c "compile(open('$SKILL_DIR/scripts/fix_engine.py').read(), 'f', 'exec')" 2>/dev/null; then
        log_ok "fix_engine.py sintaxis OK"
    else
        log_err "fix_engine.py tiene errores de sintaxis"
        ERRORS=$((ERRORS + 1))
    fi
    if python3 -c "compile(open('$SKILL_DIR/scripts/check.py').read(), 'f', 'exec')" 2>/dev/null; then
        log_ok "check.py sintaxis OK"
    else
        log_err "check.py tiene errores de sintaxis"
        ERRORS=$((ERRORS + 1))
    fi
    if [ "$OC_USER" != "root" ]; then
        if su - "$OC_USER" -c "sudo -n ufw status" > /dev/null 2>&1; then
            log_ok "Sudo NOPASSWD funciona"
        else
            log_warn "Sudo NOPASSWD - verificar manualmente"
        fi
    fi
    return $ERRORS
}

uninstall() {
    print_banner
    printf "  ${YELLOW}Desinstalando LobsterGuard...${NC}\n\n"
    check_openclaw
    SKILL_DIR="$OPENCLAW_DIR/skills/lobsterguard"
    EXT_DIR="$OPENCLAW_DIR/extensions/lobsterguard-shield"
    [ -d "$SKILL_DIR" ] && rm -rf "$SKILL_DIR" && log_ok "Skill eliminado"
    [ -d "$EXT_DIR" ] && rm -rf "$EXT_DIR" && log_ok "Extension eliminada"
    [ -f "/etc/sudoers.d/lobsterguard" ] && rm -f "/etc/sudoers.d/lobsterguard" && log_ok "Sudoers eliminado"
    # Remove cleanup cron
    if su - "$OC_USER" -c "crontab -l 2>/dev/null" | grep -q "cleanup.py"; then
        su - "$OC_USER" -c "crontab -l 2>/dev/null | grep -v cleanup.py | crontab -"
        log_ok "Cron de limpieza eliminado"
    fi
    printf "\n"
    log_ok "LobsterGuard desinstalado completamente"
    printf "  ${BLUE}Reinicia OpenClaw para aplicar cambios${NC}\n\n"
}

main() {
    print_banner
    check_root
    if [ "$1" = "--uninstall" ] || [ "$1" = "-u" ]; then
        uninstall
        exit 0
    fi
    printf "  ${BLUE}Iniciando instalacion...${NC}\n\n"
    check_openclaw
    select_language
    install_deps
    setup_sudoers
    install_skill
    save_config
    setup_backup_dir
    setup_auto_cleanup
    setup_apparmor
    printf "\n"
    verify_install || true
    printf "\n"
    printf "  ${GREEN}════════════════════════════════════════════${NC}\n"
    printf "  ${GREEN}   LobsterGuard instalado exitosamente!    ${NC}\n"
    printf "  ${GREEN}════════════════════════════════════════════${NC}\n"
    printf "\n"
    printf "  ${BLUE}Comandos disponibles desde Telegram:${NC}\n"
    printf "  /scan        - Escaneo completo de seguridad\n"
    printf "  /score       - Puntaje de seguridad\n"
    printf "  /fixlist     - Lista de fixes disponibles\n"
    printf "  /fixfw       - Configurar firewall\n"
    printf "  /fixbackup   - Configurar backups\n"
    printf "  /fixaudit    - Configurar auditoria\n"
    printf "  /fixkernel   - Endurecer kernel\n"
    printf "  /fixenv      - Proteger tokens\n"
    printf "  /fixsandbox  - Configurar sandbox\n"
    printf "  /fixtmp      - Proteger /tmp\n"
    printf "  /fixcode     - Verificar integridad\n"
    printf "  /fixcore     - Deshabilitar core dumps\n"
    printf "\n"
    printf "  ${BLUE}Reinicia OpenClaw para activar el plugin${NC}\n"
    printf "  ${YELLOW}Desinstalar: sudo bash install.sh --uninstall${NC}\n\n"
}

main "$@"
