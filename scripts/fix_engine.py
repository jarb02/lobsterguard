#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
# LobsterGuard Fix Engine v1.0
# Guided auto-remediation for security issues
#
# Usage:
#   python3 fix_engine.py plan <check_id> [--user <target_user>] [--lang es|en]
#   python3 fix_engine.py execute <check_id> <step_id>
#   python3 fix_engine.py rollback <check_id>
#   python3 fix_engine.py verify <check_id>
#
# Returns JSON to stdout for the plugin to parse.
# ─────────────────────────────────────────────────────────────────────────────

import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# ─── Paths ──────────────────────────────────────────────────────────────────

OPENCLAW_HOME = os.path.join(os.environ.get("HOME", "/root"), ".openclaw")
LOBSTERGUARD_DIR = os.path.join(OPENCLAW_HOME, "skills", "lobsterguard")
DATA_DIR = os.path.join(LOBSTERGUARD_DIR, "data")
FIX_STATE_FILE = os.path.join(DATA_DIR, "fix-state.json")
FIX_LOG_FILE = os.path.join(DATA_DIR, "fix-log.jsonl")

# ─── Helpers ────────────────────────────────────────────────────────────────


def run_command(cmd, timeout=30):
    """Run a shell command and return (stdout, stderr, returncode)."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", 1
    except Exception as e:
        return "", str(e), 1


def log_action(action, check_id, step_id=None, result=None, error=None):
    """Append to fix log for audit trail."""
    entry = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "action": action,
        "check_id": check_id,
        "step_id": step_id,
        "result": result,
        "error": error,
    }
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(FIX_LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


def load_fix_state():
    """Load persistent fix state."""
    try:
        if os.path.exists(FIX_STATE_FILE):
            with open(FIX_STATE_FILE, "r") as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def save_fix_state(state):
    """Save persistent fix state."""
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(FIX_STATE_FILE, "w") as f:
            json.dump(state, f, indent=2)
    except Exception:
        pass


def output(data):
    """Print JSON result to stdout for the plugin."""
    print(json.dumps(data, indent=2, ensure_ascii=False))
    sys.exit(0)


def output_error(message_es, message_en, details=None):
    """Print error JSON and exit."""
    output({
        "success": False,
        "error_es": message_es,
        "error_en": message_en,
        "details": details,
    })


# ─── Process Manager Detection ──────────────────────────────────────────────


def detect_openclaw_process():
    """Find the OpenClaw gateway process and how it's managed."""
    stdout, _, rc = run_command("ps aux | grep -E 'openclaw.*(gateway|index\\.js)' | grep -v grep")
    if rc != 0 or not stdout:
        return None

    # Parse ps output: USER PID ... COMMAND
    lines = [l for l in stdout.split("\n") if l.strip()]
    if not lines:
        return None

    parts = lines[0].split()
    proc_user = parts[0]
    proc_pid = parts[1]

    # Get parent PID
    stdout2, _, rc2 = run_command(f"ps -o ppid= -p {proc_pid}")
    ppid = stdout2.strip() if rc2 == 0 else ""

    # Get parent process name
    parent_name = ""
    if ppid:
        stdout3, _, rc3 = run_command(f"ps -o comm= -p {ppid}")
        parent_name = stdout3.strip() if rc3 == 0 else ""

    # Extract command line
    stdout4, _, _ = run_command(f"ps -o args= -p {proc_pid}")
    cmdline = stdout4.strip()

    return {
        "user": proc_user,
        "pid": proc_pid,
        "ppid": ppid,
        "parent": parent_name,
        "cmdline": cmdline,
    }


def detect_process_manager(proc_info):
    """Determine which process manager controls OpenClaw."""
    if not proc_info:
        return "not_running", {}

    parent = proc_info.get("parent", "")
    user = proc_info.get("user", "")
    ppid = proc_info.get("ppid", "")

    # Check systemd user service
    if parent == "systemd":
        # Check if there's a user service for the running user
        if user == "root":
            svc_path = "/root/.config/systemd/user/openclaw-gateway.service"
            stdout, _, rc = run_command(f"sudo cat {svc_path} 2>/dev/null")
            if rc == 0 and stdout:
                return "systemd_user_root", {
                    "service_path": svc_path,
                    "service_content": stdout,
                }

        # Non-root user systemd
        home = os.environ.get("HOME", f"/home/{user}")
        svc_path = f"{home}/.config/systemd/user/openclaw-gateway.service"
        if os.path.exists(svc_path):
            with open(svc_path) as f:
                content = f.read()
            return "systemd_user", {
                "service_path": svc_path,
                "service_content": content,
            }

    # Check systemd system service
    stdout, _, rc = run_command("sudo systemctl cat openclaw-gateway 2>/dev/null")
    if rc == 0 and stdout:
        return "systemd_system", {"service_content": stdout}

    # Check pm2
    stdout, _, rc = run_command("pm2 jlist 2>/dev/null")
    if rc == 0 and "openclaw" in stdout.lower():
        return "pm2", {"pm2_list": stdout}

    # Check supervisor
    stdout, _, rc = run_command("sudo supervisorctl status 2>/dev/null")
    if rc == 0 and "openclaw" in stdout.lower():
        return "supervisor", {"supervisor_status": stdout}

    # Check Docker
    stdout, _, rc = run_command("docker ps --format '{{.Names}}' 2>/dev/null")
    if rc == 0 and "openclaw" in stdout.lower():
        return "docker", {"container_name": stdout.strip()}

    # Manual / nohup
    return "manual", {}


def extract_service_vars(service_content):
    """Extract key variables from a systemd service file."""
    vars_found = {}
    for line in service_content.split("\n"):
        line = line.strip()
        if line.startswith("ExecStart="):
            vars_found["exec_start"] = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("Environment="):
            val = line.split("=", 1)[1].strip().strip('"')
            if "=" in val:
                k, v = val.split("=", 1)
                vars_found[f"env_{k}"] = v
            else:
                vars_found[f"env_{val}"] = ""
    return vars_found


# ─── Fix Plan Generators ────────────────────────────────────────────────────


def plan_check_11(target_user, lang="es"):
    """Generate fix plan for Check #11: OpenClaw running as root."""

    proc = detect_openclaw_process()
    if not proc:
        output_error(
            "No se detectó OpenClaw corriendo.",
            "OpenClaw process not detected.",
        )

    if proc["user"] != "root":
        output({
            "success": True,
            "already_fixed": True,
            "message_es": f"OpenClaw ya corre como '{proc['user']}', no como root. No hay nada que arreglar.",
            "message_en": f"OpenClaw already runs as '{proc['user']}', not root. Nothing to fix.",
        })

    pm_type, pm_info = detect_process_manager(proc)

    # Determine target user
    if not target_user:
        target_user = os.environ.get("USER", "")
        if target_user == "root":
            # Try to find a non-root user with a home directory
            stdout, _, _ = run_command("ls /home/ | head -1")
            target_user = stdout.strip() if stdout.strip() else ""

    if not target_user or target_user == "root":
        output_error(
            "No se encontró un usuario no-root para migrar. Crea uno primero: sudo useradd -m -s /bin/bash <nombre>",
            "No non-root user found to migrate to. Create one first: sudo useradd -m -s /bin/bash <name>",
        )

    target_home = f"/home/{target_user}"
    target_openclaw = f"{target_home}/.openclaw"

    # Build steps based on process manager
    steps = []

    if pm_type == "systemd_user_root":
        svc_content = pm_info.get("service_content", "")
        svc_vars = extract_service_vars(svc_content)
        exec_start = svc_vars.get("exec_start", "/usr/bin/node /usr/lib/node_modules/openclaw/dist/index.js gateway --port 18789")

        # Extract all Environment lines for the new service
        env_lines = []
        for line in svc_content.split("\n"):
            line = line.strip()
            if line.startswith("Environment="):
                # Replace /root with target home
                new_line = line.replace("/root", target_home)
                env_lines.append(new_line)

        # Rebuild ExecStart without quotes if present
        exec_start_clean = exec_start.replace('"', '')

        # Build new service content
        new_service = f"""[Unit]
Description=OpenClaw Gateway
After=network-online.target
Wants=network-online.target

[Service]
ExecStart={exec_start_clean}
Restart=always
RestartSec=5
KillMode=control-group
"""
        for env_line in env_lines:
            new_service += env_line + "\n"
        new_service += """
[Install]
WantedBy=default.target
"""

        steps = [
            {
                "id": 1,
                "title_es": "Detener servicio de root",
                "title_en": "Stop root service",
                "description_es": "Paramos OpenClaw que corre como root para poder migrarlo.",
                "description_en": "Stopping the root OpenClaw process to migrate it.",
                "command": "sudo bash -c 'XDG_RUNTIME_DIR=/run/user/0 systemctl --user is-active openclaw-gateway' && sudo bash -c 'XDG_RUNTIME_DIR=/run/user/0 systemctl --user stop openclaw-gateway' && sudo kill $(pgrep -u root -f openclaw-gateway) 2>/dev/null; sleep 2",
                "validation": "! pgrep -u root -f openclaw-gateway",
                "rollback": "sudo bash -c 'XDG_RUNTIME_DIR=/run/user/0 systemctl --user start openclaw-gateway'",
                "critical": True,
            },
            {
                "id": 2,
                "title_es": "Desactivar servicio de root",
                "title_en": "Disable root service",
                "description_es": "Eliminamos el servicio de root para que no vuelva a arrancar.",
                "description_en": "Removing the root service so it doesn't restart.",
                "command": f"sudo rm -f /root/.config/systemd/user/openclaw-gateway.service && sudo rm -f /root/.config/systemd/user/default.target.wants/openclaw-gateway.service && sudo bash -c 'XDG_RUNTIME_DIR=/run/user/0 systemctl --user is-active openclaw-gateway'",
                "validation": "! sudo test -f /root/.config/systemd/user/openclaw-gateway.service",
                "rollback": f"sudo bash -c 'mkdir -p /root/.config/systemd/user/default.target.wants'",
                "critical": True,
            },
            {
                "id": 3,
                "title_es": f"Copiar configuración a {target_user}",
                "title_en": f"Copy configuration to {target_user}",
                "description_es": "Copiamos toda la configuración de OpenClaw al nuevo usuario.",
                "description_en": "Copying all OpenClaw configuration to the target user.",
                "command": f"mkdir -p {target_openclaw} && sudo bash -c 'cp -r /root/.openclaw/* {target_openclaw}/' && sudo chown -R {target_user}:{target_user} {target_openclaw}",
                "validation": f"test -f {target_openclaw}/openclaw.json",
                "rollback": "",
                "critical": True,
            },
            {
                "id": 4,
                "title_es": "Corregir rutas en configuración",
                "title_en": "Fix paths in configuration",
                "description_es": "Actualizamos las rutas que apuntan a /root/ para que apunten al nuevo usuario.",
                "description_en": "Updating paths from /root/ to point to the new user's home.",
                "command": f"sed -i 's|/root/.openclaw|{target_openclaw}|g' {target_openclaw}/openclaw.json",
                "validation": f"! grep -q '/root/.openclaw' {target_openclaw}/openclaw.json",
                "rollback": "",
                "critical": False,
            },
            {
                "id": 5,
                "title_es": f"Crear servicio para {target_user}",
                "title_en": f"Create service for {target_user}",
                "description_es": "Creamos el servicio de systemd para que OpenClaw arranque con tu usuario.",
                "description_en": "Creating a systemd service so OpenClaw starts with your user.",
                "command": f"mkdir -p {target_home}/.config/systemd/user/ && cat > {target_home}/.config/systemd/user/openclaw-gateway.service << 'SVCEOF'\n{new_service}SVCEOF",
                "validation": f"test -f {target_home}/.config/systemd/user/openclaw-gateway.service",
                "rollback": f"rm -f {target_home}/.config/systemd/user/openclaw-gateway.service",
                "critical": True,
            },
            {
                "id": 6,
                "title_es": "Crear enlace de compatibilidad",
                "title_en": "Create compatibility symlink",
                "description_es": "Creamos un enlace para que programas que busquen /root/.openclaw encuentren tu configuración.",
                "description_en": "Creating a symlink so programs looking for /root/.openclaw find your config.",
                "command": f"sudo rm -rf /root/.openclaw && sudo ln -s {target_openclaw} /root/.openclaw && sudo chmod 711 /root",
                "validation": f"sudo readlink /root/.openclaw | grep -q '{target_openclaw}'",
                "rollback": "sudo rm -f /root/.openclaw",
                "critical": False,
            },
            {
                "id": 7,
                "title_es": "Iniciar servicio con tu usuario",
                "title_en": "Start service with your user",
                "description_es": "Habilitamos e iniciamos OpenClaw con tu usuario.",
                "description_en": "Enabling and starting OpenClaw with your user.",
                "command": f"sudo loginctl enable-linger {target_user} && systemctl --user is-active openclaw-gateway",
                "validation": f"pgrep -u {target_user} -f openclaw-gateway",
                "rollback": "systemctl --user stop openclaw-gateway && systemctl --user disable openclaw-gateway",
                "critical": True,
            },
            {
                "id": 8,
                "title_es": "Verificar que todo funciona",
                "title_en": "Verify everything works",
                "description_es": "Esperamos unos segundos y verificamos que OpenClaw responde correctamente.",
                "description_en": "Waiting a few seconds and verifying OpenClaw responds correctly.",
                "command": f"sleep 5 && journalctl --user -u openclaw-gateway --no-pager --since '10 sec ago' 2>/dev/null | head -10",
                "validation": f"pgrep -u {target_user} -f openclaw-gateway && ! pgrep -u root -f openclaw-gateway",
                "rollback": "",
                "critical": False,
            },
        ]

    elif pm_type == "systemd_system":
        steps = [
            {
                "id": 1,
                "title_es": "Detener servicio",
                "title_en": "Stop service",
                "description_es": "Paramos el servicio de OpenClaw.",
                "description_en": "Stopping the OpenClaw service.",
                "command": "sudo systemctl stop openclaw-gateway",
                "validation": "! pgrep -f openclaw-gateway",
                "rollback": "sudo systemctl start openclaw-gateway",
                "critical": True,
            },
            {
                "id": 2,
                "title_es": f"Copiar configuración a {target_user}",
                "title_en": f"Copy configuration to {target_user}",
                "description_es": "Copiamos la configuración al nuevo usuario.",
                "description_en": "Copying configuration to the target user.",
                "command": f"mkdir -p {target_openclaw} && sudo bash -c 'cp -r /root/.openclaw/* {target_openclaw}/' && sudo chown -R {target_user}:{target_user} {target_openclaw}",
                "validation": f"test -f {target_openclaw}/openclaw.json",
                "rollback": "",
                "critical": True,
            },
            {
                "id": 3,
                "title_es": "Corregir rutas en configuración",
                "title_en": "Fix paths in configuration",
                "description_es": "Actualizamos rutas de /root/ al nuevo usuario.",
                "description_en": "Updating paths from /root/ to the new user.",
                "command": f"sed -i 's|/root/.openclaw|{target_openclaw}|g' {target_openclaw}/openclaw.json",
                "validation": f"! grep -q '/root/.openclaw' {target_openclaw}/openclaw.json",
                "rollback": "",
                "critical": False,
            },
            {
                "id": 4,
                "title_es": f"Cambiar usuario en servicio",
                "title_en": f"Change user in service",
                "description_es": f"Configuramos el servicio para que corra como {target_user}.",
                "description_en": f"Configuring the service to run as {target_user}.",
                "command": f"sudo sed -i 's/User=root/User={target_user}/' /etc/systemd/system/openclaw-gateway.service && sudo sed -i 's|HOME=/root|HOME={target_home}|g' /etc/systemd/system/openclaw-gateway.service && sudo systemctl is-active openclaw-gateway",
                "validation": f"sudo grep -q 'User={target_user}' /etc/systemd/system/openclaw-gateway.service",
                "rollback": "sudo sed -i 's/User={target_user}/User=root/' /etc/systemd/system/openclaw-gateway.service && sudo systemctl is-active openclaw-gateway",
                "critical": True,
            },
            {
                "id": 5,
                "title_es": "Crear enlace de compatibilidad",
                "title_en": "Create compatibility symlink",
                "description_es": "Enlace para que /root/.openclaw apunte a tu configuración.",
                "description_en": "Symlink so /root/.openclaw points to your config.",
                "command": f"sudo rm -rf /root/.openclaw && sudo ln -s {target_openclaw} /root/.openclaw && sudo chmod 711 /root",
                "validation": f"sudo readlink /root/.openclaw | grep -q '{target_openclaw}'",
                "rollback": "sudo rm -f /root/.openclaw",
                "critical": False,
            },
            {
                "id": 6,
                "title_es": "Iniciar servicio",
                "title_en": "Start service",
                "description_es": "Arrancamos OpenClaw con el nuevo usuario.",
                "description_en": "Starting OpenClaw with the new user.",
                "command": "sudo systemctl start openclaw-gateway",
                "validation": f"pgrep -u {target_user} -f openclaw-gateway",
                "rollback": "",
                "critical": True,
            },
        ]

    elif pm_type == "pm2":
        steps = [
            {
                "id": 1,
                "title_es": "Detener proceso en pm2",
                "title_en": "Stop pm2 process",
                "description_es": "Paramos OpenClaw en pm2.",
                "description_en": "Stopping OpenClaw in pm2.",
                "command": "sudo pm2 stop openclaw-gateway && sudo pm2 delete openclaw-gateway",
                "validation": "! pm2 jlist 2>/dev/null | grep -qi openclaw",
                "rollback": "",
                "critical": True,
            },
            {
                "id": 2,
                "title_es": f"Copiar configuración a {target_user}",
                "title_en": f"Copy configuration to {target_user}",
                "description_es": "Copiamos la configuración.",
                "description_en": "Copying configuration.",
                "command": f"mkdir -p {target_openclaw} && sudo bash -c 'cp -r /root/.openclaw/* {target_openclaw}/' && sudo chown -R {target_user}:{target_user} {target_openclaw}",
                "validation": f"test -f {target_openclaw}/openclaw.json",
                "rollback": "",
                "critical": True,
            },
            {
                "id": 3,
                "title_es": "Corregir rutas",
                "title_en": "Fix paths",
                "description_es": "Actualizamos rutas en la configuración.",
                "description_en": "Updating configuration paths.",
                "command": f"sed -i 's|/root/.openclaw|{target_openclaw}|g' {target_openclaw}/openclaw.json",
                "validation": f"! grep -q '/root/.openclaw' {target_openclaw}/openclaw.json",
                "rollback": "",
                "critical": False,
            },
            {
                "id": 4,
                "title_es": f"Iniciar con pm2 como {target_user}",
                "title_en": f"Start with pm2 as {target_user}",
                "description_es": f"Arrancamos OpenClaw con pm2 usando tu usuario.",
                "description_en": f"Starting OpenClaw with pm2 using your user.",
                "command": f"sudo -u {target_user} pm2 start /usr/lib/node_modules/openclaw/dist/index.js --name openclaw-gateway -- gateway --port 18789 && sudo -u {target_user} pm2 save",
                "validation": f"pgrep -u {target_user} -f openclaw-gateway",
                "rollback": "",
                "critical": True,
            },
        ]

    elif pm_type == "manual":
        exec_cmd = proc.get("cmdline", "/usr/bin/node /usr/lib/node_modules/openclaw/dist/index.js gateway --port 18789")
        steps = [
            {
                "id": 1,
                "title_es": "Detener proceso",
                "title_en": "Stop process",
                "description_es": "Paramos OpenClaw.",
                "description_en": "Stopping OpenClaw.",
                "command": f"sudo kill {proc['pid']}; sleep 2",
                "validation": "! pgrep -u root -f openclaw-gateway",
                "rollback": "",
                "critical": True,
            },
            {
                "id": 2,
                "title_es": f"Copiar configuración a {target_user}",
                "title_en": f"Copy configuration to {target_user}",
                "description_es": "Copiamos la configuración.",
                "description_en": "Copying configuration.",
                "command": f"mkdir -p {target_openclaw} && sudo bash -c 'cp -r /root/.openclaw/* {target_openclaw}/' && sudo chown -R {target_user}:{target_user} {target_openclaw}",
                "validation": f"test -f {target_openclaw}/openclaw.json",
                "rollback": "",
                "critical": True,
            },
            {
                "id": 3,
                "title_es": "Corregir rutas",
                "title_en": "Fix paths",
                "description_es": "Actualizamos rutas en la configuración.",
                "description_en": "Updating configuration paths.",
                "command": f"sed -i 's|/root/.openclaw|{target_openclaw}|g' {target_openclaw}/openclaw.json",
                "validation": f"! grep -q '/root/.openclaw' {target_openclaw}/openclaw.json",
                "rollback": "",
                "critical": False,
            },
            {
                "id": 4,
                "title_es": f"Relanzar como {target_user}",
                "title_en": f"Relaunch as {target_user}",
                "description_es": f"Arrancamos OpenClaw con tu usuario.",
                "description_en": f"Starting OpenClaw with your user.",
                "command": f"sudo -u {target_user} nohup {exec_cmd} > /dev/null 2>&1 &",
                "validation": f"sleep 3 && pgrep -u {target_user} -f openclaw-gateway",
                "rollback": "",
                "critical": True,
            },
        ]

    else:
        output_error(
            f"No sé cómo manejar el process manager '{pm_type}'. Contacta soporte.",
            f"Don't know how to handle process manager '{pm_type}'. Contact support.",
            {"process_manager": pm_type, "process_info": proc},
        )

    plan = {
        "success": True,
        "check_id": "openclaw_user",
        "title_es": f"Migrar OpenClaw de root a {target_user}",
        "title_en": f"Migrate OpenClaw from root to {target_user}",
        "description_es": (
            f"Voy a mover OpenClaw para que corra con tu usuario '{target_user}' en vez de root. "
            "Si el agente es comprometido, el daño será limitado a tu usuario."
        ),
        "description_en": (
            f"I'll move OpenClaw to run under your user '{target_user}' instead of root. "
            "If the agent is compromised, the damage will be limited to your user."
        ),
        "estimated_time_es": "2-5 minutos",
        "estimated_time_en": "2-5 minutes",
        "requires_sudo": True,
        "process_manager": pm_type,
        "target_user": target_user,
        "current_user": proc["user"],
        "total_steps": len(steps),
        "steps": steps,
    }

    # Save plan to state
    state = load_fix_state()
    state["active_fix"] = {
        "check_id": "openclaw_user",
        "state": "planned",
        "target_user": target_user,
        "process_manager": pm_type,
        "total_steps": len(steps),
        "completed_steps": [],
        "started_at": datetime.utcnow().isoformat() + "Z",
    }
    state["plan"] = plan
    save_fix_state(state)

    log_action("plan", "openclaw_user", result=f"Generated {len(steps)}-step plan for {pm_type}")

    return plan


# ─── Step Execution ─────────────────────────────────────────────────────────


def execute_step(check_id, step_id):
    """Execute a single step of a fix plan."""
    state = load_fix_state()

    if not state.get("plan"):
        output_error(
            "No hay un plan activo. Ejecuta 'plan' primero.",
            "No active plan. Run 'plan' first.",
        )

    plan = state["plan"]
    steps = plan.get("steps", [])
    step = None
    for s in steps:
        if s["id"] == step_id:
            step = s
            break

    if not step:
        output_error(
            f"Paso {step_id} no encontrado en el plan.",
            f"Step {step_id} not found in the plan.",
        )

    lang_suffix = "es"  # Default to Spanish

    # Execute the command
    log_action("execute_start", check_id, step_id=step_id)

    stdout, stderr, rc = run_command(step["command"], timeout=60)

    # Validate
    validation_passed = True
    if step.get("validation"):
        _, _, vrc = run_command(step["validation"], timeout=15)
        validation_passed = vrc == 0

    if rc != 0 and step.get("critical", False) and not validation_passed:
        # Step failed
        log_action("execute_fail", check_id, step_id=step_id, error=stderr)

        state["active_fix"]["state"] = "failed"
        state["active_fix"]["failed_step"] = step_id
        save_fix_state(state)

        output({
            "success": False,
            "step_id": step_id,
            "title_es": step["title_es"],
            "title_en": step["title_en"],
            "error_es": f"Error en paso {step_id}: {stderr or stdout or 'comando falló'}",
            "error_en": f"Error in step {step_id}: {stderr or stdout or 'command failed'}",
            "stdout": stdout,
            "stderr": stderr,
            "can_rollback": bool(step.get("rollback")),
            "total_steps": plan["total_steps"],
        })

    # Step succeeded
    log_action("execute_ok", check_id, step_id=step_id, result="success")

    state["active_fix"]["state"] = "in_progress"
    state["active_fix"]["completed_steps"].append(step_id)
    state["active_fix"]["last_step"] = step_id
    save_fix_state(state)

    is_last = step_id == plan["total_steps"]

    if is_last:
        state["active_fix"]["state"] = "completed"
        save_fix_state(state)

    output({
        "success": True,
        "step_id": step_id,
        "title_es": step["title_es"],
        "title_en": step["title_en"],
        "description_es": step.get("description_es", ""),
        "description_en": step.get("description_en", ""),
        "stdout": stdout,
        "validation_passed": validation_passed,
        "is_last_step": is_last,
        "total_steps": plan["total_steps"],
        "next_step": step_id + 1 if not is_last else None,
    })


# ─── Rollback ───────────────────────────────────────────────────────────────


def rollback(check_id):
    """Rollback all completed steps in reverse order."""
    state = load_fix_state()

    if not state.get("plan"):
        output_error(
            "No hay un plan activo para revertir.",
            "No active plan to rollback.",
        )

    plan = state["plan"]
    completed = state.get("active_fix", {}).get("completed_steps", [])

    if not completed:
        output({
            "success": True,
            "message_es": "No hay pasos completados para revertir.",
            "message_en": "No completed steps to rollback.",
        })

    results = []
    # Rollback in reverse order
    for step_id in reversed(completed):
        step = None
        for s in plan["steps"]:
            if s["id"] == step_id:
                step = s
                break

        if step and step.get("rollback"):
            stdout, stderr, rc = run_command(step["rollback"], timeout=60)
            results.append({
                "step_id": step_id,
                "title_es": step["title_es"],
                "title_en": step["title_en"],
                "success": rc == 0,
                "error": stderr if rc != 0 else None,
            })
            log_action("rollback", check_id, step_id=step_id,
                       result="ok" if rc == 0 else "fail", error=stderr if rc != 0 else None)

    # Clear state
    state["active_fix"] = {"state": "rolled_back"}
    save_fix_state(state)

    output({
        "success": True,
        "message_es": "Cambios revertidos correctamente.",
        "message_en": "Changes rolled back successfully.",
        "steps_rolled_back": results,
    })


# ─── Verify ─────────────────────────────────────────────────────────────────


def verify(check_id):
    """Re-run the check to see if the fix worked."""
    if check_id == "openclaw_user":
        proc = detect_openclaw_process()
        if not proc:
            output({
                "success": True,
                "fixed": False,
                "message_es": "OpenClaw no está corriendo. Puede que necesite reiniciarse.",
                "message_en": "OpenClaw is not running. It may need to be restarted.",
            })

        if proc["user"] == "root":
            output({
                "success": True,
                "fixed": False,
                "message_es": f"OpenClaw sigue corriendo como root (PID {proc['pid']}).",
                "message_en": f"OpenClaw is still running as root (PID {proc['pid']}).",
            })

        output({
            "success": True,
            "fixed": True,
            "message_es": f"✅ OpenClaw corre como '{proc['user']}' (PID {proc['pid']}). Problema resuelto.",
            "message_en": f"✅ OpenClaw runs as '{proc['user']}' (PID {proc['pid']}). Issue resolved.",
            "user": proc["user"],
            "pid": proc["pid"],
        })

    output_error(
        f"Check '{check_id}' no tiene verificación de fix implementada.",
        f"Check '{check_id}' doesn't have fix verification implemented.",
    )


# ─── Available Fixes Registry ──────────────────────────────────────────────

AVAILABLE_FIXES = {
    "openclaw_user": {
        "plan_fn": plan_check_11,
        "verify_fn": verify,
        "title_es": "Migrar OpenClaw de root a usuario no-root",
        "title_en": "Migrate OpenClaw from root to non-root user",
    },
}


def list_fixes():
    """List all available auto-fixes."""
    fixes = []
    for check_id, info in AVAILABLE_FIXES.items():
        fixes.append({
            "check_id": check_id,
            "title_es": info["title_es"],
            "title_en": info["title_en"],
        })
    output({"success": True, "fixes": fixes})


# ─── Main ───────────────────────────────────────────────────────────────────


def main():
    if len(sys.argv) < 2:
        print("Usage: fix_engine.py <action> <check_id> [options]", file=sys.stderr)
        print("Actions: plan, execute, rollback, verify, list", file=sys.stderr)
        sys.exit(1)

    action = sys.argv[1]

    if action == "list":
        list_fixes()

    if action == "plan":
        if len(sys.argv) < 3:
            output_error("Falta check_id", "Missing check_id")
        check_id = sys.argv[2]
        target_user = ""
        lang = "es"

        # Parse optional args
        i = 3
        while i < len(sys.argv):
            if sys.argv[i] == "--user" and i + 1 < len(sys.argv):
                target_user = sys.argv[i + 1]
                i += 2
            elif sys.argv[i] == "--lang" and i + 1 < len(sys.argv):
                lang = sys.argv[i + 1]
                i += 2
            else:
                i += 1

        if check_id not in AVAILABLE_FIXES:
            output_error(
                f"Check '{check_id}' no tiene auto-fix disponible.",
                f"Check '{check_id}' doesn't have auto-fix available.",
            )

        result = AVAILABLE_FIXES[check_id]["plan_fn"](target_user, lang)
        output(result)

    elif action == "execute":
        if len(sys.argv) < 4:
            output_error("Falta check_id y step_id", "Missing check_id and step_id")
        check_id = sys.argv[2]
        step_id = int(sys.argv[3])
        execute_step(check_id, step_id)

    elif action == "rollback":
        if len(sys.argv) < 3:
            output_error("Falta check_id", "Missing check_id")
        check_id = sys.argv[2]
        rollback(check_id)

    elif action == "verify":
        if len(sys.argv) < 3:
            output_error("Falta check_id", "Missing check_id")
        check_id = sys.argv[2]
        verify(check_id)

    else:
        output_error(f"Acción desconocida: {action}", f"Unknown action: {action}")


if __name__ == "__main__":
    main()
