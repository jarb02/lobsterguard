#!/bin/bash
# LobsterGuard Monitor v5.0
# Runs security checks automatically and alerts via Telegram on critical findings.
# Designed to run as a cron job every 6 hours.
#
# Features:
# - Runs check.py and saves report for OpenClaw to read instantly
# - Sends Telegram alert ONLY when new critical/high issues appear
# - Repeats critical alerts every 24h until resolved
# - Zero configuration needed — uses OpenClaw's existing Telegram channel
#
# Install: sudo crontab -e → add:
#   0 */6 * * * /root/.openclaw/skills/lobsterguard/scripts/monitor.sh

set -euo pipefail

LOBSTERGUARD_DIR="/root/.openclaw/skills/lobsterguard"
SCRIPTS_DIR="$LOBSTERGUARD_DIR/scripts"
DATA_DIR="$LOBSTERGUARD_DIR/data"
REPORT_FILE="$DATA_DIR/latest-report.txt"
REPORT_JSON="$DATA_DIR/latest-report.json"
LAST_ALERT_FILE="$DATA_DIR/last-alert.json"
LAST_CRITICAL_ALERT="$DATA_DIR/last-critical-alert-time"

# Create data directory if needed
mkdir -p "$DATA_DIR"

# ─── Step 1: Run the security scan ──────────────────────────────────────────
echo "[$(date)] LobsterGuard monitor: running scan..."

# Generate text report
python3 "$SCRIPTS_DIR/check.py" > "$REPORT_FILE" 2>&1

# Generate JSON report for comparison
python3 "$SCRIPTS_DIR/check.py" --json > "$REPORT_JSON" 2>&1

echo "[$(date)] Scan complete. Report saved to $REPORT_FILE"

# ─── Step 2: Extract current failures ───────────────────────────────────────
# Get current critical and high failures as a sorted list
CURRENT_FAILURES=$(python3 -c "
import json, sys
try:
    with open('$REPORT_JSON') as f:
        report = json.load(f)
    failures = []
    for c in report.get('checks', []):
        if not c['passed'] and c['severity'] in ('CRITICAL', 'HIGH'):
            failures.append(c['id'] + ':' + c['severity'])
    failures.sort()
    print(json.dumps(failures))
except Exception as e:
    print('[]')
    sys.exit(0)
")

CRITICAL_COUNT=$(python3 -c "
import json
try:
    with open('$REPORT_JSON') as f:
        report = json.load(f)
    print(report.get('failure_summary', {}).get('critical', 0))
except:
    print(0)
")

HIGH_COUNT=$(python3 -c "
import json
try:
    with open('$REPORT_JSON') as f:
        report = json.load(f)
    print(report.get('failure_summary', {}).get('high', 0))
except:
    print(0)
")

SCORE=$(python3 -c "
import json
try:
    with open('$REPORT_JSON') as f:
        report = json.load(f)
    print(report.get('score', 0))
except:
    print(0)
")

TOTAL_PASSED=$(python3 -c "
import json
try:
    with open('$REPORT_JSON') as f:
        report = json.load(f)
    print(report.get('failure_summary', {}).get('total_passed', 0))
except:
    print(0)
")

TOTAL_CHECKS=$(python3 -c "
import json
try:
    with open('$REPORT_JSON') as f:
        report = json.load(f)
    print(report.get('failure_summary', {}).get('total_checks', 0))
except:
    print(0)
")

# ─── Step 3: Compare with previous scan ─────────────────────────────────────
PREVIOUS_FAILURES="[]"
if [ -f "$LAST_ALERT_FILE" ]; then
    PREVIOUS_FAILURES=$(cat "$LAST_ALERT_FILE")
fi

# Check if failures changed (new issues appeared)
NEW_ISSUES=$(python3 -c "
import json
current = json.loads('$CURRENT_FAILURES')
previous = json.loads('$PREVIOUS_FAILURES')
new = [f for f in current if f not in previous]
print(json.dumps(new))
")

RESOLVED_ISSUES=$(python3 -c "
import json
current = json.loads('$CURRENT_FAILURES')
previous = json.loads('$PREVIOUS_FAILURES')
resolved = [f for f in previous if f not in current]
print(json.dumps(resolved))
")

HAS_NEW=$(python3 -c "
import json
new = json.loads('$NEW_ISSUES')
print('yes' if len(new) > 0 else 'no')
")

HAS_RESOLVED=$(python3 -c "
import json
resolved = json.loads('$RESOLVED_ISSUES')
print('yes' if len(resolved) > 0 else 'no')
")

# ─── Step 4: Determine if we should send alert ──────────────────────────────
SEND_ALERT="no"
ALERT_TYPE=""

# Case 1: New issues appeared
if [ "$HAS_NEW" = "yes" ]; then
    SEND_ALERT="yes"
    ALERT_TYPE="new"
fi

# Case 2: Issues were resolved (good news!)
if [ "$HAS_RESOLVED" = "yes" ] && [ "$CURRENT_FAILURES" = "[]" ]; then
    SEND_ALERT="yes"
    ALERT_TYPE="resolved"
fi

# Case 3: Critical issues still exist — repeat every 24h
if [ "$CRITICAL_COUNT" -gt 0 ] && [ "$SEND_ALERT" = "no" ]; then
    if [ -f "$LAST_CRITICAL_ALERT" ]; then
        LAST_TIME=$(cat "$LAST_CRITICAL_ALERT")
        NOW=$(date +%s)
        DIFF=$((NOW - LAST_TIME))
        # 86400 seconds = 24 hours
        if [ "$DIFF" -ge 86400 ]; then
            SEND_ALERT="yes"
            ALERT_TYPE="reminder"
        fi
    else
        SEND_ALERT="yes"
        ALERT_TYPE="reminder"
    fi
fi

# ─── Step 5: Send Telegram alert via OpenClaw ────────────────────────────────
if [ "$SEND_ALERT" = "yes" ]; then
    echo "[$(date)] Sending alert (type: $ALERT_TYPE)..."

    # Build the alert message based on type
    if [ "$ALERT_TYPE" = "new" ]; then
        # New issues detected
        NEW_LIST=$(python3 -c "
import json
new = json.loads('$NEW_ISSUES')
lines = []
for f in new:
    name, sev = f.split(':')
    emoji = '🔴' if sev == 'CRITICAL' else '🟠'
    lines.append(f'{emoji} {name}')
print('\n'.join(lines))
")
        MSG="🚨 LobsterGuard — Nuevos problemas detectados

Score: ${SCORE}/100 | ${TOTAL_PASSED}/${TOTAL_CHECKS} checks OK

Nuevos problemas:
${NEW_LIST}

Escribe \"revisa mi seguridad\" para ver el reporte completo y corregirlos."

    elif [ "$ALERT_TYPE" = "reminder" ]; then
        # Reminder for unresolved critical issues
        CRIT_LIST=$(python3 -c "
import json
current = json.loads('$CURRENT_FAILURES')
lines = []
for f in current:
    name, sev = f.split(':')
    if sev == 'CRITICAL':
        lines.append(f'🔴 {name}')
print('\n'.join(lines))
")
        MSG="⏰ LobsterGuard — Recordatorio: problemas críticos sin resolver

Score: ${SCORE}/100

Problemas críticos pendientes:
${CRIT_LIST}

Estos problemas llevan más de 24h sin resolverse. Escribe \"revisa mi seguridad\" para que te ayude a corregirlos."

    elif [ "$ALERT_TYPE" = "resolved" ]; then
        MSG="✅ LobsterGuard — ¡Todo limpio!

Score: ${SCORE}/100 | ${TOTAL_PASSED}/${TOTAL_CHECKS} checks OK

Todos los problemas críticos y altos han sido resueltos. Tu servidor está bien protegido. 🛡️"
    fi

    # Auto-discover user's channel and ID from OpenClaw sessions (zero config)
    # Works with ANY channel: Telegram, WhatsApp, Discord, Slack, Signal, etc.
    SESSIONS_FILE="/root/.openclaw/agents/main/sessions/sessions.json"
    DELIVERY_INFO=$(python3 -c "
import json, os
try:
    with open('$SESSIONS_FILE') as f:
        sessions = json.load(f)
    # Find the most recent direct session with any provider
    best = None
    best_ts = ''
    for key, val in sessions.items():
        origin = val.get('origin', {})
        provider = origin.get('provider', '')
        chat_type = origin.get('chatType', '')
        if provider and chat_type == 'direct':
            # Use session key as rough timestamp proxy (later entries = more recent)
            ts = val.get('lastActivity', val.get('createdAt', key))
            if ts >= best_ts:
                best_ts = ts
                best = val
    if best:
        origin = best['origin']
        provider = origin['provider']
        from_field = origin.get('from', '')
        # Extract target ID: remove provider prefix (e.g., 'telegram:123' -> '123')
        target = from_field.replace(f'{provider}:', '') if ':' in from_field else from_field
        print(f'{provider}|{target}')
except:
    pass
" 2>/dev/null)

    if [ -n "$DELIVERY_INFO" ]; then
        CHANNEL=$(echo "$DELIVERY_INFO" | cut -d'|' -f1)
        TARGET=$(echo "$DELIVERY_INFO" | cut -d'|' -f2)
        echo "[$(date)] Sending via ${CHANNEL} to ${TARGET}..."
        openclaw message send --channel "$CHANNEL" --target "$TARGET" --message "$MSG" 2>/dev/null || \
            echo "[$(date)] Warning: could not send alert via $CHANNEL"
    else
        echo "[$(date)] Warning: no active user session found in OpenClaw"
    fi

    # Update tracking files
    echo "$CURRENT_FAILURES" > "$LAST_ALERT_FILE"

    if [ "$CRITICAL_COUNT" -gt 0 ]; then
        date +%s > "$LAST_CRITICAL_ALERT"
    else
        rm -f "$LAST_CRITICAL_ALERT"
    fi

    echo "[$(date)] Alert sent successfully."
else
    echo "[$(date)] No new issues. No alert needed."
    # Still update the failures file for next comparison
    echo "$CURRENT_FAILURES" > "$LAST_ALERT_FILE"
fi

echo "[$(date)] LobsterGuard monitor complete."
