#!/bin/bash

# LobsterGuard RunAll Wrapper - Executes all fixable checks
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== LobsterGuard RunAll Started ==="
echo "Time: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

# Initialize output
OUTPUT=""

# Non-privileged checks
CHECKS=("firewall_config" "backup_config" "kernel_hardening" "core_dumps" "audit_logging" "sandbox_security" "session_token_security" "tmp_security" "code_integrity")

echo "Running non-privileged checks..."
for check in "${CHECKS[@]}"; do
    echo "  - Processing: $check"
    OUTPUT+=$'=== '"$check"$' ===\n'
    OUTPUT+=$(python3 -W ignore "$SCRIPT_DIR/fix_engine.py" fix "$check" --telegram 2>&1)
    OUTPUT+=$'\n\n'
done

# Privileged checks
SUDO_CHECKS=("openclaw_user" "code_integrity" "tmp_security" "session_token_security" "sandbox_security" "audit_logging" "core_dumps" "kernel_hardening")

echo "Running privileged checks (with sudo)..."
for check in "${SUDO_CHECKS[@]}"; do
    echo "  - Processing: $check (sudo)"
    OUTPUT+=$'=== '"$check"$' (sudo) ===\n'
    OUTPUT+=$(sudo python3 -W ignore "$SCRIPT_DIR/fix_engine.py" fix "$check" --telegram 2>&1)
    OUTPUT+=$'\n\n'
done

# Print all results
echo ""
echo "=== RESULTS ==="
echo "$OUTPUT"

# Summary
echo ""
echo "🛡 LobsterGuard RunAll Complete / Ejecución completa"
echo "Time: $(date '+%Y-%m-%d %H:%M:%S')"
