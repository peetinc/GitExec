#!/bin/bash
# test-gitexec.sh - Simple test script to verify GitExec implementation
# Copyright (C) 2026 Peet, Inc. - Licensed under GPLv2

LOG_FILE="/tmp/gitexec-test.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# Function to log and echo
log() {
    echo "$1"
    echo "[$TIMESTAMP] $1" >> "$LOG_FILE"
}

# Append to log
echo "" >> "$LOG_FILE"
echo "=== GitExec Test Run: $TIMESTAMP ===" >> "$LOG_FILE"

log "GitExec Test Script - macOS/Linux"
log "=================================="

# Hostname
HOSTNAME=$(hostname)
log "Hostname: $HOSTNAME"

# Machine UUID/GUID
if [[ "$(uname)" == "Darwin" ]]; then
    # macOS - get hardware UUID
    MACHINE_UUID=$(ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}')
else
    # Linux - try multiple methods
    if [[ -f /etc/machine-id ]]; then
        MACHINE_UUID=$(cat /etc/machine-id)
    elif [[ -f /sys/class/dmi/id/product_uuid ]]; then
        MACHINE_UUID=$(cat /sys/class/dmi/id/product_uuid 2>/dev/null || echo "N/A")
    else
        MACHINE_UUID="N/A"
    fi
fi
log "Machine UUID: $MACHINE_UUID"

# Primary IP address
if [[ "$(uname)" == "Darwin" ]]; then
    # macOS - get primary interface IP
    PRIMARY_IF=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
    if [[ -n "$PRIMARY_IF" ]]; then
        PRIMARY_IP=$(ipconfig getifaddr "$PRIMARY_IF" 2>/dev/null)
    else
        PRIMARY_IP=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null)
    fi
else
    # Linux
    PRIMARY_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')
    if [[ -z "$PRIMARY_IP" ]]; then
        PRIMARY_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    fi
fi
log "Primary IP: ${PRIMARY_IP:-N/A}"

# Additional info
log ""
log "Additional Info:"
log "  OS: $(uname -s) $(uname -r)"
log "  User: $(whoami)"
log "  PWD: $(pwd)"
log "  Date: $(date)"

log ""
log "=================================="
log "GitExec test completed successfully!"
log "Log written to: $LOG_FILE"

exit 0
