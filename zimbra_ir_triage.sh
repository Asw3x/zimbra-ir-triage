#!/usr/bin/env bash
# ==============================================================================
# Script: zimbra_ir_triage.sh
# Purpose: Autonomous Comprehensive Incident Response & Forensic Triage for ZCS
# Author: Aleksey Kostin — https://github.com/Asw3x
# Mode: Read-Only (Non-destructive, zero state change, 100% passive audit)
# Compatible: RHEL/CentOS/Rocky/Alma/Debian/Ubuntu running Zimbra 8.x / 9.x / 10.x
# ==============================================================================

set -uo pipefail

# ------------------------------------------------------------------------------
# 0. CONFIGURATION, COLORS & INITIALIZATION
# ------------------------------------------------------------------------------

# Self-Throttling: Ensure 0% disruption to production services (Lowest CPU/IO priority)
renice -n 15 $$ &>/dev/null || true
ionice -c 2 -n 7 -p $$ &>/dev/null || ionice -c 3 -p $$ &>/dev/null || true

if [[ -t 1 ]]; then
    BOLD="\e[1m"
    DIM="\e[2m"
    RED="\e[1;31m"
    GREEN="\e[1;32m"
    YELLOW="\e[1;33m"
    BLUE="\e[1;34m"
    CYAN="\e[1;36m"
    MAGENTA="\e[1;35m"
    RESET="\e[0m"
else
    BOLD=""
    DIM=""
    RED=""
    GREEN=""
    YELLOW=""
    BLUE=""
    CYAN=""
    MAGENTA=""
    RESET=""
fi

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
HUMAN_DATE=$(date +"%Y-%m-%d %H:%M:%S %Z")
REPORT_FILE="/tmp/zimbra_triage_report_${TIMESTAMP}.txt"
TEMP_DIR=$(mktemp -d /tmp/zimbra_triage_XXXXXX 2>/dev/null || echo "/tmp/zimbra_triage_${TIMESTAMP}")
mkdir -p "${TEMP_DIR}" 2>/dev/null || true

# Summary Indicators / Finding Counters
FINDING_SASL_ABUSE=0
FINDING_OPEN_RELAY=0
FINDING_SUSPICIOUS_JSP=0
FINDING_MAIL_FORWARD=0
FINDING_SIEVE_RULES=0
FINDING_GLOBAL_BCC=0
FINDING_ADMIN_ANOMALY=0
FINDING_WEB_EXPLOIT=0
FINDING_AUDIT_EXPLOIT=0
FINDING_SUSPICIOUS_PROC=0
FINDING_MEMORY_DELETED=0
FINDING_RBL_LISTED=0
FINDING_PERSISTENCE=0
FINDING_ADMIN_PORT_EXPOSED=0
FINDING_SPOOFING_PERMISSIVE=0
FINDING_NO_LOCKOUT=0
FINDING_NO_POLICYD=0
FINDING_DNS_MISSING=0

cleanup() {
    rm -rf "${TEMP_DIR}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

log_raw() {
    local msg="$1"
    echo -e "${msg}"
    # Strip ANSI colors when appending to report file
    echo -e "${msg}" | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,3})*)?[mGK]//g" >> "${REPORT_FILE}"
}

log_header() {
    local title="$1"
    log_raw "\n${BLUE}================================================================================${RESET}"
    log_raw "${BOLD}${CYAN}>>> [${title}]${RESET}"
    log_raw "${BLUE}================================================================================${RESET}"
}

log_sub() {
    local subtitle="$1"
    log_raw "\n${BOLD}${MAGENTA}--- ${subtitle} ---${RESET}"
}

log_info() {
    log_raw "${BLUE}[*]${RESET} $1"
}

log_ok() {
    log_raw "${GREEN}[+]${RESET} $1"
}

log_warn() {
    log_raw "${YELLOW}[!] WARNING:${RESET} $1"
}

log_alert() {
    log_raw "${RED}[CRITICAL ALERT]${RESET} $1"
}

run_as_zimbra() {
    local cmd="$1"
    if id "zimbra" &>/dev/null; then
        su - zimbra -c "${cmd}" 2>/dev/null || true
    else
        log_warn "User 'zimbra' not found on system!"
    fi
}

# ------------------------------------------------------------------------------
# 0.1 ROOT CHECK & TOOL AVAILABILITY
# ------------------------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo -e "\e[1;31m[ERROR] This script must be run as root to access all logs and configurations.\e[0m" >&2
    exit 1
fi

touch "${REPORT_FILE}" 2>/dev/null || {
    echo -e "\e[1;31m[ERROR] Unable to create report file at ${REPORT_FILE}\e[0m" >&2
    exit 1
}

# Banner
log_raw "${CYAN}${BOLD}"
log_raw "################################################################################"
log_raw "#            ZIMBRA (ZCS) INCIDENT RESPONSE & FORENSIC TRIAGE TOOL             #"
log_raw "#             Automated Digital Evidence Collector (T-9 Days Post-IR)          #"
log_raw "#                    Mode: 100% Passive / Read-Only Audit                      #"
log_raw "################################################################################"
log_raw "${RESET}"
log_info "Execution Time: ${HUMAN_DATE}"
log_info "Hostname:       $(hostname -f 2>/dev/null || hostname)"
log_info "Report File:    ${REPORT_FILE}"
log_info "Audit Mode:     Read-Only (Non-Destructive, Zero Configuration Changes)"

# Check core binaries
POSTCONF="/opt/zimbra/common/sbin/postconf"
[[ ! -x "${POSTCONF}" ]] && POSTCONF="/opt/zimbra/postfix/sbin/postconf"
POSTQUEUE="/opt/zimbra/common/sbin/postqueue"
[[ ! -x "${POSTQUEUE}" ]] && POSTQUEUE="/opt/zimbra/postfix/sbin/postqueue"
QSHAPE="/opt/zimbra/common/sbin/qshape"
[[ ! -x "${QSHAPE}" ]] && QSHAPE="/opt/zimbra/postfix/sbin/qshape"
LDAP_SEARCH_BIN="/opt/zimbra/common/bin/ldapsearch"
[[ ! -x "${LDAP_SEARCH_BIN}" ]] && LDAP_SEARCH_BIN="/opt/zimbra/openldap/bin/ldapsearch"

# Retrieve LDAP Credentials for low-overhead bulk inspection
LDAP_PASSWORD=$(run_as_zimbra "zmlocalconfig -s -m nokey zimbra_ldap_password" 2>/dev/null || true)
LDAP_MASTER=$(run_as_zimbra "zmlocalconfig -s -m nokey ldap_master_url" 2>/dev/null || true)

# ------------------------------------------------------------------------------
# MODULE 1: SYSTEM & ZIMBRA ENVIRONMENT + RBL REPUTATION
# ------------------------------------------------------------------------------
log_header "MODULE 1: SYSTEM, ZIMBRA ENVIRONMENT & RBL REPUTATION"

log_sub "Operating System & System Vitals"
if [[ -f /etc/os-release ]]; then
    OS_NAME=$(grep -E '^PRETTY_NAME=' /etc/os-release | cut -d= -f2 | tr -d '"')
    log_info "OS Distribution: ${OS_NAME}"
elif [[ -f /etc/redhat-release ]]; then
    log_info "OS Distribution: $(cat /etc/redhat-release)"
elif [[ -f /etc/debian_version ]]; then
    log_info "OS Distribution: Debian $(cat /etc/debian_version)"
else
    log_info "OS Distribution: $(uname -s -r -m)"
fi

log_info "Kernel:          $(uname -r -m)"
log_info "System Uptime:   $(uptime -p 2>/dev/null || uptime)"
log_info "Current Load:    $(uptime | awk -F'load average:' '{print $2}' | sed 's/^[ \t]*//')"

log_sub "Network Identifiers & Interfaces"
LOCAL_IPS=$(ip -4 addr show 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | tr '\n' ' ' || hostname -I 2>/dev/null || echo "Unknown")
log_info "Local IPv4 Addrs: ${LOCAL_IPS}"

PUBLIC_IP=$(curl -s --max-time 4 https://ifconfig.me 2>/dev/null || \
           curl -s --max-time 4 https://api.ipify.org 2>/dev/null || \
           curl -s --max-time 4 https://icanhazip.com 2>/dev/null || \
           echo "Unavailable")
log_info "Public IP Addr:  ${PUBLIC_IP}"

# Real-Time DNSBL / RBL Reputation Check
log_sub "Live IP Reputation & Spam Blacklists (DNSBL / RBL Check)"
if [[ -n "${PUBLIC_IP}" ]] && [[ "${PUBLIC_IP}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    REV_IP=$(echo "${PUBLIC_IP}" | awk -F. '{print $4"."$3"."$2"."$1}')
    RBL_LIST=(
        "zen.spamhaus.org"
        "b.barracudacentral.org"
        "bl.spamcop.net"
        "dnsbl.sorbs.net"
        "psbl.surriel.com"
        "bl.mailspike.net"
        "ix.dnsbl.manitu.net"
        "dnsbl-1.uceprotect.net"
    )

    log_info "Querying major spam blacklists for reverse IP: ${REV_IP}..."
    for rbl in "${RBL_LIST[@]}"; do
        RBL_HIT=""
        if command -v dig &>/dev/null; then
            RBL_HIT=$(dig +short +time=2 +tries=1 "${REV_IP}.${rbl}" 2>/dev/null || true)
        elif command -v host &>/dev/null; then
            RBL_HIT=$(host -W 2 -t A "${REV_IP}.${rbl}" 2>/dev/null | grep "has address" || true)
        fi

        if [[ -n "${RBL_HIT}" ]]; then
            log_alert "BLACKLIST HIT: IP ${PUBLIC_IP} is LISTED in ${BOLD}${rbl}${RESET} (Result: ${RBL_HIT})"
            FINDING_RBL_LISTED=$((FINDING_RBL_LISTED + 1))
        else
            log_ok "Clean in ${rbl}"
        fi
    done
else
    log_warn "Public IP is private or unavailable, skipping DNSBL check."
fi

log_sub "ZCS Version & Service Health"
ZCS_VERSION=$(run_as_zimbra "zmcontrol -v")
if [[ -n "${ZCS_VERSION}" ]]; then
    log_info "ZCS Version: ${BOLD}${ZCS_VERSION}${RESET}"
else
    log_warn "Unable to retrieve ZCS version via 'zmcontrol -v'."
fi

log_info "Status of Zimbra Services (zmcontrol status):"
ZM_STATUS=$(run_as_zimbra "zmcontrol status")
if [[ -n "${ZM_STATUS}" ]]; then
    while IFS= read -r line; do
        if echo "${line}" | grep -iq "Running"; then
            log_raw "  ${GREEN}[+]${RESET} ${line}"
        elif echo "${line}" | grep -iq "Stopped"; then
            log_raw "  ${RED}[!]${RESET} ${line}"
            FINDING_PERSISTENCE=$((FINDING_PERSISTENCE + 1))
        else
            log_raw "      ${line}"
        fi
    done <<< "${ZM_STATUS}"
else
    log_warn "zmcontrol status returned empty output."
fi

log_sub "Installed Zimbra Packages Summary"
if command -v rpm &>/dev/null; then
    Z_PKGS=$(rpm -qa 2>/dev/null | grep -iE 'zimbra' | sort)
    log_info "Core RPM Packages count: $(echo "${Z_PKGS}" | grep -c 'zimbra' || echo 0)"
    log_raw "${DIM}${Z_PKGS}${RESET}"
elif command -v dpkg &>/dev/null; then
    Z_PKGS=$(dpkg -l 2>/dev/null | grep -iE 'zimbra' | awk '{print $2, $3}')
    log_info "Core DEB Packages count: $(echo "${Z_PKGS}" | grep -c 'zimbra' || echo 0)"
    log_raw "${DIM}${Z_PKGS}${RESET}"
fi

# ------------------------------------------------------------------------------
# MODULE 2: POSTFIX MAIL QUEUE STATE
# ------------------------------------------------------------------------------
log_header "MODULE 2: POSTFIX MAIL QUEUE INSPECTION"

log_sub "Current Queue Size"
MAILQ_OUTPUT=$(run_as_zimbra "mailq")
QUEUE_SUMMARY=$(echo "${MAILQ_OUTPUT}" | tail -n 2)
log_info "Mailq summary:"
log_raw "  ${QUEUE_SUMMARY}"

TOTAL_QUEUED=0
if echo "${QUEUE_SUMMARY}" | grep -q "Mail queue is empty"; then
    log_ok "Postfix mail queue is completely empty."
else
    TOTAL_QUEUED=$(echo "${MAILQ_OUTPUT}" | grep -E -c '^[0-9A-F]{10,12}[*! ]|^[0-9A-Za-z]{10,16}[*! ]' || echo 0)
    if [[ ${TOTAL_QUEUED} -gt 500 ]]; then
        log_alert "High volume of messages in mail queue: ~${TOTAL_QUEUED} messages! Potential active spam outbreak."
        FINDING_SASL_ABUSE=$((FINDING_SASL_ABUSE + 1))
    else
        log_warn "Total messages waiting in queue: ~${TOTAL_QUEUED}"
    fi
fi

log_sub "Queue Breakdown (qshape: Active & Deferred)"
if [[ -x "${QSHAPE}" ]]; then
    log_info "Analyzing Deferred Queue (Recent vs Stalled):"
    QSHAPE_DEF=$(run_as_zimbra "${QSHAPE} -s deferred" | head -n 15 || true)
    if [[ -n "${QSHAPE_DEF}" ]]; then
        log_raw "${DIM}${QSHAPE_DEF}${RESET}"
    else
        log_info "Deferred queue is empty."
    fi

    log_info "Analyzing Active Queue (Top Domains):"
    QSHAPE_ACT=$(run_as_zimbra "${QSHAPE} -s active" | head -n 15 || true)
    if [[ -n "${QSHAPE_ACT}" ]]; then
        log_raw "${DIM}${QSHAPE_ACT}${RESET}"
    else
        log_info "Active queue is empty."
    fi
else
    log_warn "qshape utility not found at standard Zimbra paths."
fi

log_sub "Top Senders & Recipients in Queue"
if [[ -n "${MAILQ_OUTPUT}" ]] && ! echo "${MAILQ_OUTPUT}" | grep -q "Mail queue is empty"; then
    log_info "Top 10 Senders in Queue:"
    TOP_SENDERS=$(echo "${MAILQ_OUTPUT}" | grep -oP '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' | \
                  awk '{seen[$1]++} END {for (i in seen) print seen[i], i}' | sort -nr | head -n 10 || true)
    if [[ -n "${TOP_SENDERS}" ]]; then
        while IFS= read -r line; do
            log_raw "  ${YELLOW}${line}${RESET}"
        done <<< "${TOP_SENDERS}"
    fi

    log_info "Top 10 Domains in Queue:"
    TOP_DOMAINS=$(echo "${MAILQ_OUTPUT}" | grep -oP '@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' | \
                  awk '{seen[$1]++} END {for (i in seen) print seen[i], i}' | sort -nr | head -n 10 || true)
    if [[ -n "${TOP_DOMAINS}" ]]; then
        while IFS= read -r line; do
            log_raw "  ${CYAN}${line}${RESET}"
        done <<< "${TOP_DOMAINS}"
    fi
fi

# ------------------------------------------------------------------------------
# MODULE 3: POSTFIX & SASL LOG ANALYSIS (T-9 DAYS FORENSICS)
# ------------------------------------------------------------------------------
log_header "MODULE 3: POSTFIX & SASL LOGS (COMPROMISED ACCOUNTS & ATTACKERS)"

LOG_FILES=()
for lf in /var/log/zimbra.log /var/log/mail.log /var/log/maillog; do
    if [[ -f "${lf}" ]]; then
        LOG_FILES+=("${lf}")
        for rlog in $(find "$(dirname "${lf}")" -maxdepth 1 -name "$(basename "${lf}")*" -mtime -30 2>/dev/null); do
            if [[ "${rlog}" != "${lf}" ]]; then
                LOG_FILES+=("${rlog}")
            fi
        done
        break
    fi
done

if [[ ${#LOG_FILES[@]} -eq 0 ]]; then
    log_warn "No Postfix/Zimbra log files found in /var/log/ (checked zimbra.log, mail.log, maillog)."
else
    log_info "Analyzing Postfix log files (${#LOG_FILES[@]} file(s) identified):"
    for f in "${LOG_FILES[@]}"; do
        log_raw "  - ${f} ($(stat -c '%y' "${f}" 2>/dev/null || ls -l "${f}" | awk '{print $6,$7,$8}'))"
    done
fi

log_sub "Top 15 Accounts with Successful SASL Authentication"
SASL_SUCCESS_TMP="${TEMP_DIR}/sasl_success.txt"
if [[ ${#LOG_FILES[@]} -gt 0 ]]; then
    for f in "${LOG_FILES[@]}"; do
        if [[ "${f}" == *.gz ]]; then
            gzip -dc "${f}" 2>/dev/null | grep -E 'sasl_username=' | sed -n 's/.*sasl_username=\([^, ]*\).*/\1/p' >> "${SASL_SUCCESS_TMP}" || true
        else
            grep -E 'sasl_username=' "${f}" 2>/dev/null | sed -n 's/.*sasl_username=\([^, ]*\).*/\1/p' >> "${SASL_SUCCESS_TMP}" || true
        fi
    done

    if [[ -s "${SASL_SUCCESS_TMP}" ]]; then
        log_info "Ranked successful SASL authentications (Account : Sent/Relayed count):"
        sort "${SASL_SUCCESS_TMP}" | uniq -c | sort -nr | head -n 15 | while IFS= read -r line; do
            count=$(echo "${line}" | awk '{print $1}')
            user=$(echo "${line}" | awk '{print $2}')
            if [[ ${count} -gt 1000 ]]; then
                log_raw "  ${RED}[!] ${count} msgs -> ${user} (VERY HIGH VOLUME - Suspect Compromised)${RESET}"
                FINDING_SASL_ABUSE=$((FINDING_SASL_ABUSE + 1))
            elif [[ ${count} -gt 200 ]]; then
                log_raw "  ${YELLOW}[*] ${count} msgs -> ${user} (Elevated Volume)${RESET}"
            else
                log_raw "  ${GREEN}[+]${RESET} ${count} msgs -> ${user}"
            fi
        done
    else
        log_info "No SASL authenticated transactions recorded in the parsed logs."
    fi
fi

log_sub "SASL Authentication IP Mapping (Account <-> IP Mapping)"
SASL_IP_TMP="${TEMP_DIR}/sasl_user_ip.txt"
if [[ ${#LOG_FILES[@]} -gt 0 ]]; then
    for f in "${LOG_FILES[@]}"; do
        if [[ "${f}" == *.gz ]]; then
            gzip -dc "${f}" 2>/dev/null | grep -E 'sasl_username=' | grep -oP 'client=[^, ]+|sasl_username=[^, ]+' | paste - - 2>/dev/null >> "${SASL_IP_TMP}" || true
        else
            grep -E 'sasl_username=' "${f}" 2>/dev/null | grep -oP 'client=[^, ]+|sasl_username=[^, ]+' | paste - - 2>/dev/null >> "${SASL_IP_TMP}" || true
        fi
    done

    if [[ -s "${SASL_IP_TMP}" ]]; then
        log_info "Top 15 Client IPs authenticating to user accounts:"
        sort "${SASL_IP_TMP}" | uniq -c | sort -nr | head -n 15 | while IFS= read -r line; do
            log_raw "  ${line}"
        done
    fi
fi

log_sub "Daily Outbound Sent Volume (Last 14-30 Days Trend)"
DAILY_SENT_TMP="${TEMP_DIR}/daily_sent.txt"
if [[ ${#LOG_FILES[@]} -gt 0 ]]; then
    for f in "${LOG_FILES[@]}"; do
        if [[ "${f}" == *.gz ]]; then
            gzip -dc "${f}" 2>/dev/null | grep -E 'status=sent' | awk '{print $1, $2}' >> "${DAILY_SENT_TMP}" || true
        else
            grep -E 'status=sent' "${f}" 2>/dev/null | awk '{print $1, $2}' >> "${DAILY_SENT_TMP}" || true
        fi
    done

    if [[ -s "${DAILY_SENT_TMP}" ]]; then
        log_info "Message distribution per calendar day (status=sent):"
        sort "${DAILY_SENT_TMP}" | uniq -c | sort -k2,2M -k3,3n | while IFS= read -r line; do
            count=$(echo "${line}" | awk '{print $1}')
            day=$(echo "${line}" | awk '{print $2, $3}')
            if [[ ${count} -gt 5000 ]]; then
                log_raw "  ${RED}${day}: ${count} sent (POTENTIAL SPAM SPIKE)${RESET}"
            elif [[ ${count} -gt 1500 ]]; then
                log_raw "  ${YELLOW}${day}: ${count} sent${RESET}"
            else
                log_raw "  ${GREEN}${day}: ${count} sent${RESET}"
            fi
        done
    fi
fi

log_sub "Top 10 Failed SASL / Login IPs (Brute Force / Password Spraying)"
FAILED_AUTH_TMP="${TEMP_DIR}/failed_auth.txt"
if [[ ${#LOG_FILES[@]} -gt 0 ]]; then
    for f in "${LOG_FILES[@]}"; do
        if [[ "${f}" == *.gz ]]; then
            gzip -dc "${f}" 2>/dev/null | grep -iE 'authentication failed|SASL LOGIN failed|authentication failure' | grep -oP '\[\K[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?=\])|client=[^, ]+' >> "${FAILED_AUTH_TMP}" || true
        else
            grep -iE 'authentication failed|SASL LOGIN failed|authentication failure' "${f}" 2>/dev/null | grep -oP '\[\K[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?=\])|client=[^, ]+' >> "${FAILED_AUTH_TMP}" || true
        fi
    done

    if [[ -s "${FAILED_AUTH_TMP}" ]]; then
        log_info "Top source IP addresses attempting unauthorized logins:"
        sort "${FAILED_AUTH_TMP}" | uniq -c | sort -nr | head -n 10 | while IFS= read -r line; do
            log_raw "  ${RED}${line}${RESET}"
        done
    else
        log_info "No prominent SASL authentication failure spikes found."
    fi
fi

# ------------------------------------------------------------------------------
# MODULE 4: ZIMBRA CONFIGURATION, SIEVE & BCC AUDIT
# ------------------------------------------------------------------------------
log_header "MODULE 4: ZIMBRA CONFIGURATION, SIEVE FILTERS & BCC AUDIT"

log_sub "Open Relay & Trusted Networks Audit (zimbraMtaMyNetworks)"
MY_NETWORKS=$(run_as_zimbra "zmprov gacf zimbraMtaMyNetworks" | grep -v '^#' || true)
if [[ -z "${MY_NETWORKS}" ]]; then
    SERVER_HOSTNAME=$(hostname -f 2>/dev/null || hostname)
    MY_NETWORKS=$(run_as_zimbra "zmprov gs ${SERVER_HOSTNAME} zimbraMtaMyNetworks" | grep -v '^#' || true)
fi

log_info "zimbraMtaMyNetworks value:"
log_raw "  ${MY_NETWORKS}"

if echo "${MY_NETWORKS}" | grep -E -q '0\.0\.0\.0/0|0/0|::/0'; then
    log_alert "OPEN RELAY DETECTED: '0.0.0.0/0' found in zimbraMtaMyNetworks! Any internet host can send unauthenticated spam!"
    FINDING_OPEN_RELAY=1
else
    SUSPICIOUS_NETWORKS=0
    for net in $(echo "${MY_NETWORKS}" | grep -oP '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?'); do
        if ! echo "${net}" | grep -E -q '^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)'; then
            log_warn "Non-RFC1918 public network found in trusted networks: ${net}"
            SUSPICIOUS_NETWORKS=$((SUSPICIOUS_NETWORKS + 1))
        fi
    done
    if [[ ${SUSPICIOUS_NETWORKS} -eq 0 ]]; then
        log_ok "zimbraMtaMyNetworks configuration appears restricted to local/private ranges."
    fi
fi

log_sub "Global Mail Interception Audit (Postfix BCC Maps)"
for bcc_param in "always_bcc" "sender_bcc_maps" "recipient_bcc_maps"; do
    BCC_VAL=""
    if [[ -x "${POSTCONF}" ]]; then
        BCC_VAL=$("${POSTCONF}" -h "${bcc_param}" 2>/dev/null || true)
    fi
    if [[ -n "${BCC_VAL}" ]]; then
        log_alert "GLOBAL BCC INTERCEPTION ACTIVE (${bcc_param}): ${BOLD}${RED}${BCC_VAL}${RESET}"
        FINDING_GLOBAL_BCC=$((FINDING_GLOBAL_BCC + 1))
    else
        log_ok "Postfix parameter '${bcc_param}' is empty (No global intercept)."
    fi
done

log_sub "Domain & Global Administrator Accounts"
ADMIN_ACCOUNTS=$(run_as_zimbra "zmprov gaaa" || true)
if [[ -n "${ADMIN_ACCOUNTS}" ]]; then
    ADMIN_COUNT=$(echo "${ADMIN_ACCOUNTS}" | grep -v '^[[:space:]]*$' | wc -l)
    log_info "Total Administrator Accounts configured (${ADMIN_COUNT}):"
    while IFS= read -r admin; do
        if [[ -n "${admin}" ]]; then
            log_raw "  ${YELLOW}[ADMIN]${RESET} ${admin}"
        fi
    done <<< "${ADMIN_ACCOUNTS}"

    if [[ ${ADMIN_COUNT} -gt 5 ]]; then
        log_warn "Unusually large number of admin accounts (${ADMIN_COUNT}). Verify all accounts are legitimate!"
        FINDING_ADMIN_ANOMALY=$((FINDING_ADMIN_ANOMALY + 1))
    fi
else
    log_warn "zmprov gaaa returned no administrator accounts or failed."
fi

log_sub "Hidden Mail Auto-Forwarding (zimbraPrefMailForwardingAddress)"
FORWARDINGS_FOUND=0
if [[ -x "${LDAP_SEARCH_BIN}" ]] && [[ -n "${LDAP_PASSWORD}" ]] && [[ -n "${LDAP_MASTER}" ]]; then
    log_info "Querying Zimbra Directory via fast LDAP search..."
    LDAP_RES=$("${LDAP_SEARCH_BIN}" -x -H "${LDAP_MASTER}" -D "uid=zimbra,cn=admins,cn=zimbra" -w "${LDAP_PASSWORD}" \
               "(|(zimbraPrefMailForwardingAddress=*)(zimbraMailCatchAllForwardingAddress=*))" \
               mail zimbraPrefMailForwardingAddress zimbraMailCatchAllForwardingAddress 2>/dev/null || true)

    if [[ -n "${LDAP_RES}" ]]; then
        CURRENT_MAIL=""
        while IFS= read -r line; do
            if echo "${line}" | grep -q "^mail: "; then
                CURRENT_MAIL=$(echo "${line}" | awk '{print $2}')
            elif echo "${line}" | grep -q "^zimbraPrefMailForwardingAddress: "; then
                FWD_DEST=$(echo "${line}" | awk '{print $2}')
                log_alert "FORWARDING RULE: ${BOLD}${CURRENT_MAIL}${RESET} forwards to ${RED}${FWD_DEST}${RESET}"
                FORWARDINGS_FOUND=$((FORWARDINGS_FOUND + 1))
            elif echo "${line}" | grep -q "^zimbraMailCatchAllForwardingAddress: "; then
                FWD_DEST=$(echo "${line}" | awk '{print $2}')
                log_alert "CATCH-ALL FORWARDING: ${BOLD}${CURRENT_MAIL}${RESET} catch-all to ${RED}${FWD_DEST}${RESET}"
                FORWARDINGS_FOUND=$((FORWARDINGS_FOUND + 1))
            fi
        done <<< "${LDAP_RES}"
    fi
else
    log_info "LDAP credentials unavailable directly, falling back to zmprov sample search..."
    SAMPLE_ACCS=$(run_as_zimbra "zmprov -l gaa" | head -n 50 || true)
    while IFS= read -r acc; do
        if [[ -n "${acc}" ]]; then
            FWD_CONF=$(run_as_zimbra "zmprov ga ${acc} zimbraPrefMailForwardingAddress" | grep "^zimbraPrefMailForwardingAddress: " || true)
            if [[ -n "${FWD_CONF}" ]]; then
                DEST=$(echo "${FWD_CONF}" | awk '{print $2}')
                log_alert "FORWARDING RULE: ${BOLD}${acc}${RESET} -> ${RED}${DEST}${RESET}"
                FORWARDINGS_FOUND=$((FORWARDINGS_FOUND + 1))
            fi
        fi
    done <<< "${SAMPLE_ACCS}"
fi

if [[ ${FORWARDINGS_FOUND} -eq 0 ]]; then
    log_ok "No unauthorized mail forwarding rules detected."
else
    FINDING_MAIL_FORWARD=${FORWARDINGS_FOUND}
    log_alert "Total accounts with active mail forwarding detected: ${FORWARDINGS_FOUND}"
fi

log_sub "Hidden Mailbox Sieve Filters Audit (zimbraMailSieveRule)"
log_info "Auditing mailboxes for backdoor Sieve rules (discard/redirect/NDR suppression)..."
SIEVE_RULES_FOUND=0

if [[ -x "${LDAP_SEARCH_BIN}" ]] && [[ -n "${LDAP_PASSWORD}" ]] && [[ -n "${LDAP_MASTER}" ]]; then
    LDAP_SIEVE=$("${LDAP_SEARCH_BIN}" -x -H "${LDAP_MASTER}" -D "uid=zimbra,cn=admins,cn=zimbra" -w "${LDAP_PASSWORD}" \
                 "(zimbraMailSieveRule=*)" mail zimbraMailSieveRule 2>/dev/null || true)

    if [[ -n "${LDAP_SIEVE}" ]]; then
        CURR_USER=""
        while IFS= read -r sline; do
            if echo "${sline}" | grep -q "^mail: "; then
                CURR_USER=$(echo "${sline}" | awk '{print $2}')
            elif echo "${sline}" | grep -qiE '(redirect|discard|reject|keep|fileinto "Trash"|fileinto "Junk")'; then
                log_alert "SUSPICIOUS SIEVE RULE [${BOLD}${CURR_USER}${RESET}]: ${YELLOW}${sline}${RESET}"
                SIEVE_RULES_FOUND=$((SIEVE_RULES_FOUND + 1))
            fi
        done <<< "${LDAP_SIEVE}"
    fi
fi

if [[ ${SIEVE_RULES_FOUND} -eq 0 ]]; then
    log_ok "No malicious Sieve rules (discard/redirect) detected."
else
    FINDING_SIEVE_RULES=${SIEVE_RULES_FOUND}
    log_alert "Total suspicious Sieve rules detected: ${SIEVE_RULES_FOUND}"
fi

# ------------------------------------------------------------------------------
# MODULE 4.1: AUDIT OF SECURITY MISCONFIGURATIONS & HARDENING
# ------------------------------------------------------------------------------
log_header "MODULE 4.1: AUDIT OF SECURITY MISCONFIGURATIONS & HARDENING"

# 1. Admin Console Port (7071) Exposure Check
log_sub "ZCS Admin Console Port 7071 Exposure"
ADMIN_SOCKETS=""
if command -v ss &>/dev/null; then
    ADMIN_SOCKETS=$(ss -tulpn 2>/dev/null | grep ':7071' || true)
elif command -v netstat &>/dev/null; then
    ADMIN_SOCKETS=$(netstat -tulpn 2>/dev/null | grep ':7071' || true)
fi

if [[ -n "${ADMIN_SOCKETS}" ]]; then
    log_info "Active Sockets on Admin Port 7071:\n  ${ADMIN_SOCKETS}"
    if echo "${ADMIN_SOCKETS}" | grep -qE '0\.0\.0\.0:7071|\*:7071|\[::\]:7071'; then
        log_alert "Zimbra Admin Console (port 7071) is EXPOSED on 0.0.0.0 / [::]! Public WAN can access admin login page!"
        FINDING_ADMIN_PORT_EXPOSED=1
    else
        log_ok "Admin Console (port 7071) is bound to restricted/local IP addresses."
    fi
else
    log_info "Port 7071 is not actively listening (Admin console may use custom port or Nginx proxy)."
fi

# 2. Sender Login Mismatch (Anti-Spoofing) Check
log_sub "Internal Sender Spoofing Protection (reject_authenticated_sender_login_mismatch)"
SENDER_RESTRICTIONS=$(run_as_zimbra "zmprov gacf zimbraMtaSmtpdSenderRestrictions" 2>/dev/null || true)
if [[ -z "${SENDER_RESTRICTIONS}" ]]; then
    SENDER_RESTRICTIONS=$("${POSTCONF}" -h smtpd_sender_restrictions 2>/dev/null || true)
fi

log_info "Configured smtpd_sender_restrictions:\n  ${SENDER_RESTRICTIONS}"

if echo "${SENDER_RESTRICTIONS}" | grep -qE 'reject_authenticated_sender_login_mismatch|reject_sender_login_mismatch'; then
    log_ok "Anti-Spoofing is ACTIVE: Authenticated users CANNOT spoof other mailboxes/VIPs."
else
    log_warn "Anti-Spoofing is INACTIVE! 'reject_authenticated_sender_login_mismatch' is missing. A compromised user can forge 'From: ceo@domain.com'!"
    FINDING_SPOOFING_PERMISSIVE=1
fi

# 3. Account Lockout Policy in COS default
log_sub "Brute-Force Protection: Account Lockout Policy (default COS)"
COS_LOCKOUT=$(run_as_zimbra "zmprov gc default zimbraPasswordLockoutEnabled zimbraPasswordLockoutMaxFailures zimbraPasswordLockoutDuration" 2>/dev/null || true)
log_info "Default COS Lockout Settings:\n${COS_LOCKOUT}"

if echo "${COS_LOCKOUT}" | grep -q "zimbraPasswordLockoutEnabled: TRUE"; then
    MAX_FAILS=$(echo "${COS_LOCKOUT}" | grep "zimbraPasswordLockoutMaxFailures:" | awk '{print $2}' || echo "N/A")
    log_ok "Account Lockout is ENABLED in default COS (Max Failures: ${MAX_FAILS})."
else
    log_alert "Account Lockout is DISABLED in default COS! The server is vulnerable to unlimited password spraying/brute-force!"
    FINDING_NO_LOCKOUT=1
fi

# 4. cbpolicyd (Outbound Rate-Limiting) Service Status
log_sub "Outbound Rate-Limiting Service (cbpolicyd / Policyd)"
POLICYD_STATUS=$(run_as_zimbra "zmcontrol status" | grep -i "cbpolicyd" || true)
POLICYD_CONFIG=$(run_as_zimbra "zmprov gacf zimbraCBPolicydBindPort" 2>/dev/null || true)

if [[ -n "${POLICYD_STATUS}" ]] && echo "${POLICYD_STATUS}" | grep -qi "Running"; then
    log_ok "cbpolicyd (Rate Limiting) is Running: Outbound flood throttling is available."
else
    log_warn "cbpolicyd is NOT running or disabled. No rate-limiting in place to throttle bulk spamming from compromised mailboxes."
    FINDING_NO_POLICYD=1
fi

# 5. DNS Security Records Audit (SPF, DMARC, DKIM)
log_sub "DNS Security Records Audit (SPF, DMARC, DKIM)"
PRIMARY_DOMAIN=$(run_as_zimbra "zmprov gad" | grep -vE '^(zimbra\.|admin\.)' | head -n 1 || true)
if [[ -z "${PRIMARY_DOMAIN}" ]]; then
    PRIMARY_DOMAIN=$(hostname -d 2>/dev/null || echo "")
fi

if [[ -n "${PRIMARY_DOMAIN}" ]]; then
    log_info "Auditing DNS records for primary domain: ${BOLD}${PRIMARY_DOMAIN}${RESET}"

    # SPF Check
    SPF_REC=$(dig +short +time=2 +tries=1 TXT "${PRIMARY_DOMAIN}" 2>/dev/null | grep -i 'v=spf1' || true)
    if [[ -n "${SPF_REC}" ]]; then
        log_ok "SPF Record Found: ${SPF_REC}"
    else
        log_alert "MISSING SPF RECORD for ${PRIMARY_DOMAIN}! External servers cannot verify outbound mail legitimacy."
        FINDING_DNS_MISSING=$((FINDING_DNS_MISSING + 1))
    fi

    # DMARC Check
    DMARC_REC=$(dig +short +time=2 +tries=1 TXT "_dmarc.${PRIMARY_DOMAIN}" 2>/dev/null | grep -i 'v=DMARC1' || true)
    if [[ -n "${DMARC_REC}" ]]; then
        if echo "${DMARC_REC}" | grep -qiE 'p=reject|p=quarantine'; then
            log_ok "DMARC Record Enforcing Policy: ${DMARC_REC}"
        else
            log_warn "DMARC Record in Monitoring Mode (p=none): ${DMARC_REC}"
        fi
    else
        log_alert "MISSING DMARC RECORD for _dmarc.${PRIMARY_DOMAIN}! Domain vulnerable to direct spoofing."
        FINDING_DNS_MISSING=$((FINDING_DNS_MISSING + 1))
    fi

    # DKIM Selector Check
    DKIM_STATUS=$(run_as_zimbra "/opt/zimbra/libexec/zmdkimkeyutil -q -d ${PRIMARY_DOMAIN}" 2>/dev/null || true)
    if [[ -n "${DKIM_STATUS}" ]] && echo "${DKIM_STATUS}" | grep -q "DKIM Data"; then
        log_ok "Zimbra DKIM configuration is present in LDAP for ${PRIMARY_DOMAIN}."
    else
        log_warn "No DKIM keys found in LDAP for ${PRIMARY_DOMAIN} via zmdkimkeyutil."
    fi
else
    log_warn "Primary domain name could not be resolved from ZCS."
fi

# ------------------------------------------------------------------------------
# MODULE 4.2: INSTALLED ZIMLETS INVENTORY
# ------------------------------------------------------------------------------
log_sub "Installed Zimlets Inventory"
ZIMLETS=$(run_as_zimbra "zmzimletctl listZimlets" || true)
if [[ -n "${ZIMLETS}" ]]; then
    log_info "Currently deployed Zimlets:"
    while IFS= read -r zimlet; do
        if [[ -n "${zimlet}" ]]; then
            log_raw "  - ${zimlet}"
        fi
    done <<< "${ZIMLETS}"
else
    log_info "No custom zimlets or unable to query zmzimletctl."
fi

# ------------------------------------------------------------------------------
# MODULE 5: WEB LOGS, CVE EXPLOITATION & AUDIT.LOG FORENSICS
# ------------------------------------------------------------------------------
log_header "MODULE 5: WEB LOGS, CVE EXPLOITATION & AUDIT.LOG FORENSICS"

WEB_LOG_PATHS=(
    "/opt/zimbra/log/access_log*"
    "/opt/zimbra/log/mailbox.log*"
    "/opt/zimbra/log/nginx.access.log*"
)

FOUND_WEB_LOGS=()
for pattern in "${WEB_LOG_PATHS[@]}"; do
    for f in ${pattern}; do
        if [[ -f "${f}" ]]; then
            FOUND_WEB_LOGS+=("${f}")
        fi
    done
done

log_info "Identified ${#FOUND_WEB_LOGS[@]} web and mailbox log files."

# Known Exploit Signatures / CVE patterns
SUSPICIOUS_SIGNATURES=(
    "mboximport"
    "/service/admin/soap"
    "/service/soap"
    "Autodiscover/Autodiscover.xml"
    "/public/zmFilterClient.jsp"
    "upload?fmt=raw"
    "clientman"
    "service/extension/backup"
    "zmmailbox -z"
    "eval("
    "cmd.jsp"
    "shell.jsp"
)

log_sub "Scanning Web Logs for CVE Signatures & Exploitation Attempts"
EXPLOIT_HITS_TMP="${TEMP_DIR}/exploit_hits.txt"

for pattern in "${SUSPICIOUS_SIGNATURES[@]}"; do
    for f in "${FOUND_WEB_LOGS[@]}"; do
        if [[ "${f}" == *.gz ]]; then
            gzip -dc "${f}" 2>/dev/null | grep -iF "${pattern}" >> "${EXPLOIT_HITS_TMP}" || true
        else
            grep -iF "${pattern}" "${f}" 2>/dev/null >> "${EXPLOIT_HITS_TMP}" || true
        fi
    done
done

if [[ -s "${EXPLOIT_HITS_TMP}" ]]; then
    TOTAL_HITS=$(wc -l < "${EXPLOIT_HITS_TMP}")
    log_alert "Detected ${TOTAL_HITS} log entries matching high-risk web vulnerability signatures!"
    FINDING_WEB_EXPLOIT=$((FINDING_WEB_EXPLOIT + TOTAL_HITS))
    
    log_info "Sample of high-risk requests (Top 10 unique events):"
    sort "${EXPLOIT_HITS_TMP}" | uniq -c | sort -nr | head -n 10 | while IFS= read -r line; do
        log_raw "  ${RED}${line}${RESET}"
    done

    log_sub "Top Remote IP Addresses Targeting Sensitive Web APIs"
    TOP_EXPLOIT_IPS=$(grep -oP '\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b' "${EXPLOIT_HITS_TMP}" | \
                      grep -vE '^(127\.0\.0\.1|0\.0\.0\.0)' | \
                      sort | uniq -c | sort -nr | head -n 10 || true)
    if [[ -n "${TOP_EXPLOIT_IPS}" ]]; then
        while IFS= read -r line; do
            log_raw "  ${YELLOW}${line}${RESET}"
        done <<< "${TOP_EXPLOIT_IPS}"
    fi
else
    log_ok "No direct hits for known CVE exploit signatures in recent web logs."
fi

# Zimbra Audit Log Forensics (audit.log*)
log_sub "Zimbra Audit Log Forensics (/opt/zimbra/log/audit.log*)"
AUDIT_LOG_FILES=($(find /opt/zimbra/log/ -name "audit.log*" -mtime -30 2>/dev/null || true))
if [[ ${#AUDIT_LOG_FILES[@]} -gt 0 ]]; then
    log_info "Auditing ${#AUDIT_LOG_FILES[@]} audit.log file(s) for high-impact admin & auth events:"

    AUDIT_PWD_TMP="${TEMP_DIR}/audit_pwd.txt"
    AUDIT_GAL_TMP="${TEMP_DIR}/audit_gal.txt"
    AUDIT_AUTH_TMP="${TEMP_DIR}/audit_auth.txt"

    for af in "${AUDIT_LOG_FILES[@]}"; do
        if [[ "${af}" == *.gz ]]; then
            gzip -dc "${af}" 2>/dev/null | grep -i "SetPasswordRequest" >> "${AUDIT_PWD_TMP}" || true
            gzip -dc "${af}" 2>/dev/null | grep -i "SearchGalRequest" >> "${AUDIT_GAL_TMP}" || true
            gzip -dc "${af}" 2>/dev/null | grep -i "AuthRequest" | grep -i "invalid password" >> "${AUDIT_AUTH_TMP}" || true
        else
            grep -i "SetPasswordRequest" "${af}" 2>/dev/null >> "${AUDIT_PWD_TMP}" || true
            grep -i "SearchGalRequest" "${af}" 2>/dev/null >> "${AUDIT_GAL_TMP}" || true
            grep -i "AuthRequest" "${af}" 2>/dev/null | grep -i "invalid password" >> "${AUDIT_AUTH_TMP}" || true
        fi
    done

    # 1. Password Resets
    if [[ -s "${AUDIT_PWD_TMP}" ]]; then
        PWD_COUNT=$(wc -l < "${AUDIT_PWD_TMP}")
        log_alert "SetPasswordRequest events found in audit log (${PWD_COUNT} events):"
        FINDING_AUDIT_EXPLOIT=$((FINDING_AUDIT_EXPLOIT + 1))
        sort "${AUDIT_PWD_TMP}" | uniq -c | sort -nr | head -n 10 | while IFS= read -r pline; do
            log_raw "  ${YELLOW}${pline}${RESET}"
        done
    else
        log_ok "No suspicious SetPasswordRequest events in audit logs."
    fi

    # 2. Address Book Harvesting (SearchGalRequest)
    if [[ -s "${AUDIT_GAL_TMP}" ]]; then
        GAL_COUNT=$(wc -l < "${AUDIT_GAL_TMP}")
        log_warn "Global Address List (GAL) Search queries detected (${GAL_COUNT} queries):"
        sort "${AUDIT_GAL_TMP}" | awk '{print $1, $2, $NF}' | uniq -c | sort -nr | head -n 10 | while IFS= read -r gline; do
            log_raw "  ${CYAN}${gline}${RESET}"
        done
    fi

    # 3. Webmail Auth Failures
    if [[ -s "${AUDIT_AUTH_TMP}" ]]; then
        AUTH_FAILS=$(wc -l < "${AUDIT_AUTH_TMP}")
        log_info "Web/SOAP Auth failures recorded: ${AUTH_FAILS}"
    fi
else
    log_info "No audit.log files located in /opt/zimbra/log/."
fi

# ------------------------------------------------------------------------------
# MODULE 6: PERSISTENCE, MEMORY FORENSICS & WEB SHELL HUNTING
# ------------------------------------------------------------------------------
log_header "MODULE 6: PERSISTENCE, MEMORY FORENSICS & WEB SHELL HUNTING"

log_sub "Memory Forensics: Deleted Executables in RAM (/proc/*/exe)"
DELETED_PROCS=$(ls -l /proc/[0-9]*/exe 2>/dev/null | grep '(deleted)' || true)

if [[ -n "${DELETED_PROCS}" ]]; then
    while IFS= read -r dline; do
        TARGET_PATH=$(echo "${dline}" | awk '{print $NF}' | sed 's/ (deleted)//')
        PID=$(echo "${dline}" | awk '{print $9}' | cut -d/ -f3)
        CMDLINE=$(tr '\0' ' ' < "/proc/${PID}/cmdline" 2>/dev/null || echo "N/A")
        PROC_USER=$(stat -c '%U' "/proc/${PID}" 2>/dev/null || echo "N/A")

        if echo "${TARGET_PATH}" | grep -qE '(/tmp/|/var/tmp/|/dev/shm/|\.sh|\.py|\.pl|\.php|/tmp)'; then
            log_alert "MALICIOUS MEMORY PROCESS (PID ${PID}, User: ${PROC_USER}): ${RED}${TARGET_PATH} (DELETED)${RESET}"
            log_raw "    -> Cmdline: ${BOLD}${CMDLINE}${RESET}"
            FINDING_MEMORY_DELETED=$((FINDING_MEMORY_DELETED + 1))
        elif ! echo "${TARGET_PATH}" | grep -qE '(mysqld|java|slapd|nginx|postfix|systemd|postgres|amavis)'; then
            log_warn "Process running from deleted executable (PID ${PID}, User: ${PROC_USER}): ${TARGET_PATH}"
            log_raw "    -> Cmdline: ${CMDLINE}"
        fi
    done <<< "${DELETED_PROCS}"
fi

if [[ ${FINDING_MEMORY_DELETED} -eq 0 ]]; then
    log_ok "No spambots or hidden payloads detected running from deleted binaries in RAM."
fi

log_sub "Web Shells & Suspicious Executables in Jetty / Mailboxd / Tmp Dirs"
TARGET_SCAN_DIRS=(
    "/opt/zimbra/jetty/webapps"
    "/opt/zimbra/mailboxd/webapps"
    "/opt/zimbra/data/tmp"
    "/tmp"
    "/var/tmp"
    "/dev/shm"
)

SUSPECT_FILES_TMP="${TEMP_DIR}/suspect_files.txt"
touch "${SUSPECT_FILES_TMP}"

for dir in "${TARGET_SCAN_DIRS[@]}"; do
    if [[ -d "${dir}" ]]; then
        log_info "Scanning directory: ${dir} ..."
        find "${dir}" -maxdepth 5 -type f \( -name "*.jsp" -o -name "*.jspx" -o -name "*.php" -o -name "*.sh" -o -name "*.py" -o -name "*.war" \) -mtime -60 2>/dev/null >> "${SUSPECT_FILES_TMP}" || true
    fi
done

if [[ -s "${SUSPECT_FILES_TMP}" ]]; then
    SUSP_COUNT=$(wc -l < "${SUSPECT_FILES_TMP}")
    log_alert "Found ${SUSP_COUNT} recently modified or created scripts/JSPs in web roots & temp dirs!"
    FINDING_SUSPICIOUS_JSP=${SUSP_COUNT}

    while IFS= read -r file; do
        FILE_INFO=$(ls -lh --time-style=long-iso "${file}" 2>/dev/null || ls -l "${file}")
        FILE_MD5=$(md5sum "${file}" 2>/dev/null | awk '{print $1}' || echo "N/A")
        log_raw "  ${RED}[SUSPICIOUS FILE]${RESET} ${FILE_INFO}"
        log_raw "    ${DIM}MD5: ${FILE_MD5}${RESET}"
        
        if grep -q -iE '(Runtime\.getRuntime\(\)\.exec|ProcessBuilder|eval\(|base64_decode|cmd\.exe|/bin/sh|/bin/bash|passthru|shell_exec)' "${file}" 2>/dev/null; then
            log_alert "    -> HIGH CONFIDENCE WEB SHELL SIGNATURE FOUND INSIDE: ${file}"
            FINDING_SUSPICIOUS_JSP=$((FINDING_SUSPICIOUS_JSP + 10))
        fi
    done <<< "${SUSPECT_FILES_TMP}"
else
    log_ok "No newly created or modified .jsp/.sh/.py files found in inspected webapp directories."
fi

log_sub "Scheduled Tasks & Cron Audit (Persistence)"
log_info "Crontab for user 'zimbra':"
ZIMBRA_CRON=$(crontab -u zimbra -l 2>/dev/null || echo "No crontab for zimbra")
while IFS= read -r line; do
    if [[ "${line}" =~ ^# ]] || [[ -z "${line}" ]]; then
        continue
    fi
    log_raw "  [zimbra cron] ${line}"
    if echo "${line}" | grep -q -iE '(curl|wget|nc|bash -i|/tmp|/dev/shm|\.sh|\.py)'; then
        log_alert "  -> Suspicious command in zimbra crontab: ${line}"
        FINDING_PERSISTENCE=$((FINDING_PERSISTENCE + 1))
    fi
done <<< "${ZIMBRA_CRON}"

log_info "Crontab for user 'root':"
ROOT_CRON=$(crontab -u root -l 2>/dev/null || echo "No crontab for root")
while IFS= read -r line; do
    if [[ "${line}" =~ ^# ]] || [[ -z "${line}" ]]; then
        continue
    fi
    log_raw "  [root cron] ${line}"
    if echo "${line}" | grep -q -iE '(curl|wget|nc|bash -i|/tmp|/dev/shm)'; then
        log_alert "  -> Suspicious command in root crontab: ${line}"
        FINDING_PERSISTENCE=$((FINDING_PERSISTENCE + 1))
    fi
done <<< "${ROOT_CRON}"

log_info "Checking /etc/cron.* entries modified within 30 days:"
RECENT_CRONS=$(find /etc/cron* /etc/crontab -type f -mtime -30 2>/dev/null || true)
if [[ -n "${RECENT_CRONS}" ]]; then
    while IFS= read -r f; do
        log_raw "  ${YELLOW}${f}${RESET} ($(stat -c '%y' "${f}" 2>/dev/null || echo 'recently touched'))"
    done <<< "${RECENT_CRONS}"
else
    log_ok "No recently modified system-wide cron files."
fi

log_sub "SSH Authorized Keys Audit"
SSH_KEY_PATHS=(
    "/opt/zimbra/.ssh/authorized_keys"
    "/root/.ssh/authorized_keys"
)
for u_home in /home/*; do
    if [[ -f "${u_home}/.ssh/authorized_keys" ]]; then
        SSH_KEY_PATHS+=("${u_home}/.ssh/authorized_keys")
    fi
done

for kpath in "${SSH_KEY_PATHS[@]}"; do
    if [[ -f "${kpath}" ]]; then
        KEY_COUNT=$(grep -v '^#' "${kpath}" | grep -v '^[[:space:]]*$' | wc -l)
        log_info "SSH Keys in ${kpath} (Count: ${KEY_COUNT}):"
        while IFS= read -r key; do
            if [[ -n "${key}" ]] && ! [[ "${key}" =~ ^# ]]; then
                log_raw "  ${CYAN}${key}${RESET}"
            fi
        done < "${kpath}"
    fi
done

log_sub "Systemd Services & Timers Modified in Last 30 Days"
RECENT_SYSTEMD=$(find /etc/systemd/system/ /usr/lib/systemd/system/ -maxdepth 2 -type f \( -name "*.service" -o -name "*.timer" \) -mtime -30 2>/dev/null || true)
if [[ -n "${RECENT_SYSTEMD}" ]]; then
    while IFS= read -r unit; do
        log_raw "  ${YELLOW}[SYSTEMD UNIT]${RESET} ${unit}"
    done <<< "${RECENT_SYSTEMD}"
else
    log_ok "No recently added custom systemd services or timers."
fi

log_sub "Suspicious Processes Running Under 'zimbra' / System"
log_info "Checking for interactive shells, network utilities or scripting runtimes under 'zimbra':"
SUSP_PROCS=$(ps -ef | grep -E '^zimbra' | grep -iE '(\bnc\b|\bncat\b|\bnetcat\b|\bbash -i\b|\bsh -i\b|\bpython\b|\bpython3\b|\bperl\b|\bphp\b|\bcurl\b|\bwget\b|\bsocat\b|\btclsh\b|\bruby\b)' | grep -v grep || true)
if [[ -n "${SUSP_PROCS}" ]]; then
    log_alert "Suspicious process running under user 'zimbra':"
    while IFS= read -r proc; do
        log_raw "  ${RED}${proc}${RESET}"
    done <<< "${SUSP_PROCS}"
    FINDING_SUSPICIOUS_PROC=$((FINDING_SUSPICIOUS_PROC + 1))
else
    log_ok "No abnormal reverse-shell or networking tools detected running under user 'zimbra'."
fi

log_sub "Shell History Review (.bash_history for root & zimbra)"
for hfile in "/root/.bash_history" "/opt/zimbra/.bash_history"; do
    if [[ -f "${hfile}" ]]; then
        log_info "Last 15 commands in ${hfile}:"
        tail -n 15 "${hfile}" | while IFS= read -r hcmd; do
            log_raw "    ${DIM}${hcmd}${RESET}"
        done
    fi
done

log_sub "Active Network Sockets & Established External Connections"
if command -v ss &>/dev/null; then
    log_info "Listening Ports (TCP/UDP):"
    LISTEN_PORTS=$(ss -tulpn 2>/dev/null | grep -v '127.0.0.1' | head -n 25 || true)
    log_raw "${DIM}${LISTEN_PORTS}${RESET}"

    log_info "Established External Connections (State ESTABLISHED):"
    ESTAB_CONNS=$(ss -tpn state established 2>/dev/null | grep -vE '127\.0\.0\.1|::1' || true)
    if [[ -n "${ESTAB_CONNS}" ]]; then
        while IFS= read -r conn; do
            if echo "${conn}" | grep -q -iE '(bash|sh|nc|python|perl|socat|zimbra)'; then
                log_alert "Suspicious Outbound Connection: ${conn}"
                FINDING_SUSPICIOUS_PROC=$((FINDING_SUSPICIOUS_PROC + 1))
            else
                log_raw "  ${conn}"
            fi
        done <<< "${ESTAB_CONNS}"
    fi
elif command -v netstat &>/dev/null; then
    log_info "Listening Ports via netstat:"
    netstat -tulpn 2>/dev/null | grep -v '127.0.0.1' | head -n 25 || true
fi

# ------------------------------------------------------------------------------
# MODULE 7: EXECUTIVE SUMMARY & RECOMMENDATIONS
# ------------------------------------------------------------------------------
log_header "MODULE 7: INCIDENT SUMMARY & FORENSIC MATRIX"

log_raw "\n${BOLD}======================= TRIAGE SUMMARY MATRIX =======================${RESET}"

# 1. SASL Abuse
if [[ ${FINDING_SASL_ABUSE} -gt 0 ]]; then
    log_raw "  [!] SASL / Account Abuse:      ${RED}DETECTED (High Volume / Suspicious)${RESET}"
else
    log_raw "  [+] SASL / Account Abuse:      ${GREEN}CLEAN / NO IMMEDIATE ANOMALIES${RESET}"
fi

# 2. Open Relay
if [[ ${FINDING_OPEN_RELAY} -gt 0 ]]; then
    log_raw "  [!] Open Relay Status:         ${RED}VULNERABLE (0.0.0.0/0 detected!)${RESET}"
else
    log_raw "  [+] Open Relay Status:         ${GREEN}SECURE (Restricted to MyNetworks)${RESET}"
fi

# 3. Mail Forwarding & Sieve Rules
if [[ ${FINDING_MAIL_FORWARD} -gt 0 ]] || [[ ${FINDING_SIEVE_RULES} -gt 0 ]]; then
    log_raw "  [!] Mail Forwarding / Sieve:   ${RED}DETECTED (Fwd: ${FINDING_MAIL_FORWARD}, Sieve: ${FINDING_SIEVE_RULES})${RESET}"
else
    log_raw "  [+] Mail Forwarding / Sieve:   ${GREEN}CLEAN (No unauthorized forwarding/rules)${RESET}"
fi

# 4. Global BCC Interception
if [[ ${FINDING_GLOBAL_BCC} -gt 0 ]]; then
    log_raw "  [!] Global Postfix BCC:        ${RED}ACTIVE (Global mail interception configured)${RESET}"
else
    log_raw "  [+] Global Postfix BCC:        ${GREEN}CLEAN (No BCC maps found)${RESET}"
fi

# 5. IP RBL Blacklist Status
if [[ ${FINDING_RBL_LISTED} -gt 0 ]]; then
    log_raw "  [!] DNSBL / RBL Reputation:    ${RED}BLACKLISTED (${FINDING_RBL_LISTED} list hits)${RESET}"
else
    log_raw "  [+] DNSBL / RBL Reputation:    ${GREEN}CLEAN (Not listed in major blacklists)${RESET}"
fi

# 6. Web Shells / Malicious JSP
if [[ ${FINDING_SUSPICIOUS_JSP} -gt 0 ]]; then
    log_raw "  [!] Web Shells / JSPs:         ${RED}DETECTED (${FINDING_SUSPICIOUS_JSP} artifacts found)${RESET}"
else
    log_raw "  [+] Web Shells / JSPs:         ${GREEN}CLEAN (No recent JSP anomalies)${RESET}"
fi

# 7. Web Exploit Attempts & Audit Log
if [[ ${FINDING_WEB_EXPLOIT} -gt 0 ]] || [[ ${FINDING_AUDIT_EXPLOIT} -gt 0 ]]; then
    log_raw "  [!] Web & Audit Log Exploits:  ${YELLOW}IDENTIFIED IN LOGS (${FINDING_WEB_EXPLOIT} web hits, ${FINDING_AUDIT_EXPLOIT} audit hits)${RESET}"
else
    log_raw "  [+] Web & Audit Log Exploits:  ${GREEN}CLEAN (No known CVE signatures)${RESET}"
fi

# 8. Memory Forensics (Deleted Binaries)
if [[ ${FINDING_MEMORY_DELETED} -gt 0 ]]; then
    log_raw "  [!] Memory RAM Forensics:      ${RED}MALICIOUS PROCESSES FROM DELETED EXEs (${FINDING_MEMORY_DELETED})${RESET}"
else
    log_raw "  [+] Memory RAM Forensics:      ${GREEN}CLEAN${RESET}"
fi

# 9. Misconfigurations & Hardening Posture
log_raw "\n${BOLD}--- Security Hardening & Posture Matrix ---${RESET}"
if [[ ${FINDING_ADMIN_PORT_EXPOSED} -gt 0 ]]; then
    log_raw "  [!] Admin Port 7071:           ${RED}EXPOSED on 0.0.0.0 (High Risk)${RESET}"
else
    log_raw "  [+] Admin Port 7071:           ${GREEN}RESTRICTED / SAFE${RESET}"
fi

if [[ ${FINDING_SPOOFING_PERMISSIVE} -gt 0 ]]; then
    log_raw "  [!] Internal Anti-Spoofing:    ${YELLOW}DISABLED (reject_authenticated_sender_login_mismatch missing)${RESET}"
else
    log_raw "  [+] Internal Anti-Spoofing:    ${GREEN}ENABLED${RESET}"
fi

if [[ ${FINDING_NO_LOCKOUT} -gt 0 ]]; then
    log_raw "  [!] Account Lockout Policy:    ${RED}DISABLED (Vulnerable to brute-force)${RESET}"
else
    log_raw "  [+] Account Lockout Policy:    ${GREEN}ENABLED in default COS${RESET}"
fi

if [[ ${FINDING_NO_POLICYD} -gt 0 ]]; then
    log_raw "  [!] cbpolicyd Rate Limiting:   ${YELLOW}DISABLED / INACTIVE${RESET}"
else
    log_raw "  [+] cbpolicyd Rate Limiting:   ${GREEN}ACTIVE${RESET}"
fi

if [[ ${FINDING_DNS_MISSING} -gt 0 ]]; then
    log_raw "  [!] DNS Records (SPF/DMARC):   ${RED}INCOMPLETE / MISSING RECORDS${RESET}"
else
    log_raw "  [+] DNS Records (SPF/DMARC):   ${GREEN}VALIDATED${RESET}"
fi

# 10. Persistence & Suspicious Processes
if [[ ${FINDING_SUSPICIOUS_PROC} -gt 0 ]] || [[ ${FINDING_PERSISTENCE} -gt 0 ]]; then
    log_raw "  [!] Persistence / Processes:   ${RED}DETECTED (Inspect cron/processes)${RESET}"
else
    log_raw "  [+] Persistence / Processes:   ${GREEN}CLEAN${RESET}"
fi

log_raw "${BOLD}=====================================================================${RESET}"

log_sub "Actionable Incident Response & Remediation Steps"
log_raw "1. ${BOLD}Isolate & Sanitize Postfix Queue:${RESET} If deferred queue holds spam, hold/delete spam messages ('postsuper -d ALL deferred')."
log_raw "2. ${BOLD}Revoke & Reset Compromised Accounts:${RESET} Reset passwords for high SASL users ('zmprov sp <user> <pwd>') and purge active auth tokens."
log_raw "3. ${BOLD}Remove Malicious Sieve / Forwards:${RESET} Clear unauthorized forwarding attributes ('zimbraPrefMailForwardingAddress') and Sieve rules ('zimbraMailSieveRule')."
log_raw "4. ${BOLD}Restrict Admin Port 7071:${RESET} Ensure port 7071 is only accessible via loopback / VPN / trusted management CIDRs ('zmprov ms <server> zimbraAdminBindAddress 127.0.0.1')."
log_raw "5. ${BOLD}Enable Anti-Spoofing & Lockout:${RESET} Configure 'reject_authenticated_sender_login_mismatch' and enable 'zimbraPasswordLockoutEnabled TRUE' in COS."
log_raw "6. ${BOLD}Delist IP from RBLs:${RESET} Use delisting portals (Spamhaus, Barracuda, SpamCop) once outbound spam is completely halted."
log_raw "7. ${BOLD}Kill In-Memory Droppers:${RESET} Terminate any PIDs associated with deleted binaries in /tmp /dev/shm."
log_raw "8. ${BOLD}Apply Latest ZCS Security Patches:${RESET} Patch ZCS against CVE-2022-27925, CVE-2022-41352, CVE-2024-45519."

log_raw "\n${GREEN}${BOLD}[✔] Full Triage Report successfully saved to:${RESET}"
log_raw "    ${BOLD}${YELLOW}${REPORT_FILE}${RESET}\n"

exit 0
