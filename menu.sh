#!/bin/bash

# Check for root user
if [ "$(id -u)" -ne 0 ]; then
  echo "این اسکریپت باید با دسترسی ریشه (root) اجرا شود."
  echo "لطفاً از دستور 'sudo bash menu.sh' استفاده کنید."
  exit 1
fi

# --- Color Palette (From menu.sh) ---
C_RESET='\033[0m'
C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'
C_BLUE='\033[0;34m'
C_MAGENTA='\033[0;35m'
C_CYAN='\033[0;36m'
C_WHITE='\033[0;37m'
# Bold
B_BLUE='\033[1;34m'
B_MAGENTA='\033[1;35m'
B_CYAN='\033[1;36m'
B_YELLOW='\033[1;33m'

# --- Color Palette (From AS-BBR.sh) ---
readonly AS_RED=$'\033[0;31m'
readonly AS_GREEN=$'\033[0;32m'
readonly AS_YELLOW=$'\033[1;33m'
readonly AS_BLUE=$'\033[0;34m'
readonly AS_CYAN=$'\033[0;36m'
readonly AS_NC=$'\033[0m' # No Color


# --- Header and Banner ---
show_banner() {
    echo -e "${B_BLUE}╔══════════════════════════════════════════════════════════════╗${C_RESET}"
    echo -e "${B_BLUE}║        ${B_CYAN}مدیریت جامع بهینه سازی لینوکس اوبونتو${B_BLUE}         ║${C_RESET}"
    echo -e "${B_BLUE}╠══════════════════════════════════════════════════════════════╣${C_RESET}"
    echo -e "${B_BLUE}║ ${C_WHITE}CREATED BY: AMIR ALI KARBALAEE${B_BLUE}   |   ${C_WHITE}TELEGRAM: T.ME/CY3ER${B_BLUE}      ║${C_RESET}"
    echo -e "${B_BLUE}║ ${C_WHITE}COLLABORATOR: FREAK${B_BLUE}              |   ${C_WHITE}TELEGRAM: T.ME/FREAK_4L${B_BLUE}   ║${C_RESET}"
    echo -e "${B_BLUE}║ ${C_WHITE}COLLABORATOR: IRCF-SPACE${B_BLUE}         |   ${C_WHITE}TELEGRAM: T.ME/IRCFSPACE${B_BLUE}  ║${C_RESET}"
    echo -e "${B_BLUE}╚══════════════════════════════════════════════════════════════╝${C_RESET}"
    echo ""
}

# --- System Status Header (REVISED AND FINAL) ---
show_system_status_header() {
    # Fetch local information
    local hostname=$(hostname 2>/dev/null || echo "N/A")
    local kernel_version=$(uname -r 2>/dev/null || echo "N/A")
    local uptime_str=$(uptime -p 2>/dev/null | sed 's/up //')
    [ -z "$uptime_str" ] && uptime_str="N/A"
    local interface=$(ip route get 8.8.8.8 2>/dev/null | awk --sandbox '/dev/ {print $5; exit}')
    [ -z "$interface" ] && interface="N/A"

    # Fetch DNS servers using the correct method and format it to a single line
    if command -v resolvectl &>/dev/null; then
        local dns_servers=$(resolvectl status | awk '/DNS Servers:/{ $1=""; $2=""; print $0 }' | head -n 1 | xargs)
    else
        local dns_servers=$(grep '^nameserver' /etc/resolv.conf | awk '{print $2}' | tr '\n' ' ')
    fi
	[ -z "$dns_servers" ] && dns_servers="N/A"

    # Set default values for geo info
    local location="N/A"
    local datacenter="N/A"
    local internet_status="${C_RED}✖ Disconnected${C_RESET}"

    # Check internet and fetch GeoIP information using the user-provided working API
    local public_ip=$(curl -s -4 --max-time 5 ip.sb)
    if [ -n "$public_ip" ]; then
        internet_status="${C_GREEN}✔ Connected${C_RESET}"
        
        # Use the new API: ipwhois.app
        local geo_info=$(curl -s --max-time 5 "http://ipwhois.app/json/$public_ip")
        
        # Check if the response is valid JSON and contains our keys
        if [[ -n "$geo_info" && "$geo_info" == *"country"* && "$geo_info" == *"isp"* ]]; then
            if command -v jq &>/dev/null; then
                location=$(echo "$geo_info" | jq -r .country)
                datacenter=$(echo "$geo_info" | jq -r .isp)
            else # Fallback if jq is not installed
                location=$(echo "$geo_info" | grep '"country"' | awk -F'"' '{print $4}')
                datacenter=$(echo "$geo_info" | grep '"isp"' | awk -F'"' '{print $4}')
            fi
        fi
    fi
    [ -z "$location" ] && location="N/A"
    [ -z "$datacenter" ] && datacenter="N/A"

    # Print the box with truncation for long strings to prevent breaking the layout
    printf "${B_BLUE}╔══════════════════════════════════════════════════════════════╗${C_RESET}\n"
    printf "${B_BLUE}║ ${C_WHITE}%-19s: ${C_CYAN}%-35s ${B_BLUE}║${C_RESET}\n" "HOSTNAME" "$hostname"
    printf "${B_BLUE}║ ${C_WHITE}%-19s: ${C_CYAN}%-35s ${B_BLUE}║${C_RESET}\n" "KERNEL VERSION" "$kernel_version"
    printf "${B_BLUE}║ ${C_WHITE}%-19s: ${C_CYAN}%-35s ${B_BLUE}║${C_RESET}\n" "UPTIME" "$uptime_str"
    printf "${B_BLUE}║ ${C_WHITE}%-19s: ${C_CYAN}%-35s ${B_BLUE}║${C_RESET}\n" "DEFAULT INTERFACE" "$interface"
    printf "${B_BLUE}║ ${C_WHITE}%-19s: %-45b ${B_BLUE}║${C_RESET}\n" "INTERNET" "$internet_status"
    printf "${B_BLUE}╟──────────────────────────────────────────────────────────╢${C_RESET}\n"
    printf "${B_BLUE}║ ${C_WHITE}%-19s: ${C_CYAN}%-35.35s ${B_BLUE}║${C_RESET}\n" "DNS SERVERS" "$dns_servers"
    printf "${B_BLUE}║ ${C_WHITE}%-19s: ${C_CYAN}%-35.35s ${B_BLUE}║${C_RESET}\n" "LOCATION" "$location"
    printf "${B_BLUE}║ ${C_WHITE}%-19s: ${C_CYAN}%-35.35s ${B_BLUE}║${C_RESET}\n" "DATACENTER" "$datacenter"
    printf "${B_BLUE}╚══════════════════════════════════════════════════════════════╝${C_RESET}\n"
}


# --- HELPER FUNCTIONS (From menu.sh) ---
backup_file() {
  local file=$1
  if [ -f "$file" ] && [ ! -f "${file}.bak" ]; then
    cp "$file" "${file}.bak"
    echo -e "${C_GREEN}یک نسخه پشتیبان از $file در ${file}.bak برای بازیابی‌های بعدی ایجاد شد.${C_RESET}"
  fi
}

check_service_status() {
    local service_name=$1
    if systemctl is-active --quiet "$service_name"; then
        echo -e "\n${C_GREEN}سرویس $service_name با موفقیت اجرا شد.${C_RESET}"
    else
        echo -e "\n${C_RED}خطا: سرویس $service_name با موفقیت اجرا نشد. لطفاً وضعیت را دستی بررسی کنید: systemctl status $service_name${C_RESET}"
    fi
}

is_valid_ip() {
    local ip=$1
    if [[ "$ip" =~ ^([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}$ || "$ip" =~ ^(([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])) || "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 0
    else
        return 1
    fi
}


# #############################################################################
# --- START OF MERGED SCRIPT: AS-BBR.sh ---
# #############################################################################

readonly LOG_FILE="/var/log/network_optimizer.log"
readonly BACKUP_DIR="/var/backups/network_optimizer"
readonly TARGET_DNS=("9.9.9.9" "149.112.112.112")
readonly MIN_MTU=576
readonly MAX_MTU=9000

declare -g SYSTEM_CPU_CORES
declare -g SYSTEM_TOTAL_RAM
declare -g SYSTEM_OPTIMAL_BACKLOG
declare -g SYSTEM_OPTIMAL_MEM
declare -g PRIMARY_INTERFACE

check_color_support() {
    if [[ -t 1 ]] && [[ "${TERM:-}" != "dumb" ]] && command -v tput >/dev/null 2>&1; then
        local colors
        if colors=$(tput colors 2>/dev/null) && [[ "$colors" -ge 8 ]]; then
            return 0
        fi
    fi
    return 1
}

init_environment() {
    export LC_ALL=C
    export LANG=C
    export DEBIAN_FRONTEND=noninteractive
    export APT_LISTCHANGES_FRONTEND=none

    mkdir -p "$BACKUP_DIR" "$(dirname "$LOG_FILE")" 2>/dev/null
    chmod 700 "$BACKUP_DIR" 2>/dev/null
    : >> "$LOG_FILE"
    chmod 640 "$LOG_FILE" 2>/dev/null

    # --- FIX 1: Removed 'EXIT' from trap to prevent script termination ---
    trap 'handle_interrupt' INT TERM

    PRIMARY_INTERFACE=$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')
    if ! check_color_support; then
        AS_RED="" AS_GREEN="" AS_YELLOW="" AS_BLUE="" AS_CYAN="" AS_NC=""
    fi
}

handle_interrupt() {
    log_message WARN "Script interrupted. Cleaning up..."
    local pids
    pids=$(jobs -p 2>/dev/null)
    if [[ -n "$pids" ]]; then
        echo "$pids" | xargs -r kill -TERM 2>/dev/null || true
        sleep 1
        echo "$pids" | xargs -r kill -KILL 2>/dev/null || true
    fi
    rm -f /tmp/dns_test_$$_* /tmp/conn_test_$$_* 2>/dev/null
    exit 130
}

log_message() {
    local level="$1"
    local message="$2"
    local timestamp color
    printf -v timestamp '%(%Y-%m-%d %H:%M:%S)T' -1
    case "$level" in
        INFO) color="$AS_BLUE" ;;
        WARN) color="$AS_YELLOW" ;;
        ERROR) color="$AS_RED" ;;
        SUCCESS) color="$AS_GREEN" ;;
        *) color="$AS_NC" ;;
    esac
    local log_line="[$timestamp] [$level] $message"
    printf "%s%s%s\n" "$color" "$log_line" "$AS_NC" | tee -a "$LOG_FILE"
}

check_internet_connection() {
    local test_ips=("8.8.8.8" "1.1.1.1" "9.9.9.9")
    local pids=()
    local success=0
    for ip in "${test_ips[@]}"; do
        timeout 3 ping -c1 -W2 "$ip" &>/dev/null &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do
        if wait "$pid" 2>/dev/null; then
            success=1
            break
        fi
    done
    for pid in "${pids[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    return $((1 - success))
}

wait_for_dpkg_lock() {
    local max_wait=300
    local waited=0
    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/apt/lists/lock >/dev/null 2>&1; do
        if [[ "$waited" -ge "$max_wait" ]]; then
            log_message ERROR "Timeout waiting for package manager"
            return 1
        fi
        if [[ $((waited % 30)) -eq 0 ]]; then
            log_message WARN "Package manager locked. Waiting... (${waited}s/${max_wait}s)"
        fi
        sleep 5
        waited=$((waited + 5))
    done
    return 0
}

reset_environment() {
    log_message INFO "Resetting environment after package installation..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get clean 2>/dev/null || true
        rm -f /var/lib/dpkg/lock* /var/lib/apt/lists/lock /var/cache/apt/archives/lock 2>/dev/null || true
    fi
    reset 2>/dev/null || true
    stty sane 2>/dev/null || true
    hash -r 2>/dev/null || true
    [[ -f /etc/environment ]] && source /etc/environment 2>/dev/null || true
    [[ -f ~/.bashrc ]] && source ~/.bashrc 2>/dev/null || true
    export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
    local hanging_procs
    hanging_procs=$(ps aux | grep -E "(apt|dpkg|unattended)" | grep -v grep | awk '{print $2}' 2>/dev/null || true)
    if [[ -n "$hanging_procs" ]]; then
        echo "$hanging_procs" | xargs -r kill -9 2>/dev/null || true
    fi
    sleep 3
    log_message SUCCESS "Environment reset completed."
    if ! test_environment_health; then
        suggest_reconnection
        return 1
    fi
    return 0
}

test_environment_health() {
    log_message INFO "Testing environment health..."
    local test_commands=("ping" "dig" "ethtool" "ip" "sysctl")
    local failed_commands=()
    for cmd in "${test_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            failed_commands+=("$cmd")
        fi
    done
    if ! echo "test" >/dev/null 2>&1; then
        log_message WARN "Terminal output test failed"
        return 1
    fi
    if ! touch "/tmp/netopt_test_$$" 2>/dev/null; then
        log_message WARN "File system access test failed"
        return 1
    fi
    rm -f "/tmp/netopt_test_$$" 2>/dev/null
    if [[ "${#failed_commands[@]}" -gt 0 ]]; then
        log_message WARN "Some commands not found: ${failed_commands[*]}"
        return 1
    fi
    log_message SUCCESS "Environment health check passed."
    return 0
}

suggest_reconnection() {
    printf "\n%s╔════════════════════════════════════════════════════════╗%s\n" "$AS_RED" "$AS_NC"
    printf "%s║                    ATTENTION REQUIRED                 ║%s\n" "$AS_RED" "$AS_NC"
    printf "%s╚════════════════════════════════════════════════════════╝%s\n\n" "$AS_RED" "$AS_NC"
    log_message WARN "Environment issues detected after package installation."
    printf "%sFor optimal performance, please:%s\n\n" "$AS_YELLOW" "$AS_NC"
    printf "%s1. %sPress Ctrl+C to exit this script%s\n" "$AS_CYAN" "$C_WHITE" "$AS_NC"
    printf "%s2. %sReconnect your SSH session%s\n" "$AS_CYAN" "$C_WHITE" "$AS_NC"
    printf "%s3. %sRun the script again%s\n\n" "$AS_CYAN" "$C_WHITE" "$AS_NC"
    printf "%sThis ensures all environment changes take effect properly.%s\n\n" "$AS_YELLOW" "$AS_NC"
    local countdown=30
    while [[ $countdown -gt 0 ]]; do
        printf "\r%sContinuing anyway in %d seconds (Press Ctrl+C to exit)...%s" "$AS_YELLOW" "$countdown" "$AS_NC"
        sleep 1
        ((countdown--))
    done
    printf "\n\n"
    read -erp "Continue with potential issues? (y/N): " choice
    if [[ ! "$choice" =~ ^[Yy]$ ]]; then
        log_message INFO "Script paused for SSH reconnection. Please run again after reconnecting."
        exit 0
    fi
    log_message WARN "Continuing despite environment issues..."
}

install_dependencies() {
    log_message INFO "Checking and installing required dependencies..."
    if ! check_internet_connection; then
        log_message ERROR "No internet connection available."
        return 1
    fi
    local pkg_manager="" update_cmd="" install_cmd=""
    if command -v apt-get >/dev/null 2>&1; then
        pkg_manager="apt-get"
        update_cmd="apt-get update -qq"
        install_cmd="apt-get install -y -qq"
    elif command -v yum >/dev/null 2>&1; then
        pkg_manager="yum"
        update_cmd="yum makecache"
        install_cmd="yum install -y"
    elif command -v dnf >/dev/null 2>&1; then
        pkg_manager="dnf"
        update_cmd="dnf makecache"
        install_cmd="dnf install -y"
    elif command -v pacman >/dev/null 2>&1; then
        pkg_manager="pacman"
        update_cmd="pacman -Sy"
        install_cmd="pacman -S --noconfirm"
    elif command -v zypper >/dev/null 2>&1; then
        pkg_manager="zypper"
        update_cmd="zypper refresh"
        install_cmd="zypper install -y"
    else
        log_message ERROR "No supported package manager found"
        return 1
    fi
    log_message INFO "Detected package manager: $pkg_manager"
    if [[ "$pkg_manager" == "apt-get" ]]; then
        if ! wait_for_dpkg_lock; then
            log_message ERROR "Could not acquire package lock"
            return 1
        fi
        pkill -9 apt-get apt dpkg 2>/dev/null || true
        rm -f /var/lib/dpkg/lock* /var/lib/apt/lists/lock /var/cache/apt/archives/lock 2>/dev/null
        dpkg --configure -a 2>/dev/null || true
    fi
    log_message INFO "Updating package lists..."
    if ! timeout 180 $update_cmd 2>/dev/null; then
        log_message WARN "Package update failed, continuing anyway..."
    fi
    local deps=()
    case "$pkg_manager" in
        "apt-get") deps=("ethtool" "net-tools" "dnsutils" "mtr-tiny" "iperf3" "jq") ;;
        "yum"|"dnf") deps=("ethtool" "net-tools" "bind-utils" "mtr" "iperf3" "jq") ;;
        "pacman") deps=("ethtool" "net-tools" "bind-tools" "mtr" "iperf3" "jq") ;;
        "zypper") deps=("ethtool" "net-tools" "bind-utils" "mtr" "iperf3" "jq") ;;
    esac
    local missing_deps=()
    for dep in "${deps[@]}"; do
        if ! command -v "${dep%%-*}" >/dev/null 2>&1; then
            missing_deps+=("$dep")
        fi
    done
    if [[ "${#missing_deps[@]}" -gt 0 ]]; then
        log_message WARN "Installing: ${missing_deps[*]}"
        local install_options=""
        if [[ "$pkg_manager" == "apt-get" ]]; then
            install_options="-o DPkg::Options::=--force-confold -o DPkg::Options::=--force-confdef -o APT::Install-Recommends=false"
        fi
        printf "%sInstalling packages (timeout: 10min)...%s\n" "$AS_YELLOW" "$AS_NC"
        if timeout 600 $install_cmd $install_options "${missing_deps[@]}" 2>/dev/null; then
            log_message SUCCESS "Dependencies installed successfully."
            if ! reset_environment; then
                return 1
            fi
        else
            local exit_code=$?
            if [[ "$exit_code" -eq 124 ]]; then
                log_message ERROR "Installation timed out"
            else
                log_message WARN "Some packages failed to install, continuing..."
            fi
            return 1
        fi
    else
        log_message INFO "All dependencies are already installed."
    fi
    return 0
}

create_backup() {
    local file_path="$1"
    local backup_name
    printf -v backup_name '%s.bak.%(%s)T' "$(basename "$file_path")" -1
    if cp -f "$file_path" "$BACKUP_DIR/$backup_name" 2>/dev/null; then
        log_message INFO "Backup created: $backup_name"
        printf '%s\n' "$BACKUP_DIR/$backup_name"
        return 0
    else
        log_message ERROR "Backup failed for $file_path"
        return 1
    fi
}

restore_backup() {
    local original_file="$1"
    local backup_file="$2"
    if cp -f "$backup_file" "$original_file" 2>/dev/null; then
        log_message SUCCESS "Restored $original_file from backup"
        return 0
    else
        log_message ERROR "Failed to restore from backup"
        return 1
    fi
}

show_header_as_bbr() {
    clear
    log_message INFO "Displaying header information."
    local hostname kernel_version uptime
    hostname=$(hostname 2>/dev/null || echo "Unknown")
    kernel_version=$(uname -r 2>/dev/null || echo "Unknown")
    uptime=$(uptime -p 2>/dev/null || echo "Unknown")
    printf "\n%s===========================================%s\n" "$AS_BLUE" "$AS_NC"
    printf "" "$AS_CYAN" "$AS_NC"
    printf "" "$AS_CYAN" "$AS_NC"
    printf "%s===========================================%s\n" "$AS_BLUE" "$AS_NC"
    printf "%sHostname: %s%s\n" "$AS_GREEN" "$hostname" "$AS_NC"
    printf "%sKernel Version: %s%s\n" "$AS_GREEN" "$kernel_version" "$AS_NC"
    printf "%sUptime: %s%s\n" "$AS_GREEN" "$uptime" "$AS_NC"
    printf "%sDefault Interface: %s%s\n" "$AS_GREEN" "${PRIMARY_INTERFACE:-"Not detected"}" "$AS_NC"
    if check_internet_connection >/dev/null 2>&1; then
        printf "%sInternet: Connected%s\n" "$AS_GREEN" "$AS_NC"
    else
        printf "%sInternet: Disconnected%s\n" "$AS_RED" "$AS_NC"
    fi
    printf "%s===========================================%s\n\n" "$AS_BLUE" "$AS_NC"
}

fix_etc_hosts() {
    local host_path="${1:-/etc/hosts}"
    local hostname_cached
    log_message INFO "Starting to fix the hosts file..."
    hostname_cached=$(hostname 2>/dev/null || echo "localhost")
    local backup_path
    if ! backup_path=$(create_backup "$host_path"); then
        log_message ERROR "Failed to create backup of hosts file."
        return 1
    fi
    if lsattr "$host_path" 2>/dev/null | grep -q 'i'; then
        log_message WARN "File $host_path is immutable. Making it mutable..."
        if ! chattr -i "$host_path" 2>/dev/null; then
            log_message ERROR "Failed to remove immutable attribute."
            return 1
        fi
    fi
    if [[ ! -w "$host_path" ]]; then
        log_message ERROR "Cannot write to $host_path. Check permissions."
        return 1
    fi
    if ! grep -q "$hostname_cached" "$host_path" 2>/dev/null; then
        local hostname_entry="127.0.1.1 $hostname_cached"
        if printf '%s\n' "$hostname_entry" >> "$host_path"; then
            log_message SUCCESS "Hostname entry added to hosts file."
        else
            log_message ERROR "Failed to add hostname entry."
            restore_backup "$host_path" "$backup_path"
            return 1
        fi
    else
        log_message INFO "Hostname entry already present."
    fi
    return 0
}

fix_dns() {
    local dns_file="/etc/resolv.conf"
    log_message INFO "Starting to update DNS configuration..."
    local backup_path
    if ! backup_path=$(create_backup "$dns_file"); then
        log_message ERROR "Failed to create backup of DNS configuration."
        return 1
    fi
    if lsattr "$dns_file" 2>/dev/null | grep -q 'i'; then
        log_message WARN "File $dns_file is immutable. Making it mutable..."
        if ! chattr -i "$dns_file" 2>/dev/null; then
            log_message ERROR "Failed to remove immutable attribute."
            return 1
        fi
    fi
    if [[ ! -w "$dns_file" ]]; then
        log_message ERROR "Cannot write to $dns_file. Check permissions."
        return 1
    fi
    local current_time
    printf -v current_time '%(%Y-%m-%d %H:%M:%S)T' -1
    local dns1="${TARGET_DNS[0]}"
    local dns2="${TARGET_DNS[1]}"
    if cat > "$dns_file" << EOF
# Generated by network optimizer on $current_time
nameserver $dns1
nameserver $dns2
options rotate timeout:1 attempts:3
EOF
    then
        log_message SUCCESS "DNS configuration updated successfully."
        if dig +short +timeout=2 google.com @"$dns1" >/dev/null 2>&1; then
            log_message SUCCESS "DNS resolution verified."
        else
            log_message WARN "DNS verification failed, but continuing..."
        fi
    else
        log_message ERROR "Failed to update DNS configuration."
        restore_backup "$dns_file" "$backup_path"
        return 1
    fi
    return 0
}

custom_dns_config() {
    log_message INFO "Starting custom DNS configuration..."
    read -erp "Enter primary DNS server IP: " dns1
    read -erp "Enter secondary DNS server IP: " dns2
    if ! [[ "$dns1" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        log_message ERROR "Invalid primary DNS IP format"
        return 1
    fi
    if ! [[ "$dns2" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        log_message ERROR "Invalid secondary DNS IP format"
        return 1
    fi
    log_message INFO "Applying custom DNS: $dns1, $dns2"
    custom_fix_dns "$dns1" "$dns2"
}

custom_fix_dns() {
    local custom_dns1="$1"
    local custom_dns2="$2"
    local dns_file="/etc/resolv.conf"
    log_message INFO "Updating DNS configuration with custom servers..."
    local backup_path
    if ! backup_path=$(create_backup "$dns_file"); then
        log_message ERROR "Failed to create backup of DNS configuration."
        return 1
    fi
    if lsattr "$dns_file" 2>/dev/null | grep -q 'i'; then
        log_message WARN "File $dns_file is immutable. Making it mutable..."
        if ! chattr -i "$dns_file" 2>/dev/null; then
            log_message ERROR "Failed to remove immutable attribute."
            return 1
        fi
    fi
    if [[ ! -w "$dns_file" ]]; then
        log_message ERROR "Cannot write to $dns_file. Check permissions."
        return 1
    fi
    local current_time
    printf -v current_time '%(%Y-%m-%d %H:%M:%S)T' -1
    if cat > "$dns_file" << EOF
# Generated by network optimizer on $current_time
# Custom DNS configuration
nameserver $custom_dns1
nameserver $custom_dns2
options rotate timeout:1 attempts:3
EOF
    then
        log_message SUCCESS "Custom DNS configuration applied successfully."
        log_message INFO "Primary DNS: $custom_dns1"
        log_message INFO "Secondary DNS: $custom_dns2"
        if dig +short +timeout=2 google.com @"$custom_dns1" >/dev/null 2>&1; then
            log_message SUCCESS "Custom DNS resolution verified."
        else
            log_message WARN "Custom DNS verification failed, but continuing..."
        fi
    else
        log_message ERROR "Failed to update DNS configuration."
        restore_backup "$dns_file" "$backup_path"
        return 1
    fi
    return 0
}

gather_system_info() {
    log_message INFO "Gathering system information..."
    local cpu_cores total_ram
    cpu_cores=$(nproc 2>/dev/null | head -1)
    cpu_cores=$(printf '%s' "$cpu_cores" | tr -cd '0-9')
    if [[ -z "$cpu_cores" ]] || ! [[ "$cpu_cores" =~ ^[0-9]+$ ]] || [[ "$cpu_cores" -eq 0 ]]; then
        log_message WARN "CPU detection failed. Using fallback value."
        cpu_cores=1
    fi
    total_ram=$(awk '/MemTotal:/ {print int($2/1024); exit}' /proc/meminfo 2>/dev/null | head -1)
    total_ram=$(printf '%s' "$total_ram" | tr -cd '0-9')
    if [[ -z "$total_ram" ]] || ! [[ "$total_ram" =~ ^[0-9]+$ ]] || [[ "$total_ram" -eq 0 ]]; then
        log_message WARN "RAM detection failed. Using fallback value."
        total_ram=1024
    fi
    log_message INFO "System Information:"
    log_message INFO "CPU cores: $cpu_cores"
    log_message INFO "Total RAM: ${total_ram}MB"
    local optimal_backlog optimal_mem
    optimal_backlog=$((50000 * cpu_cores))
    optimal_mem=$((total_ram * 1024 / 4))
    SYSTEM_CPU_CORES=$cpu_cores
    SYSTEM_TOTAL_RAM=$total_ram
    SYSTEM_OPTIMAL_BACKLOG=$optimal_backlog
    SYSTEM_OPTIMAL_MEM=$optimal_mem
    return 0
}

optimize_network() {
    local interface="$1"
    if [[ -z "$interface" ]]; then
        log_message ERROR "No interface specified."
        return 1
    fi
    log_message INFO "Optimizing network interface $interface..."
    if [[ -z "$SYSTEM_OPTIMAL_BACKLOG" ]]; then
        gather_system_info
    fi
    local max_mem=$SYSTEM_OPTIMAL_MEM
    if [[ "$max_mem" -gt 16777216 ]]; then
        max_mem=16777216
    fi
    log_message INFO "Configuring NIC offload settings..."
    {
        ethtool -K "$interface" tso on gso on gro on 2>/dev/null
        ethtool -G "$interface" rx 4096 tx 4096 2>/dev/null
    } || true
    if ethtool -k "$interface" 2>/dev/null | grep -q "rx-udp-gro-forwarding"; then
        log_message INFO "Enabling UDP GRO forwarding..."
        ethtool -K "$interface" rx-udp-gro-forwarding on rx-gro-list off 2>/dev/null || true
    fi
    local sysctl_conf="/etc/sysctl.d/99-network-optimizer.conf"
    log_message INFO "Creating network optimization configuration..."
    if [[ -f "$sysctl_conf" ]]; then
        create_backup "$sysctl_conf"
    fi
    local current_time
    printf -v current_time '%(%Y-%m-%d %H:%M:%S)T' -1
    cat > "$sysctl_conf" << EOF
# Network optimizations added on $current_time
net.core.netdev_max_backlog = $SYSTEM_OPTIMAL_BACKLOG
net.core.rmem_max = $max_mem
net.core.wmem_max = $max_mem
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.default_qdisc = fq
net.ipv4.tcp_rmem = 4096 87380 $max_mem
net.ipv4.tcp_wmem = 4096 65536 $max_mem
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_max_syn_backlog = $SYSTEM_OPTIMAL_BACKLOG
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
EOF
    if sysctl -p "$sysctl_conf" &>/dev/null; then
        log_message SUCCESS "Network optimizations applied successfully."
    else
        log_message ERROR "Failed to apply network optimizations."
        return 1
    fi
    local current_cc
    current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    if [[ "$current_cc" == "bbr" ]]; then
        log_message SUCCESS "TCP BBR congestion control enabled."
    else
        log_message WARN "TCP BBR not available. Falling back to cubic."
        sysctl -w net.ipv4.tcp_congestion_control=cubic &>/dev/null
    fi
    if ip link set dev "$interface" txqueuelen 10000 2>/dev/null; then
        log_message SUCCESS "Increased TX queue length for $interface."
    else
        log_message WARN "Failed to set TX queue length."
    fi
    return 0
}

find_best_mtu() {
    local interface="$1"
    local target_ip="8.8.8.8"
    if [[ -z "$interface" ]]; then
        log_message ERROR "No interface specified for MTU optimization."
        return 1
    fi
    log_message INFO "Starting MTU optimization for interface $interface..."
    local current_mtu
    if ! current_mtu=$(cat "/sys/class/net/$interface/mtu" 2>/dev/null); then
        current_mtu=$(ip link show "$interface" 2>/dev/null | sed -n 's/.*mtu \([0-9]*\).*/\1/p')
    fi
    if [[ -z "$current_mtu" ]] || [[ ! "$current_mtu" =~ ^[0-9]+$ ]]; then
        log_message ERROR "Could not determine current MTU for $interface"
        return 1
    fi
    log_message INFO "Current MTU: $current_mtu"
    if ! ip addr show "$interface" 2>/dev/null | grep -q "inet "; then
        log_message ERROR "Interface $interface is not configured with an IP address"
        return 1
    fi
    log_message INFO "Testing basic connectivity..."
    if ! ping -c 1 -W 3 "$target_ip" &>/dev/null; then
        log_message ERROR "No internet connectivity. Cannot perform MTU optimization."
        return 1
    fi
    test_mtu_size() {
        local size="$1"
        local payload_size=$((size - 28))
        if [[ "$payload_size" -lt 0 ]]; then return 1; fi
        local attempts=0; local success=0
        while [[ "$attempts" -lt 3 ]] && [[ "$success" -eq 0 ]]; do
            if ping -M do -s "$payload_size" -c 1 -W 2 -i 0.2 "$target_ip" &>/dev/null; then
                success=1; break
            fi
            ((attempts++)); sleep 0.1
        done
        return $((1 - success))
    }
    local optimal_mtu="$current_mtu"
    local found_working=0
    log_message INFO "Testing common MTU sizes..."
    local common_mtus=(1500 1492 1480 1472 1468 1460 1450 1440 1430 1420 1400 1380 1360 1340 1300 1280 1200 1024)
    for size in "${common_mtus[@]}"; do
        if [[ "$size" -le "$current_mtu" ]]; then
            printf "  Testing MTU %d... " "$size"
            if test_mtu_size "$size"; then
                printf "${AS_GREEN}✓${AS_NC}\n"
                optimal_mtu="$size"; found_working=1; break
            else
                printf "${AS_RED}✗${AS_NC}\n"
            fi
        fi
    done
    if [[ "$found_working" -eq 0 ]]; then
        log_message INFO "Common MTUs failed. Performing binary search..."
        local min_mtu=576; local max_mtu="$current_mtu"; local test_mtu
        while [[ "$min_mtu" -le "$max_mtu" ]]; do
            test_mtu=$(( (min_mtu + max_mtu) / 2 ))
            printf "  Testing MTU %d... " "$test_mtu"
            if test_mtu_size "$test_mtu"; then
                printf "${AS_GREEN}✓${AS_NC}\n"
                optimal_mtu="$test_mtu"; min_mtu=$((test_mtu + 1)); found_working=1
            else
                printf "${AS_RED}✗${AS_NC}\n"
                max_mtu=$((test_mtu - 1))
            fi
        done
    fi
    if [[ "$found_working" -eq 1 ]]; then
        if [[ "$optimal_mtu" -ne "$current_mtu" ]]; then
            log_message INFO "Applying optimal MTU: $optimal_mtu"
            if ip link set "$interface" mtu "$optimal_mtu" 2>/dev/null; then
                log_message SUCCESS "MTU successfully set to $optimal_mtu"
                local new_mtu
                new_mtu=$(cat "/sys/class/net/$interface/mtu" 2>/dev/null)
                if [[ "$new_mtu" = "$optimal_mtu" ]]; then
                    log_message SUCCESS "MTU change verified: $new_mtu"
                else
                    log_message WARN "MTU verification failed. Reported: $new_mtu"
                fi
            else
                log_message ERROR "Failed to set MTU to $optimal_mtu"
                return 1
            fi
        else
            log_message INFO "Current MTU ($current_mtu) is already optimal"
        fi
    else
        log_message WARN "Could not find working MTU. Keeping current MTU: $current_mtu"
    fi
    return 0
}

restore_defaults() {
    log_message INFO "Restoring original settings..."
    read -erp "Are you sure you want to restore default settings? (y/N): " choice
    if [[ ! "$choice" =~ ^[Yy]$ ]]; then
        log_message INFO "Restoration cancelled."
        return 0
    fi
    local sysctl_backup hosts_backup resolv_backup
    sysctl_backup=$(find "$BACKUP_DIR" -name "99-network-optimizer.conf.bak*" -type f 2>/dev/null | sort -V | tail -n1)
    hosts_backup=$(find "$BACKUP_DIR" -name "hosts.bak*" -type f 2>/dev/null | sort -V | tail -n1)
    resolv_backup=$(find "$BACKUP_DIR" -name "resolv.conf.bak*" -type f 2>/dev/null | sort -V | tail -n1)
    if [[ -f "$sysctl_backup" ]]; then
        if cp -f "$sysctl_backup" "/etc/sysctl.d/99-network-optimizer.conf" 2>/dev/null; then
            sysctl -p "/etc/sysctl.d/99-network-optimizer.conf" &>/dev/null
            log_message SUCCESS "Restored sysctl settings"
        else
            log_message ERROR "Failed to restore sysctl settings"
        fi
    else
        log_message WARN "No sysctl backup found. Removing optimization file..."
        rm -f "/etc/sysctl.d/99-network-optimizer.conf"
        log_message INFO "Reset to system defaults"
    fi
    if [[ -f "$hosts_backup" ]]; then
        if cp -f "$hosts_backup" "/etc/hosts" 2>/dev/null; then
            log_message SUCCESS "Restored hosts file"
        else
            log_message ERROR "Failed to restore hosts file"
        fi
    else
        log_message WARN "No hosts backup found"
    fi
    if [[ -f "$resolv_backup" ]]; then
        if cp -f "$resolv_backup" "/etc/resolv.conf" 2>/dev/null; then
            log_message SUCCESS "Restored DNS settings"
        else
            log_message ERROR "Failed to restore DNS settings"
        fi
    else
        log_message WARN "No DNS backup found"
    fi
    log_message SUCCESS "Original settings restored successfully."
    log_message INFO "A system reboot is recommended for changes to take effect."
    read -erp "Would you like to reboot now? (y/N): " choice
    if [[ "$choice" =~ ^[Yy]$ ]]; then
        reboot
    fi
    return 0
}

run_diagnostics() {
    local interface="${PRIMARY_INTERFACE:-$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')}"
    clear
    printf "\n%s╔════════════════════════════════════════╗%s\n" "$AS_CYAN" "$AS_NC"
    printf "%s║           Network Diagnostics         ║%s\n" "$AS_CYAN" "$AS_NC"
    printf "%s╚════════════════════════════════════════╝%s\n\n" "$AS_CYAN" "$AS_NC"
    printf "%s┌─ [1] Network Interface Status%s\n" "$AS_YELLOW" "$AS_NC"; printf "%s│%s\n" "$AS_YELLOW" "$AS_NC"
    if [[ -n "$interface" ]]; then
        printf "%s│%s Interface: %s%s%s\n" "$AS_YELLOW" "$AS_NC" "$AS_GREEN" "$interface" "$AS_NC"
        local ip_info speed duplex link_status mtu
        ip_info=$(ip -4 addr show "$interface" 2>/dev/null | grep "inet " | awk '{print $2}' | head -1)
        if [[ -n "$ip_info" ]]; then
            printf "%s│%s IPv4 Address: %s%s%s\n" "$AS_YELLOW" "$AS_NC" "$AS_GREEN" "$ip_info" "$AS_NC"
        else
            printf "%s│%s IPv4 Address: %sNot configured%s\n" "$AS_YELLOW" "$AS_NC" "$AS_RED" "$AS_NC"
        fi
        mtu=$(cat "/sys/class/net/$interface/mtu" 2>/dev/null || echo "Unknown")
        printf "%s│%s MTU: %s%s%s\n" "$AS_YELLOW" "$AS_NC" "$AS_GREEN" "$mtu" "$AS_NC"
        if command -v ethtool &>/dev/null; then
            local ethtool_output; ethtool_output=$(ethtool "$interface" 2>/dev/null)
            if [[ -n "$ethtool_output" ]]; then
                speed=$(echo "$ethtool_output" | grep "Speed:" | awk '{print $2}' | head -1)
                duplex=$(echo "$ethtool_output" | grep "Duplex:" | awk '{print $2}' | head -1)
                link_status=$(echo "$ethtool_output" | grep "Link detected:" | awk '{print $3}' | head -1)
                [[ "$speed" = "Unknown!" ]] && speed="Unknown"; [[ "$duplex" = "Unknown!" ]] && duplex="Unknown"
                printf "%s│%s Speed: %s%s%s\n" "$AS_YELLOW" "$AS_NC" "$AS_GREEN" "${speed:-Unknown}" "$AS_NC"
                printf "%s│%s Duplex: %s%s%s\n" "$AS_YELLOW" "$AS_NC" "$AS_GREEN" "${duplex:-Unknown}" "$AS_NC"
                printf "%s│%s Link: %s%s%s\n" "$AS_YELLOW" "$AS_NC" "$AS_GREEN" "${link_status:-Unknown}" "$AS_NC"
            fi
        fi
        local rx_bytes tx_bytes
        if [[ -f "/sys/class/net/$interface/statistics/rx_bytes" ]]; then
            rx_bytes=$(cat "/sys/class/net/$interface/statistics/rx_bytes" 2>/dev/null)
            tx_bytes=$(cat "/sys/class/net/$interface/statistics/tx_bytes" 2>/dev/null)
            if [[ -n "$rx_bytes" ]] && [[ -n "$tx_bytes" ]]; then
                rx_human=$(numfmt --to=iec --suffix=B "$rx_bytes" 2>/dev/null || echo "$rx_bytes bytes")
                tx_human=$(numfmt --to=iec --suffix=B "$tx_bytes" 2>/dev/null || echo "$tx_bytes bytes")
                printf "%s│%s RX: %s%s%s, TX: %s%s%s\n" "$AS_YELLOW" "$AS_NC" "$AS_GREEN" "$rx_human" "$AS_NC" "$AS_GREEN" "$tx_human" "$AS_NC"
            fi
        fi
    else
        printf "%s│%s %sNo interface detected%s\n" "$AS_YELLOW" "$AS_NC" "$AS_RED" "$AS_NC"
    fi
    printf "%s└─%s\n\n" "$AS_YELLOW" "$AS_NC"
    printf "%s┌─ [2] DNS Resolution Test%s\n" "$AS_YELLOW" "$AS_NC"; printf "%s│%s\n" "$AS_YELLOW" "$AS_NC"
    local dns_pids=()
    for dns in "${TARGET_DNS[@]}"; do
        { local result="FAIL"; local time_taken="N/A"; if command -v dig &>/dev/null; then local dig_output; dig_output=$(dig +short +time=2 +tries=1 google.com @"$dns" 2>/dev/null); if [[ -n "$dig_output" ]] && [[ "$dig_output" != *"connection timed out"* ]]; then result="OK"; local query_time; query_time=$(dig +noall +stats google.com @"$dns" 2>/dev/null | grep "Query time:" | awk '{print $4}'); if [[ -n "$query_time" ]]; then time_taken="${query_time}ms"; fi; fi; else if nslookup google.com "$dns" &>/dev/null; then result="OK"; fi; fi; echo "$dns|$result|$time_taken" > "/tmp/dns_test_$$_$dns"; } &
        dns_pids+=($!)
    done
    for pid in "${dns_pids[@]}"; do wait "$pid" 2>/dev/null || true; done
    for dns in "${TARGET_DNS[@]}"; do if [[ -f "/tmp/dns_test_$$_$dns" ]]; then local dns_result; IFS='|' read -r dns_ip status query_time < "/tmp/dns_test_$$_$dns"; if [[ "$status" = "OK" ]]; then printf "%s│%s %s%s%s (%s) - %s%s%s" "$AS_YELLOW" "$AS_NC" "$AS_GREEN" "✓" "$AS_NC" "$dns_ip" "$AS_GREEN" "$status" "$AS_NC"; if [[ "$query_time" != "N/A" ]]; then printf " [%s]" "$query_time"; fi; printf "\n"; else printf "%s│%s %s%s%s (%s) - %s%s%s\n" "$AS_YELLOW" "$AS_NC" "$AS_RED" "✗" "$AS_NC" "$dns_ip" "$AS_RED" "$status" "$AS_NC"; fi; rm -f "/tmp/dns_test_$$_$dns"; fi; done
    printf "%s└─%s\n\n" "$AS_YELLOW" "$AS_NC"
    printf "%s┌─ [3] Internet Connectivity%s\n" "$AS_YELLOW" "$AS_NC"; printf "%s│%s\n" "$AS_YELLOW" "$AS_NC"
    local test_hosts=("google.com" "github.com" "cloudflare.com" "quad9.net"); local conn_pids=()
    for host in "${test_hosts[@]}"; do { local result="FAIL"; local rtt="N/A"; local ping_output; ping_output=$(ping -c 1 -W 3 "$host" 2>/dev/null); if [[ $? -eq 0 ]]; then result="OK"; rtt=$(echo "$ping_output" | grep "time=" | sed 's/.*time=\([0-9.]*\).*/\1/'); if [[ -n "$rtt" ]]; then rtt="${rtt}ms"; fi; fi; echo "$host|$result|$rtt" > "/tmp/conn_test_$$_${host//\./_}"; } & conn_pids+=($!); done
    for pid in "${conn_pids[@]}"; do wait "$pid" 2>/dev/null || true; done
    for host in "${test_hosts[@]}"; do local temp_file="/tmp/conn_test_$$_${host//\./_}"; if [[ -f "$temp_file" ]]; then local conn_result; IFS='|' read -r hostname status rtt < "$temp_file"; if [[ "$status" = "OK" ]]; then printf "%s│%s %s%s%s %-15s - %s%s%s" "$AS_YELLOW" "$AS_NC" "$AS_GREEN" "✓" "$AS_NC" "$hostname" "$AS_GREEN" "$status" "$AS_NC"; if [[ "$rtt" != "N/A" ]]; then printf " [%s]" "$rtt"; fi; printf "\n"; else printf "%s│%s %s%s%s %-15s - %s%s%s\n" "$AS_YELLOW" "$AS_NC" "$AS_RED" "✗" "$AS_NC" "$hostname" "$AS_RED" "$status" "$AS_NC"; fi; rm -f "$temp_file"; fi; done
    printf "%s└─%s\n\n" "$AS_YELLOW" "$AS_NC"
    printf "%s┌─ [4] Network Configuration%s\n" "$AS_YELLOW" "$AS_NC"; printf "%s│%s\n" "$AS_YELLOW" "$AS_NC"
    local current_cc available_cc; current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "Unknown"); available_cc=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo "Unknown")
    printf "%s│%s TCP Congestion Control: %s%s%s\n" "$AS_YELLOW" "$AS_NC" "$AS_GREEN" "$current_cc" "$AS_NC"
    printf "%s│%s Available Algorithms: %s%s%s\n" "$AS_YELLOW" "$AS_NC" "$AS_CYAN" "$available_cc" "$AS_NC"
    local default_route gateway; default_route=$(ip route show default 2>/dev/null | head -1)
    if [[ -n "$default_route" ]]; then gateway=$(echo "$default_route" | awk '{print $3}'); printf "%s│%s Default Gateway: %s%s%s\n" "$AS_YELLOW" "$AS_NC" "$AS_GREEN" "${gateway:-Unknown}" "$AS_NC"; fi
    printf "%s└─%s\n\n" "$AS_YELLOW" "$AS_NC"
    printf "%s┌─ [5] Performance Test%s\n" "$AS_YELLOW" "$AS_NC"; printf "%s│%s\n" "$AS_YELLOW" "$AS_NC"
    printf "%s│%s Testing packet loss and latency...\n" "$AS_YELLOW" "$AS_NC"
    local ping_result; ping_result=$(ping -c 10 -i 0.2 8.8.8.8 2>/dev/null)
    if [[ $? -eq 0 ]]; then
        local packet_loss rtt_avg; packet_loss=$(echo "$ping_result" | grep "packet loss" | awk '{print $(NF-1)}'); rtt_avg=$(echo "$ping_result" | tail -1 | awk -F'/' '{print $5}')
        printf "%s│%s Packet Loss: %s%s%s\n" "$AS_YELLOW" "$AS_NC" "$AS_GREEN" "${packet_loss:-Unknown}" "$AS_NC"
        printf "%s│%s Average RTT: %s%s%sms\n" "$AS_YELLOW" "$AS_NC" "$AS_GREEN" "${rtt_avg:-Unknown}" "$AS_NC"
    else
        printf "%s│%s %sPerformance test failed%s\n" "$AS_YELLOW" "$AS_NC" "$AS_RED" "$AS_NC"
    fi
    printf "%s└─%s\n\n" "$AS_YELLOW" "$AS_NC"
    printf "%s%s" "$AS_CYAN" "Press any key to continue..."
    read -n 1 -s -r
    printf "%s\n" "$AS_NC"
}

intelligent_optimize() {
    log_message INFO "Starting intelligent network optimization..."
    if ! check_internet_connection; then
        log_message ERROR "No internet connection available. Cannot apply optimizations."
        return 1
    fi
    local interface="${PRIMARY_INTERFACE}"
    if [[ -z "$interface" ]]; then
        log_message ERROR "Could not detect primary network interface."
        return 1
    fi
    if ! install_dependencies; then
        log_message ERROR "Failed to install required dependencies."
        return 1
    fi
    log_message INFO "Applying optimizations to interface $interface..."
    if ! fix_etc_hosts; then log_message ERROR "Failed to optimize hosts file."; return 1; fi
    if ! fix_dns; then log_message ERROR "Failed to optimize DNS settings."; return 1; fi
    if ! gather_system_info; then log_message ERROR "Failed to gather system information."; return 1; fi
    if ! optimize_network "$interface"; then log_message ERROR "Failed to apply network optimizations."; return 1; fi
    if ! find_best_mtu "$interface"; then log_message ERROR "Failed to optimize MTU."; return 1; fi
    log_message SUCCESS "All optimizations completed successfully."
    log_message INFO "A system reboot is recommended for changes to take effect."
    read -erp "Would you like to reboot now? (y/N): " choice
    if [[ "$choice" =~ ^[Yy]$ ]]; then reboot; fi
    return 0
}

show_advanced_menu_as_bbr() {
    while true; do
        show_header_as_bbr
        log_message INFO "Displaying advanced menu."
        printf "%sگزینه های پیشرفته:%s\n" "$AS_CYAN" "$AS_NC"
        printf "%s۱. بهینه سازی دستی MTU%s\n" "$AS_GREEN" "$AS_NC"
        printf "%s۲. تنظیمات سفارشی DNS%s\n" "$AS_GREEN" "$AS_NC"
        printf "%s۳. تنظیمات کنترل ازدحام TCP%s\n" "$AS_GREEN" "$AS_NC"
        printf "%s۴. تنظیمات رابط شبکه%s\n" "$AS_GREEN" "$AS_NC"
        printf "%s۵. مشاهده بهینه سازی های فعلی%s\n" "$AS_GREEN" "$AS_NC"
        printf "%s0. بازگشت به منوی قبلی%s\n\n" "$AS_GREEN" "$AS_NC"
        read -erp "لطفا گزینه خود را وارد کنید (0-5): " choice
        case "$choice" in
            1) find_best_mtu "$PRIMARY_INTERFACE" ;;
            2) custom_dns_config ;;
            3)
                local available
                available=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null)
                printf "Available congestion control algorithms: %s\n" "$available"
                read -erp "Enter desired algorithm [bbr]: " algo
                algo=${algo:-bbr}
                sysctl -w net.ipv4.tcp_congestion_control="$algo" 2>/dev/null
                ;;
            4)
                local interfaces
                interfaces=$(ip -br link show 2>/dev/null | awk '{print $1}' | grep -v "lo")
                printf "Available interfaces:\n%s\n" "$interfaces"
                read -erp "Enter interface to optimize: " iface
                optimize_network "$iface"
                ;;
            5)
                printf "%sCurrent Network Optimizations:%s\n" "$AS_CYAN" "$AS_NC"
                if [[ -f "/etc/sysctl.d/99-network-optimizer.conf" ]]; then
                    cat "/etc/sysctl.d/99-network-optimizer.conf"
                else
                    printf "%sNo network optimizations applied yet.%s\n" "$AS_YELLOW" "$AS_NC"
                fi
                ;;
            0) return ;;
            *)
                log_message WARN "Invalid option selected."
                printf "\n%sInvalid option. Please enter a number between 0 and 5.%s\n" "$AS_RED" "$AS_NC"
                ;;
        esac
        if [[ "$choice" != "0" ]]; then
            printf "\n%sPress any key to continue...%s" "$AS_CYAN" "$AS_NC"
            read -n 1 -s -r
            printf "\n"
        fi
    done
}

show_as_bbr_menu() {
    while true; do
        show_header_as_bbr
        log_message INFO "Displaying main menu."
        printf "%sگزینه های موجود:%s\n" "$AS_CYAN" "$AS_NC"
        printf "%s۱.اعمال بهینه سازی هوشمند%s\n" "$AS_GREEN" "$AS_NC"
        printf "%s۲.اجرای ابزار تشخیص شبکه%s\n" "$AS_GREEN" "$AS_NC"
        printf "%s۳.گزینه های پیشرفته%s\n" "$AS_GREEN" "$AS_NC"
        printf "%s۴.بازگردانی به تنظیمات اولیه%s\n" "$AS_GREEN" "$AS_NC"
        printf "%s0.بازگشت به منوی اصلی%s\n\n" "$AS_GREEN" "$AS_NC"
        read -erp "لطفا گزینه خود را وارد کنید (0-4): " choice
        case "$choice" in
            1)
                intelligent_optimize
                printf "\n%sبرای ادامه کلیدی را فشار دهید...%s" "$AS_CYAN" "$AS_NC"
                read -n 1 -s -r
                printf "\n"
                ;;
            2) run_diagnostics ;;
            3) show_advanced_menu_as_bbr ;;
            4)
                restore_defaults
                printf "\n%sبرای ادامه کلیدی را فشار دهید...%s" "$AS_CYAN" "$AS_NC"
                read -n 1 -s -r
                printf "\n"
                ;;
            0)
                log_message INFO "Returning to main menu."
                printf "\n%sدر حال بازگشت...%s\n" "$AS_YELLOW" "$AS_NC"
                return
                ;;
            *)
                log_message WARN "گزینه نامعتبر است."
                printf "\n%sگزینه نامعتبر است. لطفا عددی بین 0 تا 4 وارد کنید.%s\n" "$AS_RED" "$AS_NC"
                sleep 2
                ;;
        esac
    done
}

run_as_bbr_optimization() {
    init_environment
    show_as_bbr_menu
}

# ###########################################################################
# --- END OF MERGED SCRIPT: AS-BBR.sh ---
# ###########################################################################

manage_dns() {
    clear
    local IRAN_DNS_LIST=(
        "10.70.95.150" "10.70.95.162" "45.90.30.180" "45.90.28.180" "178.22.122.100" "185.51.200.2"
        "185.81.8.252" "86.105.252.193" "185.43.135.1" "46.16.216.25" "10.202.10.10" "185.78.66.4"
        "86.54.11.100" "86.54.11.200" "185.55.225.25" "185.55.226.26" "217.218.155.155" "217.218.127.127"
    )
    local GLOBAL_DNS_LIST=(
        "8.8.8.8" "8.8.4.4" "1.1.1.1" "1.0.0.1" "9.9.9.9" "149.112.112.112" "208.67.222.222" "208.67.220.220"
        "8.26.56.26" "8.20.247.20" "77.88.8.8" "77.88.8.1" "64.6.64.6" "64.6.65.6" "4.2.2.4" "4.2.2.3"
        "94.140.14.14" "94.140.15.15" "84.200.69.80" "84.200.70.40" "80.80.80.80" "80.80.81.81"
    )
    local resolved_conf="/etc/systemd/resolved.conf"
    apply_dns_settings() {
        local dns1=$1
        local dns2=$2
        echo -e "\n${B_YELLOW}در حال تنظیم DNS های زیر به صورت دائمی...${C_RESET}"
        echo -e "DNS اصلی: ${C_GREEN}$dns1${C_RESET}"
        echo -e "DNS کمکی: ${C_GREEN}$dns2${C_RESET}"
        backup_file $resolved_conf
        touch $resolved_conf
        sed -i -E 's/^#?DNS=.*//' $resolved_conf
        sed -i -E 's/^#?FallbackDNS=.*//' $resolved_conf
        sed -i -E 's/^#?\[Resolve\]/\[Resolve\]/' $resolved_conf
        grep -v '^[[:space:]]*$' $resolved_conf > "${resolved_conf}.tmp" && mv "${resolved_conf}.tmp" $resolved_conf
        if grep -q "\[Resolve\]" $resolved_conf; then
            sed -i "/\[Resolve\]/a DNS=${dns1}" $resolved_conf
            if [ -n "$dns2" ]; then
                sed -i "/DNS=${dns1}/a FallbackDNS=${dns2}" $resolved_conf
            fi
        else
            echo "" >> $resolved_conf
            echo "[Resolve]" >> $resolved_conf
            echo "DNS=${dns1}" >> $resolved_conf
            if [ -n "$dns2" ]; then
                echo "FallbackDNS=${dns2}" >> $resolved_conf
            fi
        fi
        systemctl restart systemd-resolved
        check_service_status "systemd-resolved"
    }
    find_and_set_best_dns() {
        local -n dns_list=$1
        local list_name=$2
        echo -e "\n${B_CYAN}در حال تست پینگ از لیست DNS های ${list_name}... (همیشه دو DNS با کمترین پینگ انتخاب می‌شوند)${C_RESET}"
        echo "این عملیات ممکن است کمی طول بکشد."
        local results=""
        for ip in "${dns_list[@]}"; do
            local ping_avg=$(ping -c 3 -W 1 -q "$ip" | tail -1 | awk -F '/' '{print $5}' 2>/dev/null)
            if [ -n "$ping_avg" ]; then
                echo -e "پینگ ${C_YELLOW}$ip${C_RESET}: ${C_GREEN}${ping_avg} ms${C_RESET}"
                results+="${ping_avg} ${ip}\n"
            else
                echo -e "پینگ ${C_YELLOW}$ip${C_RESET}: ${C_RED}ناموفق${C_RESET}"
            fi
        done
        if [ -z "$results" ]; then
            echo -e "\n${C_RED}هیچکدام از DNS ها پاسخ ندادند. لطفاً اتصال اینترنت را بررسی کنید.${C_RESET}"
            return
        fi
        mapfile -t best_ips < <(echo -e "${results}" | grep . | sort -n | awk '{print $2}')
        if [ "${#best_ips[@]}" -lt 2 ]; then
            echo -e "\n${C_RED}خطا: حداقل دو DNS قابل دسترس برای تنظیم یافت نشد.${C_RESET}"
            return
        fi
        local best_dns_1="${best_ips[0]}"
        local best_dns_2="${best_ips[1]}"
        apply_dns_settings "$best_dns_1" "$best_dns_2"
    }
    while true; do
        clear
        echo -e "${B_CYAN}--- مدیریت و یافتن بهترین DNS ---${C_RESET}\n"
        echo -e "${C_YELLOW}1)${C_WHITE} یافتن و تنظیم بهترین DNS ایران"
        echo -e "${C_YELLOW}2)${C_WHITE} یافتن و تنظیم بهترین DNS جهانی"
        echo -e "${C_YELLOW}3)${C_WHITE} مشاهده DNS فعال سیستم (پیشنهادی)"
        echo -e "${C_YELLOW}4)${C_WHITE} ویرایش فایل کانفیگ DNS دائمی"
        echo -e "${C_YELLOW}5)${C_WHITE} بازگشت به منوی بهینه‌سازی"
        echo -e "${B_BLUE}-----------------------------------${C_RESET}"
        read -ep "$(echo -e "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}")" choice
        case $choice in
            1) find_and_set_best_dns IRAN_DNS_LIST "ایران"; break ;;
            2) find_and_set_best_dns GLOBAL_DNS_LIST "جهانی"; break ;;
            3) clear; echo -e "${B_CYAN}--- وضعیت DNS فعال سیستم ---${C_RESET}"; resolvectl status; echo -e "${B_BLUE}-----------------------------------${C_RESET}"; break ;;
            4) nano $resolved_conf; break ;;
            5) return ;;
            *) echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}"; sleep 1 ;;
        esac
    done
    read -n 1 -s -r -p "برای ادامه، کلیدی را فشار دهید..."
}

manage_ipv6() {
    clear
    local sysctl_conf="/etc/sysctl.conf"
    echo -e "${B_CYAN}--- فعال/غیرفعال کردن IPV6 ---${C_RESET}\n"
    echo -e "${C_YELLOW}1)${C_WHITE} غیرفعال کردن IPV6"
    echo -e "${C_YELLOW}2)${C_WHITE} فعال کردن IPV6 (حذف تنظیمات)"
    echo -e "${C_YELLOW}3)${C_WHITE} بازگشت به منوی امنیت"
    echo -e "${B_BLUE}-----------------------------------${C_RESET}"
    read -ep "$(echo -e "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}")" choice
    case $choice in
        1)
            read -ep "$(echo -e "${C_YELLOW}**هشدار:** این کار ممکن است اتصال شما را دچار اختلال کند. آیا مطمئن هستید؟ (y/n): ${C_RESET}")" confirm
            if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
                echo -e "\n${C_RED}عملیات لغو شد.${C_RESET}"
            else
                backup_file $sysctl_conf
                touch $sysctl_conf
                sed -i '/net.ipv6.conf.all.disable_ipv6/d' $sysctl_conf
                sed -i '/net.ipv6.conf.default.disable_ipv6/d' $sysctl_conf
                sed -i '/net.ipv6.conf.lo.disable_ipv6/d' $sysctl_conf
                echo "net.ipv6.conf.all.disable_ipv6 = 1" >> $sysctl_conf
                echo "net.ipv6.conf.default.disable_ipv6 = 1" >> $sysctl_conf
                echo "net.ipv6.conf.lo.disable_ipv6 = 1" >> $sysctl_conf
                sysctl -p
                echo -e "\n${C_GREEN}IPV6 با موفقیت غیرفعال شد.${C_RESET}"
            fi
            ;;
        2)
            backup_file $sysctl_conf
            touch $sysctl_conf
            if [ -f "$sysctl_conf" ]; then
                sed -i '/net.ipv6.conf.all.disable_ipv6/d' $sysctl_conf
                sed -i '/net.ipv6.conf.default.disable_ipv6/d' $sysctl_conf
                sed -i '/net.ipv6.conf.lo.disable_ipv6/d' $sysctl_conf
                sysctl -p
                echo -e "\n${C_GREEN}تنظیمات غیرفعال‌سازی IPV6 حذف شد.${C_RESET}"
            else
                echo -e "\n${C_YELLOW}فایل sysctl.conf یافت نشد.${C_RESET}"
            fi
            ;;
        3) return ;;
        *) echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}" ;;
    esac
    read -n 1 -s -r -p "برای ادامه، کلیدی را فشار دهید..."
}

manage_ssh_root() {
  clear
  local sshd_config="/etc/ssh/sshd_config"
  echo -e "${B_CYAN}--- مدیریت ورود کاربر روت ---${C_RESET}\n"
  echo -e "${C_YELLOW}1)${C_WHITE} فعال کردن ورود روت با رمز عبور"
  echo -e "${C_YELLOW}2)${C_WHITE} غیرفعال کردن ورود روت با رمز عبور"
  echo -e "${C_YELLOW}3)${C_WHITE} بازگشت به منوی امنیت"
  echo -e "${B_BLUE}-----------------------------------${C_RESET}"
  read -ep "$(echo -e "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}")" choice
  case $choice in
    1)
      echo -e "\n${C_YELLOW}**هشدار:** فعال کردن ورود روت با رمز عبور، یک ریسک امنیتی است.${C_RESET}"
      read -ep "$(echo -e "${B_MAGENTA}آیا برای ادامه مطمئن هستید؟ (y/n) ${C_RESET}")" confirm
      if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
          echo -e "\n${C_RED}عملیات لغو شد.${C_RESET}"
      else
          echo -e "\nابتدا باید برای کاربر root یک رمز عبور تنظیم کنید."
          passwd root
          backup_file $sshd_config
          if grep -q "^#*PermitRootLogin" "$sshd_config"; then
            sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' "$sshd_config"
          else
            echo "PermitRootLogin yes" >> "$sshd_config"
          fi
          systemctl restart sshd
          check_service_status "sshd"
      fi
      ;;
    2)
      backup_file $sshd_config
      if grep -q "^#*PermitRootLogin" "$sshd_config"; then
        sed -i 's/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/' "$sshd_config"
      else
        echo "PermitRootLogin prohibit-password" >> "$sshd_config"
      fi
      systemctl restart sshd
      check_service_status "sshd"
      ;;
    3) return ;;
    *) echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}" ;;
  esac
  read -n 1 -s -r -p "برای ادامه، کلیدی را فشار دهید..."
}

install_core_packages() {
  clear
  echo -e "${B_CYAN}--- آپدیت و نصب پکیج های لازم ---${C_RESET}\n"
  echo "در حال به‌روزرسانی سیستم و نصب بسته‌های ضروری (curl, socat, wget)..."
  apt update && apt upgrade -y
  apt install curl socat wget -y
  echo -e "\n${C_GREEN}سیستم با موفقیت به‌روزرسانی و بسته‌ها نصب شدند.${C_RESET}"
  read -n 1 -s -r -p "برای ادامه، کلیدی را فشار دهید..."
}

manage_reboot_cron() {
  clear
  echo -e "${B_CYAN}--- مدیریت ریبوت خودکار سرور ---${C_RESET}\n"
  echo -e "${C_YELLOW}1)${C_WHITE} افزودن Cron Job برای ریبوت هر 12 ساعت"
  echo -e "${C_YELLOW}2)${C_WHITE} حذف Cron Job ریبوت خودکار"
  echo -e "${C_YELLOW}3)${C_WHITE} بازگشت به منوی امنیت"
  echo -e "${B_BLUE}-----------------------------------${C_RESET}"
  read -ep "$(echo -e "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}")" choice
  case $choice in
    1)
      (crontab -l 2>/dev/null | grep -v "/sbin/shutdown -r now"; echo "0 */12 * * * /sbin/shutdown -r now") | crontab -
      echo -e "\n${C_GREEN}ریبوت خودکار هر 12 ساعت یک‌بار تنظیم شد.${C_RESET}"
      ;;
    2)
      crontab -l | grep -v "/sbin/shutdown -r now" | crontab -
      echo -e "\n${C_GREEN}ریبوت خودکار حذف شد.${C_RESET}"
      ;;
    3) return ;;
    *) echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}" ;;
  esac
  read -n 1 -s -r -p "برای ادامه، کلیدی را فشار دهید..."
}

manage_tc_script() {
  clear
  echo -e "${B_CYAN}--- بهینه سازی سرعت (TC) ---${C_RESET}\n"
  echo -e "${C_YELLOW}1)${C_WHITE} نصب و تست اسکریپت بهینه‌سازی TC"
  echo -e "${C_YELLOW}2)${C_WHITE} حذف اسکریپت بهینه‌سازی TC"
  echo -e "${C_YELLOW}3)${C_WHITE} بازگشت به منوی بهینه‌سازی"
  echo -e "${B_BLUE}-----------------------------------${C_RESET}"
  read -ep "$(echo -e "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}")" choice
  SCRIPT_PATH="/usr/local/bin/tc_optimize.sh"
  case $choice in
    1)
      cat > $SCRIPT_PATH << 'EOF'
#!/bin/bash
INTERFACE=$(ip route get 8.8.8.8 | awk '/dev/ {print $5; exit}')
tc qdisc del dev $INTERFACE root 2>/dev/null
tc qdisc del dev $INTERFACE ingress 2>/dev/null
ip link set dev $INTERFACE mtu 1500 2>/dev/null
echo 1000 > /sys/class/net/$INTERFACE/tx_queue_len 2>/dev/null
if tc qdisc add dev $INTERFACE root cake bandwidth 1000mbit rtt 20ms nat dual-dsthost 2>/dev/null; then
    echo "$(date): CAKE optimization complete" >> /var/log/tc_smart.log
    echo 'CAKE optimization complete'
elif tc qdisc add dev $INTERFACE root fq_codel limit 10240 flows 1024 target 5ms interval 100ms 2>/dev/null; then
    echo "$(date): FQ_CoDel optimization complete" >> /var/log/tc_smart.log
    echo 'FQ_CoDel optimization complete'
elif tc qdisc add dev $INTERFACE root handle 1: htb default 11 2>/dev/null && \
     tc class add dev $INTERFACE parent 1: classid 1:1 htb rate 1000mbit ceil 1000mbit 2>/dev/null && \
     tc class add dev $INTERFACE parent 1:1 classid 1:11 htb rate 1000mbit ceil 1000mbit 2>/dev/null && \
     tc qdisc add dev $INTERFACE parent 1:11 netem delay 1ms loss 0.005% duplicate 0.05% reorder 0.5% 2>/dev/null; then
    echo "$(date): HTB+Netem optimization complete" >> /var/log/tc_smart.log
    echo 'HTB+Netem optimization complete'
else
    tc qdisc add dev $INTERFACE root netem delay 1ms loss 0.005% duplicate 0.05% reorder 0.5% 2>/dev/null
    echo "$(date): Fallback Netem optimization complete" >> /var/log/tc_smart.log
    echo 'Fallback Netem optimization complete'
fi
tc qdisc show dev $INTERFACE | grep -E 'cake|fq_codel|htb|netem'
echo -e "\033[38;5;208mCY3ER\033[0m"
EOF
      chmod +x $SCRIPT_PATH
      (crontab -l 2>/dev/null | grep -v "$SCRIPT_PATH"; echo "@reboot sleep 30 && $SCRIPT_PATH") | crontab -
      echo -e "\n${C_GREEN}اسکریپت بهینه‌سازی TC با موفقیت نصب شد.${C_RESET}"
      echo -e "\n${C_YELLOW}--- اجرای خودکار تست برای تایید نصب ---${C_RESET}"
      bash $SCRIPT_PATH && echo "تست موفق بود." && tail -5 /var/log/tc_smart.log
      ;;
    2)
      rm -f $SCRIPT_PATH
      crontab -l | grep -v "$SCRIPT_PATH" | crontab -
      echo -e "\n${C_GREEN}اسکریپت بهینه‌سازی TC و Cron Job مربوطه حذف شدند.${C_RESET}"
      ;;
    3) return ;;
    *) echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}" ;;
  esac
  read -n 1 -s -r -p "برای ادامه، کلیدی را فشار دهید..."
}

manage_sysctl() {
  clear
  local sysctl_conf="/etc/sysctl.conf"
  echo -e "${B_CYAN}--- بهینه سازی هسته (SYSCTL) ---${C_RESET}\n"
  echo -e "${C_YELLOW}1)${C_WHITE} اعمال کانفیگ کامل BBR (پیشنهادی)"
  echo -e "${C_YELLOW}2)${C_WHITE} اعمال کانفیگ Cubic/Codel (اینترنت ناپایدار)"
  echo -e "${C_YELLOW}3)${C_WHITE} بازگردانی به فایل پشتیبان"
  echo -e "${C_YELLOW}4)${C_WHITE} بازگشت به منوی بهینه‌سازی"
  echo -e "${B_BLUE}-----------------------------------${C_RESET}"
  read -ep "$(echo -e "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}")" choice
  case $choice in
    1)
      backup_file $sysctl_conf
      cat > $sysctl_conf << 'EOF'
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 16777216
net.core.wmem_default = 16777216
net.core.netdev_max_backlog = 30000
net.core.netdev_budget = 600
net.core.netdev_budget_usecs = 8000
net.core.somaxconn = 32768
net.core.dev_weight = 128
net.core.dev_weight_rx_bias = 1
net.core.dev_weight_tx_bias = 1
net.core.bpf_jit_enable = 1
net.core.bpf_jit_kallsyms = 1
net.core.bpf_jit_harden = 0
net.core.flow_limit_cpu_bitmap = 255
net.core.flow_limit_table_len = 8192
net.ipv4.tcp_rmem = 8192 131072 134217728
net.ipv4.tcp_wmem = 8192 131072 134217728
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_fastopen_blackhole_timeout_sec = 0
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 3
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_tw_reuse_delay = 100
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_dsack = 1
net.ipv4.tcp_fack = 1
net.ipv4.tcp_ecn = 2
net.ipv4.tcp_syn_retries = 3
net.ipv4.tcp_synack_retries = 3
net.ipv4.tcp_retries1 = 3
net.ipv4.tcp_retries2 = 8
net.ipv4.tcp_orphan_retries = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.tcp_mtu_probing = 2
net.ipv4.tcp_base_mss = 1024
net.ipv4.tcp_min_snd_mss = 48
net.ipv4.tcp_mtu_probe_floor = 48
net.ipv4.tcp_probe_threshold = 8
net.ipv4.tcp_probe_interval = 600
net.ipv4.tcp_adv_win_scale = 2
net.ipv4.tcp_app_win = 31
net.ipv4.tcp_tso_win_divisor = 8
net.ipv4.tcp_limit_output_bytes = 1048576
net.ipv4.tcp_challenge_ack_limit = 1000
net.ipv4.tcp_autocorking = 1
net.ipv4.tcp_min_tso_segs = 8
net.ipv4.tcp_tso_rtt_log = 9
net.ipv4.tcp_pacing_ss_ratio = 120
net.ipv4.tcp_pacing_ca_ratio = 110
net.ipv4.tcp_reordering = 3
net.ipv4.tcp_max_reordering = 32
net.ipv4.tcp_recovery = 1
net.ipv4.tcp_early_retrans = 3
net.ipv4.tcp_frto = 2
net.ipv4.tcp_thin_linear_timeouts = 1
net.ipv4.tcp_min_rtt_wlen = 300
net.ipv4.tcp_comp_sack_delay_ns = 500000
net.ipv4.tcp_comp_sack_slack_ns = 50000
net.ipv4.tcp_comp_sack_nr = 44
net.ipv4.tcp_notsent_lowat = 131072
net.ipv4.tcp_invalid_ratelimit = 250
net.ipv4.tcp_reflect_tos = 1
net.ipv4.tcp_abort_on_overflow = 0
net.ipv4.tcp_fwmark_accept = 1
net.ipv4.tcp_l3mdev_accept = 1
net.ipv4.tcp_migrate_req = 1
net.ipv4.tcp_syn_linear_timeouts = 4
net.ipv4.tcp_shrink_window = 0
net.ipv4.tcp_workaround_signed_windows = 0
net.ipv4.ip_forward = 1
net.ipv4.ip_default_ttl = 64
net.ipv4.ip_no_pmtu_disc = 0
net.ipv4.ip_forward_use_pmtu = 1
net.ipv4.fwmark_reflect = 1
net.ipv4.fib_multipath_use_neigh = 1
net.ipv4.fib_multipath_hash_policy = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.log_martians = 0
net.ipv4.conf.default.log_martians = 0
net.ipv4.icmp_echo_ignore_all = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.icmp_ratelimit = 100
net.ipv4.icmp_ratemask = 6168
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_tcp_timeout_established = 432000
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 60
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 60
net.netfilter.nf_conntrack_tcp_timeout_syn_sent = 60
net.netfilter.nf_conntrack_tcp_timeout_syn_recv = 30
net.netfilter.nf_conntrack_udp_timeout = 30
net.netfilter.nf_conntrack_udp_timeout_stream = 120
net.netfilter.nf_conntrack_icmp_timeout = 30
net.netfilter.nf_conntrack_generic_timeout = 120
net.netfilter.nf_conntrack_buckets = 262144
net.netfilter.nf_conntrack_checksum = 0
net.netfilter.nf_conntrack_tcp_be_liberal = 1
net.netfilter.nf_conntrack_tcp_loose = 1
vm.swappiness = 10
vm.dirty_ratio = 10
vm.dirty_background_ratio = 5
vm.dirty_expire_centisecs = 1500
vm.dirty_writeback_centisecs = 500
vm.vfs_cache_pressure = 50
vm.min_free_kbytes = 131072
vm.page_cluster = 0
vm.overcommit_memory = 1
vm.overcommit_ratio = 80
vm.max_map_count = 262144
vm.mmap_min_addr = 65536
vm.zone_reclaim_mode = 0
vm.stat_interval = 1
fs.file-max = 2097152
fs.nr_open = 2097152
fs.inotify.max_user_watches = 524288
fs.inotify.max_user_instances = 256
fs.inotify.max_queued_events = 32768
fs.aio-max-nr = 1048576
fs.pipe-max-size = 4194304
net.core.default_qdisc = fq
net.unix.max_dgram_qlen = 512
EOF
      sysctl -p
      echo -e "\n${C_GREEN}کانفیگ کامل Sysctl با موفقیت اعمال شد.${C_RESET}"
      ;;
    2)
      backup_file $sysctl_conf
      touch $sysctl_conf
      sed -i '/net.core.default_qdisc/d' $sysctl_conf
      sed -i '/net.ipv4.tcp_congestion_control/d' $sysctl_conf
      echo "net.core.default_qdisc=fq_codel" >> $sysctl_conf
      echo "net.ipv4.tcp_congestion_control=cubic" >> $sysctl_conf
      sysctl -p
      echo -e "\n${C_GREEN}کانفیگ Cubic/Codel با موفقیت اعمال شد.${C_RESET}"
      ;;
    3)
      if [ -f "${sysctl_conf}.bak" ]; then
          mv "${sysctl_conf}.bak" "$sysctl_conf"
          sysctl -p
          echo -e "\n${C_GREEN}فایل sysctl.conf به نسخه پشتیبان بازگردانده شد.${C_RESET}"
      else
          echo -e "\n${C_RED}هیچ فایل پشتیبانی (${sysctl_conf}.bak) یافت نشد!${C_RESET}"
      fi
      ;;
    4) return ;;
    *) echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}" ;;
  esac
  read -n 1 -s -r -p "برای ادامه، کلیدی را فشار دهید..."
}

manage_mirror_test() {
    clear
    echo -e "${B_CYAN}--- یافتن و تنظیم سریع‌ترین مخزن APT ---${C_RESET}\n"
    if command -v lsb_release &> /dev/null; then
        UBUNTU_CODENAME=$(lsb_release -cs)
    else
        UBUNTU_CODENAME="jammy"
        echo -e "${C_YELLOW}دستور lsb_release یافت نشد، از کدنام پیش‌فرض 'jammy' استفاده می‌شود.${C_RESET}"
    fi
    MIRRORS=(
        "https://mirrors.pardisco.co/ubuntu/" "http://mirror.aminidc.com/ubuntu/" "http://mirror.faraso.org/ubuntu/"
        "https://ir.ubuntu.sindad.cloud/ubuntu/" "https://ubuntu-mirror.kimiahost.com/" "https://archive.ubuntu.petiak.ir/ubuntu/"
        "https://ubuntu.hostiran.ir/ubuntuarchive/" "https://ubuntu.bardia.tech/" "https://mirror.iranserver.com/ubuntu/"
        "https://ir.archive.ubuntu.com/ubuntu/" "https://mirror.0-1.cloud/ubuntu/" "http://linuxmirrors.ir/pub/ubuntu/"
        "http://repo.iut.ac.ir/repo/Ubuntu/" "https://ubuntu.shatel.ir/ubuntu/" "http://ubuntu.byteiran.com/ubuntu/"
        "https://mirror.rasanegar.com/ubuntu/" "http://mirrors.sharif.ir/ubuntu/" "http://mirror.ut.ac.ir/ubuntu/"
        "http://repo.iut.ac.ir/repo/ubuntu/" "http://mirror.asiatech.ir/ubuntu/" "http://mirror.iranserver.com/ubuntu/"
        "http://archive.ubuntu.com/ubuntu/"
    )
    echo "🔍 در حال بررسی آینه‌های داخلی و جهانی برای Ubuntu ($UBUNTU_CODENAME)..."
    WORKING_MIRROR=""
    for MIRROR in "${MIRRORS[@]}"; do
        echo -n -e "⏳ تست $MIRROR ... "
        if curl -s --head --max-time 5 "$MIRROR" | grep -q "200 OK"; then
            echo -e "${C_GREEN}✅ در دسترس${C_RESET}"
            WORKING_MIRROR=$MIRROR
            break
        else
            echo -e "${C_RED}❌ در دسترس نیست${C_RESET}"
        fi
    done
    if [ -z "$WORKING_MIRROR" ]; then
        echo -e "\n${C_RED}🚫 هیچ مخزن قابل دسترسی یافت نشد. لطفاً اتصال اینترنت یا فایروال را بررسی کنید.${C_RESET}"
        read -n 1 -s -r -p "برای ادامه، کلیدی را فشار دهید..."
        return
    fi
    echo -e "\n🛠 ${C_YELLOW}در حال تنظیم فایل /etc/apt/sources.list با آینه:${C_RESET}"
    echo -e "    ${C_CYAN}$WORKING_MIRROR${C_RESET}"
    backup_file /etc/apt/sources.list
    tee /etc/apt/sources.list > /dev/null <<EOF
deb ${WORKING_MIRROR} ${UBUNTU_CODENAME} main restricted universe multiverse
deb ${WORKING_MIRROR} ${UBUNTU_CODENAME}-updates main restricted universe multiverse
deb ${WORKING_MIRROR} ${UBUNTU_CODENAME}-backports main restricted universe multiverse
deb ${WORKING_MIRROR} ${UBUNTU_CODENAME}-security main restricted universe multiverse
EOF
    echo ""
    echo -e "${C_GREEN}✅ فایل sources.list با موفقیت تنظیم شد.${C_RESET}"
    echo -e "${C_YELLOW}📦 حالا می‌توانید سیستم خود را با دستور زیر آپدیت کنید:${C_RESET}"
    echo -e "\n    apt update\n"
    read -n 1 -s -r -p "برای ادامه، کلیدی را فشار دهید..."
}

ping_test_ips() {
    clear
    echo -e "${B_CYAN}--- تست پینگ سرورهای مختلف DNS ---${C_RESET}\n"
    local ips=(
        "8.8.8.8" "9.9.9.9" "149.112.112.112" "1.1.1.1" "45.90.30.180" "45.90.28.180" "185.81.8.252"
        "86.105.252.193" "185.43.135.1" "46.16.216.25" "10.202.10.10" "185.78.66.4" "80.67.169.12"
        "80.67.169.40" "64.6.64.6" "64.6.65.6" "178.22.122.100" "185.51.200.2" "8.26.56.26" "8.20.247.20"
        "10.70.95.150" "10.70.95.162" "86.54.11.100" "86.54.11.200"
    )
    for ip in "${ips[@]}"; do
        ping -c 1 -W 1 "$ip" &> /dev/null
        if [ $? -eq 0 ]; then
            echo -e "Ping to ${C_YELLOW}$ip${C_RESET}: ${C_GREEN}موفق (Successful)${C_RESET}"
        else
            echo -e "Ping to ${C_YELLOW}$ip${C_RESET}: ${C_RED}ناموفق (Failed)${C_RESET}"
        fi
    done
    read -n 1 -s -r -p "\nبرای ادامه، کلیدی را فشار دهید..."
}

ping_iran_hosts() {
    clear
    echo -e "${B_CYAN}--- پینگ خارج به داخل ---${C_RESET}\n"
    local hosts=("soft98.ir" "arvancloud.ir" "mashreghnews.ir" "isna.ir")
    for host in "${hosts[@]}"; do
        echo -e "${B_YELLOW}--- تست پینگ برای ${host} ---${C_RESET}"
        ping -c 4 "$host"
        echo -e "${B_BLUE}-----------------------------------${C_RESET}"
    done
    echo -e "\n${C_GREEN}تست پینگ به پایان رسید.${C_RESET}"
    read -n 1 -s -r -p "برای ادامه، کلیدی را فشار دهید..."
}

port_scanner_menu() {
    clear
    echo -e "${B_CYAN}--- اسکنر پورت ---${C_RESET}\n"
    echo -e "${C_YELLOW}1)${C_WHITE} نصب ابزارهای مورد نیاز (hping3, nmap)"
    echo -e "${C_YELLOW}2)${C_WHITE} اسکن سریع با nmap (پیشنهادی)"
    echo -e "${C_YELLOW}3)${C_WHITE} اسکن آهسته با hping3"
    echo -e "${C_YELLOW}4)${C_WHITE} بازگشت به منوی امنیت"
    echo -e "${B_BLUE}-----------------------------------${C_RESET}"
    read -ep "$(echo -e "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}")" choice
    case $choice in
        1)
            echo -e "\n${C_YELLOW}در حال نصب hping3 و nmap...${C_RESET}"
            apt-get update
            apt-get install -y hping3 nmap
            echo -e "\n${C_GREEN}ابزارها با موفقیت نصب شدند.${C_RESET}"
            ;;
        2)
            read -ep "$(echo -e "${B_MAGENTA}آدرس IP هدف را وارد کنید: ${C_RESET}")" target_ip
            if ! is_valid_ip "$target_ip"; then
                echo -e "\n${C_RED}خطا: آدرس IP وارد شده معتبر نیست.${C_RESET}"
            elif ! command -v nmap &> /dev/null; then
                echo -e "\n${C_RED}خطا: nmap نصب نیست. لطفاً ابتدا از گزینه ۱ آن را نصب کنید.${C_RESET}"
            else
                echo -e "\n${C_YELLOW}در حال اسکن سریع پورت‌های باز روی $target_ip با nmap...${C_RESET}"
                nmap -p- --open "$target_ip"
                echo -e "\n${C_GREEN}اسکن با nmap به پایان رسید.${C_RESET}"
            fi
            ;;
        3)
            read -ep "$(echo -e "${B_MAGENTA}آدرس IP هدف را وارد کنید: ${C_RESET}")" target_ip
            if ! is_valid_ip "$target_ip"; then
                echo -e "\n${C_RED}خطا: آدرس IP وارد شده معتبر نیست.${C_RESET}"
            elif ! command -v hping3 &> /dev/null; then
                echo -e "\n${C_RED}خطا: hping3 نصب نیست. لطفاً ابتدا از گزینه ۱ آن را نصب کنید.${C_RESET}"
            else
                echo -e "\n${B_YELLOW}**هشدار:** این نوع اسکن بسیار زمان‌بر است و ممکن است ساعت‌ها طول بکشد.${C_RESET}"
                read -ep "$(echo -e "${B_MAGENTA}آیا برای شروع اسکن با hping3 مطمئن هستید؟ (y/n): ${C_RESET}")" confirm
                if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
                    echo -e "\n${C_YELLOW}در حال اسکن آهسته پورت‌های باز روی $target_ip با hping3...${C_RESET}"
                    for p in $(seq 1 65535); do
                        hping3 -S -p $p -c 1 "$target_ip" 2>/dev/null | grep 'flags=SA' && echo "Port $p is open";
                    done
                    echo -e "\n${C_GREEN}اسکن با hping3 به پایان رسید.${C_RESET}"
                else
                    echo -e "\n${C_RED}اسکن لغو شد.${C_RESET}"
                fi
            fi
            ;;
        4) return ;;
        *) echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}" ;;
    esac
    read -n 1 -s -r -p "برای ادامه، کلیدی را فشار دهید..."
}

ping_external_hosts() {
    clear
    echo -e "${B_CYAN}--- پینگ داخل به خارج ---${C_RESET}\n"
    local hosts=(
        "google.com" "mail.google.com" "github.com" "mikrotik.com" "tradingview.com" "cloudflare.com" "ionos.co.uk"
        "cloudzy.com" "vpsserver.com" "brixly.uk" "hostkey.com" "go.lightnode.com" "hetzner.com" "hostinger.com"
        "yottasrc.com" "contabo.com" "serverspace.io" "vdsina.com" "vpsdime.com" "ovhcloud.com" "aws.amazon.com"
        "bitlaunch.io" "zap-hosting.com" "intercolo.de" "interserver.net" "azure.microsoft.com" "monovm.com"
        "cherryservers.com" "digitalocean.com" "cloud.google.com" "ishosting.com" "btc.viabtc.io" "bitcoin.viabtc.io"
    )
    for host in "${hosts[@]}"; do
        echo -e "${B_YELLOW}--- تست پینگ برای ${host} ---${C_RESET}"
        ping -c 4 "$host"
        echo -e "${B_BLUE}-----------------------------------${C_RESET}"
    done
    echo -e "\n${C_GREEN}تست پینگ به پایان رسید.${C_RESET}"
    read -n 1 -s -r -p "برای ادامه، کلیدی را فشار دهید..."
}

manage_firewall() {
    if ! command -v ufw &> /dev/null; then
        echo -e "${C_YELLOW}فایروال UFW نصب نیست. در حال نصب...${C_RESET}"
        apt-get update
        apt-get install -y ufw
        echo -e "${C_GREEN}UFW با موفقیت نصب شد.${C_RESET}"
    fi
    while true; do
        clear
        echo -e "${B_CYAN}--- مدیریت فایروال (UFW) ---${C_RESET}\n"
        ufw status | head -n 1
        echo -e "${B_BLUE}-----------------------------------${C_RESET}"
        echo -e "${C_YELLOW}1)${C_WHITE} نمایش وضعیت و قوانین"
        echo -e "${C_YELLOW}2)${C_WHITE} اضافه کردن پورت (TCP/UDP)"
        echo -e "${C_YELLOW}3)${C_WHITE} حذف یک قانون"
        echo -e "${C_YELLOW}4)${C_WHITE} آزاد کردن خودکار پورت‌های فعال"
        echo -e "${C_YELLOW}5)${C_GREEN} فعال کردن فایروال"
        echo -e "${C_YELLOW}6)${C_RED} غیرفعال کردن فایروال"
        echo -e "${C_YELLOW}7)${C_WHITE} بازگشت به منوی امنیت"
        echo -e "${B_BLUE}-----------------------------------${C_RESET}"
        read -ep "$(echo -e "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}")" choice
        case $choice in
            1)
                clear
                echo -e "${B_CYAN}--- وضعیت کامل فایروال و قوانین ---${C_RESET}"
                ufw status verbose
                read -n 1 -s -r -p $'\nبرای ادامه کلیدی را فشار دهید...'
                ;;
            2)
                read -ep "$(echo -e "${B_MAGENTA}پورت مورد نظر را وارد کنید: ${C_RESET}")" port
                if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
                    echo -e "\n${C_RED}خطا: شماره پورت نامعتبر است.${C_RESET}"
                else
                    ufw allow "$port"
                    echo -e "\n${C_GREEN}قانون برای پورت $port روی هر دو پروتکل TCP و UDP اضافه شد.${C_RESET}"
                fi
                sleep 2
                ;;
            3)
                clear
                echo -e "${B_CYAN}--- حذف قانون فایروال ---${C_RESET}"
                ufw status numbered
                echo -e "${B_BLUE}-----------------------------------${C_RESET}"
                read -ep "$(echo -e "${B_MAGENTA}شماره قانونی که می‌خواهید حذف شود را وارد کنید: ${C_RESET}")" rule_num
                if ! [[ "$rule_num" =~ ^[0-9]+$ ]]; then
                    echo -e "\n${C_RED}خطا: ورودی باید یک عدد باشد.${C_RESET}"
                else
                    yes | ufw delete "$rule_num"
                    echo -e "\n${C_GREEN}قانون شماره $rule_num (در صورت وجود) حذف شد.${C_RESET}"
                fi
                sleep 2
                ;;
            4)
                echo -e "\n${C_YELLOW}در حال یافتن و آزاد کردن پورت‌های فعال (LISTEN)...${C_RESET}"
                mapfile -t ports < <(ss -lntu | grep 'LISTEN' | awk '{print $5}' | rev | cut -d: -f1 | rev | sort -un)
                if [ "${#ports[@]}" -eq 0 ]; then
                    echo -e "\n${C_RED}هیچ پورت فعالی برای آزاد کردن یافت نشد.${C_RESET}"
                else
                    echo -e "\n${C_GREEN}پورت‌های زیر به صورت خودکار آزاد شدند:${C_RESET}"
                    for p in "${ports[@]}"; do
                        ufw allow "$p"
                        echo " - $p"
                    done
                fi
                sleep 2
                ;;
            5)
                echo -e "\n${C_YELLOW}در حال فعال کردن فایروال...${C_RESET}"
                yes | ufw enable
                ;;
            6)
                echo -e "\n${C_YELLOW}در حال غیرفعال کردن فایروال...${C_RESET}"
                ufw disable
                ;;
            7)
                return
                ;;
            *)
                echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}"
                sleep 1
                ;;
        esac
    done
}

manage_xui_offline_install() {
    while true; do
        clear
        echo -e "${B_CYAN}--- نصب آفلاین پنل TX-UI ---${C_RESET}\n"
        echo -e "${C_YELLOW}1)${C_WHITE} نصب پنل از فایل موجود در سرور"
        echo -e "${C_YELLOW}2)${C_WHITE} راهنمای نصب آفلاین"
        echo -e "${C_YELLOW}3)${C_WHITE} بازگشت به منوی اصلی"
        echo -e "${B_BLUE}-----------------------------------${C_RESET}"
        read -ep "$(echo -e "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}")" choice

        case $choice in
            1)
                local xui_archive="/root/x-ui-linux-amd64.tar.gz"
                if [ ! -f "$xui_archive" ]; then
                    echo -e "\n${C_RED}خطا: فایل ${xui_archive} یافت نشد!${C_RESET}"
                    read -n 1 -s -r -p "برای ادامه، کلیدی را فشار دهید..."
                    return
                fi
                
                (
                    set -e
                    echo -e "\n${C_YELLOW}در حال آماده سازی و نصب پنل...${C_RESET}"
                    cd /root/
                    rm -rf x-ui/ /usr/local/x-ui/ /usr/bin/x-ui /etc/systemd/system/x-ui.service &>/dev/null
                    tar zxvf x-ui-linux-amd64.tar.gz &>/dev/null
                    chmod +x x-ui/x-ui x-ui/bin/xray-linux-* x-ui/x-ui.sh
                    cp x-ui/x-ui.sh /usr/bin/x-ui
                    cp -f x-ui/x-ui.service /etc/systemd/system/
                    mv x-ui/ /usr/local/
                    systemctl daemon-reload
                    systemctl enable x-ui &>/dev/null
                    systemctl restart x-ui
                )
                local install_exit_code=$?

                sleep 2

                if [ $install_exit_code -eq 0 ] && systemctl is-active --quiet x-ui; then
                    echo -e "\n${C_GREEN}✅ پنل با موفقیت نصب و اجرا شد!${C_RESET}"
                    echo -e "${C_YELLOW}در حال ورود به منوی مدیریت پنل...${C_RESET}"
                    sleep 2
                    clear
                    x-ui
                    echo -e "\n${B_CYAN}از پنل خارج شدید. بازگشت به منوی اصلی...${C_RESET}"
                    sleep 2
                else
                    echo -e "\n${C_RED}خطا! نصب ناموفق بود یا سرویس اجرا نشد.${C_RESET}"
                    echo -e "${C_YELLOW}خروجی وضعیت سرویس برای خطایابی:${C_RESET}"
                    systemctl status x-ui --no-pager
                    read -n 1 -s -r -p "برای ادامه، کلیدی را فشار دهید..."
                fi
                return
                ;;
            2)
                clear
                echo -e "${B_CYAN}--- راهنمای نصب آفلاین TX-UI ---${C_RESET}\n"
                echo -e "${C_WHITE}برای نصب، فایل ${C_GREEN}x-ui-linux-amd64.tar.gz${C_RESET}${C_WHITE} را از گیت‌هاب پروژه دانلود و در پوشه /root قرار دهید."
                echo -e "پس از نصب، با آی‌پی سرور و پورت ${C_YELLOW}2053${C_RESET} وارد پنل شوید (نام کاربری و رمز: ${C_YELLOW}admin${C_RESET})."
                echo -e "\n${C_YELLOW}آدرس گیت هاب پروژه :${C_RESET}"
                echo -e "${C_CYAN}https://github.com/AghayeCoder/tx-ui/releases${C_RESET}"
                read -n 1 -s -r -p "برای ادامه، کلیدی را فشار دهید..."
                return
                ;;
            3)
                return
                ;;
            *)
                echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}"
                sleep 1
                ;;
        esac
    done
}


scan_arvan_ranges() {
    clear
    if ! command -v nmap &> /dev/null; then
        echo -e "${C_YELLOW}ابزار nmap برای این کار لازم است. در حال نصب...${C_RESET}"
        apt-get update
        apt-get install -y nmap
        echo -e "${C_GREEN}nmap با موفقیت نصب شد.${C_RESET}"
        sleep 2
        clear
    fi

    echo -e "${B_CYAN}--- اسکن رنج IP آروان کلود ---${C_RESET}\n"
    local RANGES=(
        "185.143.232.0/22" "188.229.116.16/29" "94.101.182.0/27" "2.144.3.128/28"
        "89.45.48.64/28" "37.32.16.0/27" "37.32.17.0/27" "37.32.18.0/27"
        "37.32.19.0/27" "185.215.232.0/22"
    )

    for range in "${RANGES[@]}"; do
        echo
        read -ep "$(echo -e "${B_YELLOW}--> برای اسکن رنج [${C_CYAN}${range}${B_YELLOW}] کلید Enter را بزنید (s=رد کردن, q=خروج): ${C_RESET}")" choice
        case "$choice" in
            s|S) continue;;
            q|Q) break;;
        esac

        echo -e "${C_WHITE}در حال اسکن ${range}...${C_RESET}"
        mapfile -t ip_list < <(nmap -sL -n "$range" | awk '/Nmap scan report for/{print $NF}')

        for ip in "${ip_list[@]}"; do
            echo -ne "    ${C_YELLOW}تست IP: ${ip}   \r${C_RESET}"

            if ping -c 1 -W 1 "$ip" &> /dev/null; then
                echo -e "    ${C_GREEN}✅ IP فعال: ${ip}${C_RESET}                "
            fi
        done
        echo -e "اسکن رنج ${range} تمام شد."
    done

    echo -e "\n${B_GREEN}عملیات اسکن به پایان رسید.${C_RESET}"
    read -n 1 -s -r -p "برای ادامه، کلیدی را فشار دهید..."
}

scan_warp_endpoints() {
    clear
    if ! command -v nc &> /dev/null; then
        echo -e "${C_YELLOW}ابزار netcat (nc) برای این کار لازم است. در حال نصب...${C_RESET}"
        apt-get update
        apt-get install -y netcat-openbsd
        echo -e "${C_GREEN}netcat با موفقیت نصب شد.${C_RESET}"
        sleep 2
        clear
    fi

    echo -e "${B_CYAN}--- اسکن اندپوینت های وارپ ---${C_RESET}\n"
    local ENDPOINTS=(
        "162.159.192.19:1701" "188.114.98.61:955" "188.114.96.137:988" "188.114.99.66:4198"
        "188.114.99.212:1074" "188.114.98.224:4500" "188.114.98.224:878" "188.114.98.224:1387"
        "188.114.98.224:3476" "188.114.98.224:500" "188.114.98.224:2371" "188.114.98.224:1070"
        "188.114.98.224:854" "188.114.98.224:864" "188.114.98.224:939" "188.114.98.224:2408"
        "188.114.98.224:908" "162.159.192.121:2371" "188.114.96.145:1074" "188.114.98.0:878"
        "188.114.98.228:878" "188.114.99.0:878" "162.159.195.238:7156"
        "188.114.98.224:894" "188.114.96.191:3854" "[2606:4700:d1::58a8:0f84:d37f:90e7]:7559"
        "[2606:4700:d1::1665:bab6:7ff1:a710]:878" "[2606:4700:d0::6932:d526:67b7:77ce]:890"
        "[2606:4700:d1::9eae:b:2754:6ad9]:1018"
    )

    for endpoint in "${ENDPOINTS[@]}"; do
        if [[ $endpoint == \[* ]]; then
            ip_host=$(echo "$endpoint" | cut -d']' -f1 | tr -d '[')
            port=$(echo "$endpoint" | cut -d']' -f2 | tr -d ':')
        else
            ip_host=$(echo "$endpoint" | cut -d: -f1)
            port=$(echo "$endpoint" | cut -d: -f2)
        fi
        echo -ne "    ${C_YELLOW}تست اندپوینت: ${ip_host}:${port}   \r${C_RESET}"
        if nc -u -z -w 1 "$ip_host" "$port" &> /dev/null; then
            local ping_avg=$(ping -c 1 -W 1 "$ip_host" | tail -1 | awk -F '/' '{print $5}' 2>/dev/null)
            if [ -n "$ping_avg" ]; then
                echo -e "    ${C_GREEN}✅ اندپوینت فعال: ${ip_host}:${port} | پینگ: ${ping_avg} ms${C_RESET}          "
            else
                echo -e "    ${C_GREEN}✅ اندپوینت فعال: ${ip_host}:${port} | پینگ: (N/A)${C_RESET}          "
            fi
        fi
    done

    echo -e "\n${B_GREEN}عملیات اسکن به پایان رسید.${C_RESET}"
    read -n 1 -s -r -p "برای ادامه، کلیدی را فشار دهید..."
}

manage_ip_health_check() {
    while true; do
        clear
        echo -e "${B_CYAN}--- تشخیص سالم بودن آی پی ---${C_RESET}\n"
        echo -e "${C_YELLOW}1)${C_WHITE} تست اول (ip.check.place)"
        echo -e "${C_YELLOW}2)${C_WHITE} تست دوم (bench.openode.xyz)"
        echo -e "${C_YELLOW}3)${C_WHITE} تست سوم (git.io/JRw8R)"
        echo -e "${C_YELLOW}4)${C_WHITE} بازگشت به منوی امنیت"
        echo -e "${B_BLUE}-----------------------------------${C_RESET}"
        read -ep "$(echo -e "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}")" choice
        case $choice in
            1)
                clear; echo -e "${C_YELLOW}در حال اجرای تست اول...${C_RESET}"
                bash <(curl -Ls IP.Check.Place) -l en -4; break ;;
            2)
                clear; echo -e "${C_YELLOW}در حال اجرای تست دوم...${C_RESET}"
                bash <(curl -L -s https://bench.openode.xyz/multi_check.sh); break ;;
            3)
                clear; echo -e "${C_YELLOW}در حال اجرای تست سوم...${C_RESET}"
                bash <(curl -L -s https://git.io/JRw8R) -E en -M 4; break ;;
            4) return ;;
            *) echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}"; sleep 1 ;;
        esac
    done
    read -n 1 -s -r -p "برای ادامه، کلیدی را فشار دهید..."
}

# --- Iperf3 Interactive Test Function ---
run_iperf3_test() {
    clear
    echo -e "${B_CYAN}--- ابزار تست سرعت خودکار iperf3 ---${C_RESET}\n"
    if ! command -v iperf3 &> /dev/null; then
        echo -e "${C_YELLOW}ابزار iperf3 نصب نیست. در حال نصب...${C_RESET}"
        apt-get update > /dev/null 2>&1
        apt-get install -y iperf3
        echo -e "${C_GREEN}iperf3 با موفقیت نصب شد.${C_RESET}\n"
    fi

    echo -e "${C_WHITE}لطفاً نقش این سرور را در تست مشخص کنید:${C_RESET}"
    echo -e "${C_YELLOW}1) ${C_WHITE}سرور (مقصد تست - معمولاً سرور خارج)"
    echo -e "${C_YELLOW}2) ${C_WHITE}کلاینت (شروع کننده تست - معمولاً سرور ایران)"
    echo -e "${C_YELLOW}3) ${C_WHITE}بازگشت"
    echo -e "${B_BLUE}-----------------------------------${C_RESET}"
    read -ep "$(echo -e "${B_MAGENTA}نقش این سرور چیست؟ ${C_RESET}")" iperf_choice

    case $iperf_choice in
        1)
            local public_ip=$(curl -s -4 ifconfig.me || ip -4 addr show scope global | awk '{print $2}' | cut -d/ -f1 | head -n1)
            clear
            echo -e "${B_YELLOW}حالت سرور انتخاب شد.${C_RESET}"
            echo -e "\n${C_WHITE}آدرس IP عمومی این سرور: ${C_GREEN}${public_ip}${C_RESET}"
            echo -e "${C_WHITE}این آدرس را در سرور کلاینت (ایران) خود وارد کنید."
            echo -e "\n${C_YELLOW}برای شروع تست، iperf3 در حالت سرور اجرا می‌شود..."
            echo -e "برای توقف، کلیدهای ${C_RED}Ctrl+C${C_YELLOW} را فشار دهید.${C_RESET}"
            echo -e "${B_BLUE}-----------------------------------${C_RESET}"
            iperf3 -s
            ;;
        2)
            clear
            echo -e "${B_YELLOW}حالت کلاینت انتخاب شد.${C_RESET}\n"
            read -ep "$(echo -e "${B_MAGENTA}لطفاً آدرس IP سرور مقصد (سرور خارج) را وارد کنید: ${C_RESET}")" server_ip
            if ! is_valid_ip "$server_ip"; then
                echo -e "\n${C_RED}خطا: آدرس IP وارد شده معتبر نیست.${C_RESET}"
            else
                echo -e "\n${B_BLUE}--- شروع تست سرعت دانلود از ${server_ip} ---${C_RESET}"
                iperf3 -c "$server_ip" -i 1 -t 10 -P 20
                echo -e "\n${B_BLUE}--- شروع تست سرعت آپلود به ${server_ip} ---${C_RESET}"
                iperf3 -c "$server_ip" -R -i 1 -t 10 -P 20
                echo -e "\n${C_GREEN}--- تست به پایان رسید ---${C_RESET}"
            fi
            ;;
        3)
            return
            ;;
        *)
            echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}"
            sleep 1
            ;;
    esac
    read -n 1 -s -r -p $'\nبرای ادامه، کلیدی را فشار دهید...'
}


# --- MAIN MENUS ---

manage_network_optimization() {
    while true; do
        clear
        echo -e "${B_CYAN}--- بهینه سازی شبکه و اتصال ---${C_RESET}\n"
        echo -e "${C_YELLOW}1) ${C_WHITE}بهینه سازی سرعت (TC)"
        echo -e "${C_YELLOW}2) ${C_WHITE}بهینه سازی هسته (SYSCTL)"
        echo -e "${C_YELLOW}3) ${B_YELLOW}بهینه سازی بستر شبکه (پیشرفته)"
        echo -e "${C_YELLOW}4) ${C_WHITE}مدیریت و یافتن بهترین DNS"
        echo -e "${C_YELLOW}5) ${C_WHITE}یافتن سریعترین مخزن APT"
        echo -e "${C_YELLOW}6) ${C_WHITE}تست پینگ سرورهای DNS"
        echo -e "${C_YELLOW}7) ${C_WHITE}پینگ خارج به داخل"
        echo -e "${C_YELLOW}8) ${C_WHITE}پینگ داخل به خارج"
        echo -e "${C_YELLOW}9) ${C_WHITE}تست سرعت خودکار ایران و خارج (iperf3)"
        echo -e "${C_YELLOW}10) ${C_WHITE}بازگشت به منوی اصلی"
        echo -e "${B_BLUE}-----------------------------------${C_RESET}"
        read -ep "$(echo -e "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}")" choice
        case $choice in
            1) manage_tc_script ;;
            2) manage_sysctl ;;
            3) run_as_bbr_optimization ;;
            4) manage_dns ;;
            5) manage_mirror_test ;;
            6) ping_test_ips ;;
            7) ping_iran_hosts ;;
            8) ping_external_hosts ;;
            9) run_iperf3_test ;;
            10) return ;;
            *) echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}"; sleep 1 ;;
        esac
    done
}

manage_security() {
    while true; do
        clear
        echo -e "${B_CYAN}--- امنیت و دسترسی ---${C_RESET}\n"
        echo -e "${C_YELLOW}1) ${C_WHITE}مدیریت فایروال (UFW)"
        echo -e "${C_YELLOW}2) ${C_WHITE}مدیریت ورود کاربر روت"
        echo -e "${C_YELLOW}3) ${C_WHITE}تغییر پورت SSH"
        echo -e "${C_YELLOW}4) ${C_WHITE}فعال/غیرفعال کردن IPV6"
        echo -e "${C_YELLOW}5) ${C_WHITE}مدیریت ریبوت خودکار"
        echo -e "${C_YELLOW}6) ${C_WHITE}اسکنر پورت"
        echo -e "${C_YELLOW}7) ${C_WHITE}اسکن رنج آروان کلود"
        echo -e "${C_YELLOW}8) ${C_WHITE}تشخیص سالم بودن آی پی"
        echo -e "${C_YELLOW}9) ${C_WHITE}اسکن اندپوینت های وارپ"
        echo -e "${C_YELLOW}10) ${C_WHITE}بازگشت به منوی اصلی"
        echo -e "${B_BLUE}-----------------------------------${C_RESET}"
        read -ep "$(echo -e "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}")" choice
        case $choice in
            1) manage_firewall ;;
            2) manage_ssh_root ;;
            3) manage_ssh_port ;;
            4) manage_ipv6 ;;
            5) manage_reboot_cron ;;
            6) port_scanner_menu ;;
            7) scan_arvan_ranges ;;
            8) manage_ip_health_check ;;
            9) scan_warp_endpoints ;;
            10) return ;;
            *) echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}"; sleep 1 ;;
        esac
    done
}

# +++ START: NEW FUNCTION FOR RATHOLE OPTIMIZER +++
manage_rathole_optimizer_monitoring() {
    while true; do
        clear
        echo -e "${B_CYAN}--- بهینه ساز و مونیتورینگ رت هول ---${C_RESET}\n"
        echo -e "${C_YELLOW}1)${C_WHITE} نسخه چندسروره"
        echo -e "${C_YELLOW}2)${C_WHITE} نسخه تک‌سروره"
        echo -e "${C_YELLOW}3)${C_WHITE} بازگشت به منوی قبلی"
        echo -e "${B_BLUE}-----------------------------------${C_RESET}"
        read -ep "$(echo -e "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}")" choice

        case $choice in
            1)
                echo -e "\n${C_YELLOW}در حال اجرای اسکریپت نسخه چندسروره...${C_RESET}"
                bash <(curl -s https://raw.githubusercontent.com/naseh42/tunnel_watchdog/main/tunnel_watchdog.sh)
                read -n 1 -s -r -p $'\nبرای ادامه، کلیدی را فشار دهید...'
                ;;
            2)
                echo -e "\n${C_YELLOW}در حال اجرای اسکریپت نسخه تک‌سروره...${C_RESET}"
                bash <(curl -s https://raw.githubusercontent.com/naseh42/tunnel_watchdog/main/rathole_watchdog.sh)
                read -n 1 -s -r -p $'\nبرای ادامه، کلیدی را فشار دهید...'
                ;;
            3)
                return
                ;;
            *)
                echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}"
                sleep 1
                ;;
        esac
    done
}
# +++ END: NEW FUNCTION FOR RATHOLE OPTIMIZER +++

manage_rat_hole_tunnel() {
    while true; do
        clear
        echo -e "${B_CYAN}--- تانل رت هول بهینه ایران ---${C_RESET}\n"
        echo -e "${C_YELLOW}1)${C_WHITE} دانلود آنلاین رت هول (پیشنهادی)"
        echo -e "${C_YELLOW}2)${C_WHITE} نصب تونل رت هول"
        echo -e "${C_YELLOW}3)${C_WHITE} بهینه ساز و مونیتورینگ رت هول" # MODIFIED
        echo -e "${C_YELLOW}4)${C_WHITE} راهنما"
        echo -e "${C_YELLOW}5)${C_WHITE} بازگشت به منوی اصلی"
        echo -e "${B_BLUE}-----------------------------------${C_RESET}"
        read -ep "$(echo -e "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}")" tunnel_choice

        case $tunnel_choice in
            1)
                echo -e "\n${C_YELLOW}در حال دانلود فایل های مورد نیاز از گیت هاب...${C_RESET}"
                local rathole_v2_url="https://raw.githubusercontent.com/cy33r/IR-NET/refs/heads/main/rathole_v2.sh"
                local watchdog_url="https://raw.githubusercontent.com/cy33r/IR-NET/refs/heads/main/rathole_watchdog.sh"
                local success=true

                echo "--> دانلود rathole_v2.sh..."
                if ! curl -s -o /root/rathole_v2.sh "$rathole_v2_url"; then
                    echo -e "${C_RED}خطا در دانلود rathole_v2.sh.${C_RESET}"
                    success=false
                fi

                echo "--> دانلود rathole_watchdog.sh..."
                if ! curl -s -o /root/rathole_watchdog.sh "$watchdog_url"; then
                    echo -e "${C_RED}خطا در دانلود rathole_watchdog.sh.${C_RESET}"
                    success=false
                fi

                if $success; then
                    echo -e "\n${C_GREEN}فایل ها با موفقیت در /root/ دانلود شدند.${C_RESET}"
                    chmod +x /root/rathole_v2.sh
                    chmod +x /root/rathole_watchdog.sh
                    echo -e "${C_YELLOW}دسترسی اجرایی به اسکریپت ها داده شد.${C_RESET}"
                else
                    echo -e "\n${C_RED}یک یا چند فایل دانلود نشد. لطفاً اتصال اینترنت خود را بررسی کرده یا به صورت دستی اقدام کنید.${C_RESET}"
                fi
                read -n 1 -s -r -p $'\nبرای ادامه، کلیدی را فشار دهید...'
                ;;
            2)
                local rathole_script="/root/rathole_v2.sh"
                if [ -f "$rathole_script" ]; then
                    echo -e "\n${C_GREEN}در حال اجرای اسکریپت نصب تونل رت هول...${C_RESET}"
                    bash "$rathole_script"
                else
                    echo -e "\n${C_RED}خطا: اسکریپت ${rathole_script} یافت نشد! لطفاً ابتدا از گزینه (1) برای دانلود استفاده کنید.${C_RESET}"
                fi
                read -n 1 -s -r -p $'\nبرای ادامه، کلیدی را فشار دهید...'
                ;;
            3)
                # MODIFIED: Calls the new submenu
                manage_rathole_optimizer_monitoring
                ;;
            4)
                clear
                echo -e "${B_CYAN}--- راهنما ---${C_RESET}\n"
                echo -e "${C_WHITE}برای نصب، ابتدا از گزینه ${C_YELLOW}(1) دانلود آنلاین رت هول${C_RESET}${C_WHITE} استفاده کنید."
                echo -e "${C_WHITE}اسکریپت ها به صورت خودکار در پوشه /root دانلود و آماده اجرا می شوند."
                echo ""
                echo -e "${C_YELLOW}سپس اقدام به نصب تونل (گزینه 2) و بعد از آن بهینه ساز (گزینه 3) نمایید.${C_RESET}"
                echo -e "${C_YELLOW}دقت داشته باشید که تا تونل را کامل راه اندازی نکنید، بهینه ساز با خطا مواجه خواهد شد.${C_RESET}"
                echo ""
                echo -e "${C_WHITE}در صورت مشکل در دانلود آنلاین، می توانید فایل های زیر را به صورت دستی دانلود کرده و در پوشه روت قرار دهید:"
                echo -e "  - ${C_GREEN}rathole_v2.sh${C_RESET}"
                echo -e "  - ${C_GREEN}rathole_watchdog.sh${C_RESET}"
                echo -e "\n${C_WHITE}باتشکر${C_RESET}"
                read -n 1 -s -r -p $'\nبرای بازگشت به منو، کلیدی را فشار دهید...'
                ;;
            5)
                return
                ;;
            *)
                echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}"
                sleep 1
                ;;
        esac
    done
}

# --- SCRIPT MAIN LOOP ---
while true; do
  clear
  show_banner
  show_system_status_header

  echo -e "   ${C_YELLOW}1) ${B_CYAN}بهینه سازی شبکه و اتصال"
  echo -e "   ${C_YELLOW}2) ${B_CYAN}امنیت و دسترسی"
  echo -e "   ${C_YELLOW}3) ${C_WHITE}آپدیت و نصب پکیج های لازم"
  echo -e "   ${C_YELLOW}4) ${B_GREEN}نصب آفلاین پنل TX-UI"
  echo -e "   ${C_YELLOW}5) ${B_CYAN}تانل رت هول بهینه ایران"
  echo ""
  echo -e "   ${C_YELLOW}6) ${C_RED}خروج"
  echo -e "${B_BLUE}------------------------------------------------------------${C_RESET}"
  read -ep "$(echo -e "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}")" main_choice

  case $main_choice in
    1) manage_network_optimization ;;
    2) manage_security ;;
    3) install_core_packages ;;
    4) manage_xui_offline_install ;;
    5) manage_rat_hole_tunnel ;;
    6)
      clear
      echo -e "\n${B_CYAN}خدا نگهدار!${C_RESET}\n"
      exit 0
      ;;
    *)
      echo -e "\n${C_RED}گزینه نامعتبر است! لطفاً عددی بین 1 تا 6 وارد کنید.${C_RESET}"
      read -n 1 -s -r -p "برای ادامه، کلیدی را فشار دهید..."
      ;;
  esac
done
