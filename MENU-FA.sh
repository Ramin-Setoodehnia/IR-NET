#!/bin/bash

# Check for root user
if [ "$(id -u)" -ne 0 ]; then
  echo "این اسکریپت باید با دسترسی ریشه (ROOT) اجرا شود."
  echo "لطفاً از دستور 'sudo bash menu.sh' استفاده کنید."
  exit 1
fi

# --- START: UNIFIED ROBUST COLOR PALETTE ---
C_RESET=$'\e[0m'
C_RED=$'\e[0;31m'
C_GREEN=$'\e[0;32m'
C_YELLOW=$'\e[0;33m'
C_BLUE=$'\e[0;34m'
C_MAGENTA=$'\e[0;35m'
C_CYAN=$'\e[0;36m'
C_WHITE=$'\e[0;37m'
B_BLUE=$'\e[1;34m'
B_MAGENTA=$'\e[1;35m'
B_CYAN=$'\e[1;36m'
B_YELLOW=$'\e[1;33m'
R=$'\e[0;31m'
G=$'\e[0;32m'
Y=$'\e[0;33m'
B=$'\e[0;34m'
C=$'\e[0;36m'
W=$'\e[1;37m'
D=$'\e[0;90m'
N=$'\e[0m'
P=$'\e[1;35m'
# --- END: UNIFIED ROBUST COLOR PALETTE ---

# #############################################################################
# --- START OF CORE FRAMEWORK (FROM AS-BBR.SH) ---
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

log_message() {
    local level="$1"
    local message="$2"
    local timestamp color
    printf -v timestamp '%(%Y-%m-%d %H:%M:%S)T' -1
    case "$level" in
        INFO) color="$C_BLUE" ;;
        WARN) color="$C_YELLOW" ;;
        ERROR) color="$C_RED" ;;
        SUCCESS) color="$C_GREEN" ;;
        *) color="$C_RESET" ;;
    esac
    local log_line="[$timestamp] [$level] $message"
    printf "%s%s%s\n" "$color" "$log_line" "$C_RESET" | tee -a "$LOG_FILE"
}

create_backup() {
    local file_path="$1"
    if [ ! -f "$file_path" ]; then
        log_message "INFO" "فایل $file_path برای پشتیبان‌گیری وجود ندارد، از این مرحله صرف نظر شد."
        return 1
    fi
    local backup_name
    printf -v backup_name '%s.bak.%(%s)T' "$(basename "$file_path")" -1
    if cp -f "$file_path" "$BACKUP_DIR/$backup_name" 2>/dev/null; then
        log_message "SUCCESS" "یک نسخه پشتیبان از $file_path در $BACKUP_DIR/$backup_name ایجاد شد."
        echo "$BACKUP_DIR/$backup_name"
        return 0
    else
        log_message "ERROR" "ایجاد نسخه پشتیبان برای $file_path ناموفق بود."
        return 1
    fi
}

restore_backup() {
    local original_file="$1"
    local backup_file="$2"
    if cp -f "$backup_file" "$original_file" 2>/dev/null; then
        log_message "SUCCESS" "فایل $original_file از نسخه پشتیبان بازیابی شد."
        return 0
    else
        log_message "ERROR" "بازیابی از نسخه پشتیبان ناموفق بود."
        return 1
    fi
}

check_service_status() {
    local service_name=$1
    if systemctl is-active --quiet "$service_name"; then
        log_message "SUCCESS" "سرویس $service_name فعال و در حال اجرا است."
    else
        log_message "ERROR" "اجرای سرویس $service_name ناموفق بود. لطفاً وضعیت را دستی بررسی کنید: systemctl status $service_name"
    fi
}

handle_interrupt() {
    log_message "WARN" "اسکریپت متوقف شد. در حال پاکسازی..."
    local pids
    pids=$(jobs -p 2>/dev/null)
    if [[ -n "$pids" ]]; then
        echo "$pids" | xargs -r kill -TERM 2>/dev/null || true
        sleep 1
        echo "$pids" | xargs -r kill -KILL 2>/dev/null || true
    fi
    rm -f /tmp/setup_*.sh /tmp/dns_test_$$_* /tmp/conn_test_$$_* /tmp/mirror_speeds_$$ 2>/dev/null
    exit 130
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

    trap 'handle_interrupt' INT TERM

    PRIMARY_INTERFACE=$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')
}
# #############################################################################
# --- END OF CORE FRAMEWORK ---
# #############################################################################
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

# --- HELPER FUNCTIONS ---
progress_bar() {
    local msg="$1"
    local total_time="$2"
    local width=25
    local delay
    if command -v bc &>/dev/null; then
        delay=$(echo "scale=3; $total_time/100" | bc -l)
    else
        delay="0.05"
    fi

    printf "%-30s " "$msg"

    for ((i=0; i<=100; i++)); do
        local filled=$((i*width/100))
        local empty=$((width-filled))
        printf "\r%-30s [" "$msg"
        printf "${G}%${filled}s${N}" | tr ' ' '#'
        printf "%${empty}s" | tr ' ' '-'
        printf "] %3d%% " "$i"
        sleep "$delay"
    done
    printf "${G}COMPLETE${N}\n"
}

check_ipv6_status() {
    if sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null | grep -q "1"; then
        echo "disabled"
    else
        echo "enabled"
    fi
}

check_ping_status() {
    # This improved function now checks the full iptables ruleset for common ICMP block patterns.
    if iptables -S INPUT 2>/dev/null | grep -q -- "-p icmp .* --icmp-type echo-request -j \(DROP\|REJECT\)"; then
        echo "blocked"
    elif [[ $(iptables -P INPUT 2>/dev/null) == "DROP" ]] && ! iptables -S INPUT 2>/dev/null | grep -q -- "-p icmp .* --icmp-type 8/echo-request -j ACCEPT"; then
        echo "blocked"
    else
        echo "allowed"
    fi
}

is_valid_ip() {
    local ip=$1
    # FIX: Corrected the broken regex that caused the script to exit silently.
    if [[ "$ip" =~ ^([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}$ || "$ip" =~ ^(([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])) || "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 0
    else
        return 1
    fi
}

# --- SYSTEM STATUS ---
show_enhanced_system_status() {
    # This function calculates the visual length of a string, ignoring ANSI color codes.
    get_visual_length() {
        local clean_string
        clean_string=$(echo -e "$1" | sed 's/\x1b\[[0-9;]*m//g')
        # اصلاحیه: استفاده از 'wc -m' به جای 'wc -c' برای پشتیبانی صحیح از کاراکترهای چند بایتی (مثل فارسی) و جلوگیری از به‌هم‌ریختگی جدول
        echo -n "$clean_string" | wc -m
    }

    # Data Collection (all variables are local to this function)
    local cpu_model=$(grep "model name" /proc/cpuinfo | head -1 | cut -d':' -f2 | sed 's/^ *//' | cut -c1-30)
    local cpu_cores=$(nproc)
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1 2>/dev/null || echo "N/A")
    local mem_total=$(free -h | grep "Mem:" | awk '{print $2}')
    local mem_used=$(free -h | grep "Mem:" | awk '{print $3}')
    local mem_percent=$(free | grep "Mem:" | awk '{printf "%.0f", ($3/$2)*100.0}')
    local load_avg=$(uptime | awk -F'load average:' '{print $2}' | sed 's/^ *//' | cut -d',' -f1)
    local uptime_str=$(uptime -p 2>/dev/null | sed 's/up //')
    local ipv6_status_val=$(check_ipv6_status)
    local ping_status_val=$(check_ping_status)
    local ubuntu_version=$(lsb_release -sr 2>/dev/null || echo 'N/A')
    local current_mirror
    if [[ "$ubuntu_version" > "22" ]] && [ -f /etc/apt/sources.list.d/ubuntu.sources ]; then
        current_mirror=$(grep -m1 "URIs:" /etc/apt/sources.list.d/ubuntu.sources 2>/dev/null | awk '{print $2}')
    else
        current_mirror=$(grep -m1 "^deb " /etc/apt/sources.list 2>/dev/null | awk '{print $2}')
    fi
    [ -z "$current_mirror" ] && current_mirror="N/A"

    # Network Info
    local net_info ip_addr="N/A" location="N/A" provider="N/A" dns_servers="N/A"
    local net_status="${R}UNAVAILABLE${N}"
    if net_info=$(curl -s --connect-timeout 4 http://ip-api.com/json); then
        if [[ $(echo "$net_info" | jq -r .status 2>/dev/null) == "success" ]]; then
            net_status="${G}AVAILABLE${N}"
            ip_addr=$(echo "$net_info" | jq -r .query)
            location="$(echo "$net_info" | jq -r .city), $(echo "$net_info" | jq -r .country)"
            provider=$(echo "$net_info" | jq -r .isp)
        fi
    fi
    if command -v resolvectl &>/dev/null; then
        dns_servers=$(resolvectl status | awk '/DNS Servers:/{ $1=""; $2=""; print $0 }' | head -n 1 | xargs)
    else
        dns_servers=$(grep '^nameserver' /etc/resolv.conf | awk '{print $2}' | tr '\n' ' ')
    fi
    [ -z "$dns_servers" ] && dns_servers="N/A"

    # Status Formatting
    local ipv6_display="${ipv6_status_val^^}" # Uppercase
    [[ "$ipv6_status_val" == "enabled" ]] && ipv6_display="${G}${ipv6_display}${N}" || ipv6_display="${R}${ipv6_display}${N}"
    local ping_display="${ping_status_val^^}" # Uppercase
    [[ "$ping_status_val" == "allowed" ]] && ping_display="${G}${ping_display}${N}" || ping_display="${R}${ping_display}${N}"

    # Prepare labels and values for the table
    local labels=( "CPU" "PERFORMANCE" "MEMORY" "UPTIME" "IPV6 STATUS" "PING STATUS" "DNS" "IP ADDRESS" "LOCATION" "PROVIDER" "APT MIRROR" "UBUNTU VERSION" "NET STATUS" )
    local values=(
        "$cpu_model"
        "Cores: ${G}${cpu_cores}${N} | Usage: ${Y}${cpu_usage}%${N} | Load: ${C}${load_avg}${N}"
        "${B}${mem_used}${N} / ${C}${mem_total}${N} (${Y}${mem_percent}%${N})"
        "$uptime_str"
        "$ipv6_display"
        "$ping_display"
        "$dns_servers"
        "${G}${ip_addr}${N}"
        "$location"
        "$provider"
        "$(echo "${current_mirror}" | sed 's|https\?://||' | cut -d'/' -f1)"
        "${C}${ubuntu_version}${N}"
        "$net_status"
    )

    # Calculate dynamic padding
    local max_label_len=0
    local max_value_len=0
    for label in "${labels[@]}"; do
        (( ${#label} > max_label_len )) && max_label_len=${#label}
    done
    for value in "${values[@]}"; do
        local visual_len
        visual_len=$(get_visual_length "$value")
        (( visual_len > max_value_len )) && max_value_len=$visual_len
    done

    local total_width=$((max_label_len + max_value_len + 7))

    # Print the box
    printf "${B_BLUE}╔%s╗\n" "$(printf '═%.0s' $(seq 1 $total_width))"
    for i in "${!labels[@]}"; do
        local label="${labels[$i]}"
        local value="${values[$i]}"
        local visual_value_len
        visual_value_len=$(get_visual_length "$value")
        
        printf "${B_BLUE}║${C_WHITE} %s" "$label"
        printf "%*s" $((max_label_len - ${#label})) ""
        
        printf " ${B_BLUE}│${C_CYAN} %s" "$value"

        printf "%*s" $((max_value_len - visual_value_len)) ""
        printf " ${B_BLUE}║\n"
    done
    printf "${B_BLUE}╚%s╝\n" "$(printf '═%.0s' $(seq 1 $total_width))"
}
# #############################################################################
# --- START OF MERGED SCRIPT: AS-BBR.SH (CORRECTED AND INTEGRATED) ---
# #############################################################################

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
            log_message "ERROR" "Timeout waiting for package manager"
            log_message "ERROR" "Please manually kill the apt/dpkg process and try again."
            return 1
        fi
        if [[ $((waited % 30)) -eq 0 ]]; then
            log_message "WARN" "Package manager locked. Waiting... (${waited}s/${max_wait}s)"
        fi
        sleep 5
        waited=$((waited + 5))
    done
    return 0
}

reset_environment() {
    log_message "INFO" "Resetting environment after package installation..."
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
    
    log_message "WARN" "If package manager issues persist, a manual process check or reboot might be required."

    sleep 3
    log_message "SUCCESS" "Environment reset completed."
    if ! test_environment_health; then
        suggest_reconnection
        return 1
    fi
    return 0
}

test_environment_health() {
    log_message "INFO" "Testing environment health..."
    local test_commands=("ping" "dig" "ethtool" "ip" "sysctl")
    local failed_commands=()
    for cmd in "${test_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            failed_commands+=("$cmd")
        fi
    done
    if ! echo "test" >/dev/null 2>&1; then
        log_message "WARN" "Terminal output test failed"
        return 1
    fi
    if ! touch "/tmp/netopt_test_$$" 2>/dev/null; then
        log_message "WARN" "File system access test failed"
        return 1
    fi
    rm -f "/tmp/netopt_test_$$" 2>/dev/null
    if [[ "${#failed_commands[@]}" -gt 0 ]]; then
        log_message "WARN" "Some commands not found: ${failed_commands[*]}"
        return 1
    fi
    log_message "SUCCESS" "Environment health check passed."
    return 0
}

suggest_reconnection() {
    printf "\n%s╔════════════════════════════════════════════════════════╗%s\n" "$C_RED" "$C_RESET"
    printf "%s║                    ATTENTION REQUIRED                 ║%s\n" "$C_RED" "$C_RESET"
    printf "%s╚════════════════════════════════════════════════════════╝%s\n\n" "$C_RED" "$C_RESET"
    log_message "WARN" "Environment issues detected after package installation."
    printf "%sFor optimal performance, please:%s\n\n" "$C_YELLOW" "$C_RESET"
    printf "%s1. %sPress Ctrl+C to exit this script%s\n" "$C_CYAN" "$C_WHITE" "$C_RESET"
    printf "%s2. %sReconnect your SSH session%s\n" "$C_CYAN" "$C_WHITE" "$C_RESET"
    printf "%s3. %sRun the script again%s\n\n" "$C_CYAN" "$C_WHITE" "$C_RESET"
    printf "%sThis ensures all environment changes take effect properly.%s\n\n" "$C_YELLOW" "$C_RESET"
    local countdown=30
    while [[ $countdown -gt 0 ]]; do
        printf "\r%sContinuing anyway in %d seconds (Press Ctrl+C to exit)...%s" "$C_YELLOW" "$countdown" "$C_RESET"
        sleep 1
        ((countdown--))
    done
    printf "\n\n"
    printf "%b" "${C_YELLOW}Continue with potential issues? (Y/N): ${C_RESET}"
    read -r choice
    if [[ ! "$choice" =~ ^[Yy]$ ]]; then
        log_message "INFO" "Script paused for SSH reconnection. Please run again after reconnecting."
        exit 0
    fi
    log_message "WARN" "Continuing despite environment issues..."
}

install_dependencies() {
    log_message "INFO" "Checking and installing required dependencies..."
    if ! check_internet_connection; then
        log_message "ERROR" "No internet connection available."
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
        log_message "ERROR" "No supported package manager found"
        return 1
    fi
    log_message "INFO" "Detected package manager: $pkg_manager"
    if [[ "$pkg_manager" == "apt-get" ]]; then
        if ! wait_for_dpkg_lock; then
            log_message "ERROR" "Could not acquire package lock"
            return 1
        fi
        dpkg --configure -a 2>/dev/null || true
    fi
    log_message "INFO" "Updating package lists..."
    if ! timeout 180 $update_cmd 2>/dev/null; then
        log_message "WARN" "Package update failed, continuing anyway..."
    fi
    local deps=()
    case "$pkg_manager" in
        "apt-get") deps=("ethtool" "net-tools" "dnsutils" "mtr-tiny" "iperf3" "jq" "bc" "iptables-persistent" "lsb-release") ;;
        "yum"|"dnf") deps=("ethtool" "net-tools" "bind-utils" "mtr" "iperf3" "jq" "bc" "lsb-release") ;;
        "pacman") deps=("ethtool" "net-tools" "bind-tools" "mtr" "iperf3" "jq" "bc" "lsb-release") ;;
        "zypper") deps=("ethtool" "net-tools" "bind-utils" "mtr" "iperf3" "jq" "bc" "lsb-release") ;;
    esac
    local missing_deps=()
    for dep in "${deps[@]}"; do
        if ! command -v "${dep%%-*}" >/dev/null 2>&1; then
            missing_deps+=("$dep")
        fi
    done
    if [[ "${#missing_deps[@]}" -gt 0 ]]; then
        log_message "WARN" "Installing: ${missing_deps[*]}"
        local install_options=""
        if [[ "$pkg_manager" == "apt-get" ]]; then
            install_options="-o DPkg::Options::=--force-confold -o DPkg::Options::=--force-confdef -o APT::Install-Recommends=false"
        fi
        printf "%sInstalling packages (TIMEOUT: 10MIN)...%s\n" "$C_YELLOW" "$C_RESET"
        if timeout 600 $install_cmd $install_options "${missing_deps[@]}" 2>/dev/null; then
            log_message "SUCCESS" "Dependencies installed successfully."
            if ! reset_environment; then
                return 1
            fi
        else
            local exit_code=$?
            if [[ "$exit_code" -eq 124 ]]; then
                log_message "ERROR" "Installation timed out"
            else
                log_message "WARN" "Some packages failed to install, continuing..."
            fi
            return 1
        fi
    else
        log_message "INFO" "All dependencies are already installed."
    fi
    return 0
}

fix_etc_hosts() {
    local host_path="${1:-/etc/hosts}"
    local hostname_cached
    log_message "INFO" "Starting to fix the hosts file..."
    hostname_cached=$(hostname 2>/dev/null || echo "localhost")
    local backup_path
    if ! backup_path=$(create_backup "$host_path"); then
        log_message "ERROR" "Failed to create backup of hosts file."
        return 1
    fi
    if lsattr "$host_path" 2>/dev/null | grep -q 'i'; then
        log_message "WARN" "File $host_path is immutable. Making it mutable..."
        if ! chattr -i "$host_path" 2>/dev/null; then
            log_message "ERROR" "Failed to remove immutable attribute."
            return 1
        fi
    fi
    if [[ ! -w "$host_path" ]]; then
        log_message "ERROR" "Cannot write to $host_path. Check permissions."
        return 1
    fi
    if ! grep -q "$hostname_cached" "$host_path" 2>/dev/null; then
        local hostname_entry="127.0.1.1 $hostname_cached"
        if printf '%s\n' "$hostname_entry" >> "$host_path"; then
            log_message "SUCCESS" "Hostname entry added to hosts file."
        else
            log_message "ERROR" "Failed to add hostname entry."
            restore_backup "$host_path" "$backup_path"
            return 1
        fi
    else
        log_message "INFO" "Hostname entry already present."
    fi
    return 0
}

fix_dns() {
    local dns_file="/etc/resolv.conf"
    log_message "INFO" "Starting to update DNS configuration..."
    local backup_path
    if ! backup_path=$(create_backup "$dns_file"); then
        log_message "ERROR" "Failed to create backup of DNS configuration."
        return 1
    fi
    if lsattr "$dns_file" 2>/dev/null | grep -q 'i'; then
        log_message "WARN" "File $dns_file is immutable. Making it mutable..."
        if ! chattr -i "$dns_file" 2>/dev/null; then
            log_message "ERROR" "Failed to remove immutable attribute."
            return 1
        fi
    fi
    if [[ ! -w "$dns_file" ]]; then
        log_message "ERROR" "Cannot write to $dns_file. Check permissions."
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
        log_message "SUCCESS" "DNS configuration updated successfully."
        if dig +short +timeout=2 google.com @"$dns1" >/dev/null 2>&1; then
            log_message "SUCCESS" "DNS resolution verified."
        else
            log_message "WARN" "DNS verification failed, but continuing..."
        fi
    else
        log_message "ERROR" "Failed to update DNS configuration."
        restore_backup "$dns_file" "$backup_path"
        return 1
    fi
    return 0
}

custom_dns_config() {
    log_message "INFO" "Starting custom DNS configuration..."
    printf "%b" "Enter primary DNS server IP: "
    read -r dns1
    printf "%b" "Enter secondary DNS server IP: "
    read -r dns2
    if ! [[ "$dns1" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        log_message "ERROR" "Invalid primary DNS IP format"
        return 1
    fi
    if ! [[ "$dns2" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        log_message "ERROR" "Invalid secondary DNS IP format"
        return 1
    fi
    log_message "INFO" "Applying custom DNS: $dns1, $dns2"
    custom_fix_dns "$dns1" "$dns2"
}

custom_fix_dns() {
    local custom_dns1="$1"
    local custom_dns2="$2"
    local dns_file="/etc/resolv.conf"
    log_message "INFO" "Updating DNS configuration with custom servers..."
    local backup_path
    if ! backup_path=$(create_backup "$dns_file"); then
        log_message "ERROR" "Failed to create backup of DNS configuration."
        return 1
    fi
    if lsattr "$dns_file" 2>/dev/null | grep -q 'i'; then
        log_message "WARN" "File $dns_file is immutable. Making it mutable..."
        if ! chattr -i "$dns_file" 2>/dev/null; then
            log_message "ERROR" "Failed to remove immutable attribute."
            return 1
        fi
    fi
    if [[ ! -w "$dns_file" ]]; then
        log_message "ERROR" "Cannot write to $dns_file. Check permissions."
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
        log_message "SUCCESS" "Custom DNS configuration applied successfully."
        log_message "INFO" "Primary DNS: $custom_dns1"
        log_message "INFO" "Secondary DNS: $custom_dns2"
        if dig +short +timeout=2 google.com @"$custom_dns1" >/dev/null 2>&1; then
            log_message "SUCCESS" "Custom DNS resolution verified."
        else
            log_message "WARN" "Custom DNS verification failed, but continuing..."
        fi
    else
        log_message "ERROR" "Failed to update DNS configuration."
        restore_backup "$dns_file" "$backup_path"
        return 1
    fi
    return 0
}
gather_system_info() {
    log_message "INFO" "Gathering system information..."
    local cpu_cores total_ram
    cpu_cores=$(nproc 2>/dev/null | head -1)
    cpu_cores=$(printf '%s' "$cpu_cores" | tr -cd '0-9')
    if [[ -z "$cpu_cores" ]] || ! [[ "$cpu_cores" =~ ^[0-9]+$ ]] || [[ "$cpu_cores" -eq 0 ]]; then
        log_message "WARN" "CPU detection failed. Using fallback value."
        cpu_cores=1
    fi
    total_ram=$(awk '/MemTotal:/ {print int($2/1024); exit}' /proc/meminfo 2>/dev/null | head -1)
    total_ram=$(printf '%s' "$total_ram" | tr -cd '0-9')
    if [[ -z "$total_ram" ]] || ! [[ "$total_ram" =~ ^[0-9]+$ ]] || [[ "$total_ram" -eq 0 ]]; then
        log_message "WARN" "RAM detection failed. Using fallback value."
        total_ram=1024
    fi
    log_message "INFO" "System Information:"
    log_message "INFO" "CPU cores: $cpu_cores"
    log_message "INFO" "Total RAM: ${total_ram}MB"
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
        log_message "ERROR" "No interface specified."
        return 1
    fi
    log_message "INFO" "Optimizing network interface $interface..."
    if [[ -z "$SYSTEM_OPTIMAL_BACKLOG" ]]; then
        gather_system_info
    fi
    local max_mem=$SYSTEM_OPTIMAL_MEM
    if [[ "$max_mem" -gt 16777216 ]]; then
        max_mem=16777216
    fi
    log_message "INFO" "Configuring NIC offload settings..."
    {
        ethtool -K "$interface" tso on gso on gro on 2>/dev/null
        ethtool -G "$interface" rx 4096 tx 4096 2>/dev/null
    } || true
    if ethtool -k "$interface" 2>/dev/null | grep -q "rx-udp-gro-forwarding"; then
        log_message "INFO" "Enabling UDP GRO forwarding..."
        ethtool -K "$interface" rx-udp-gro-forwarding on rx-gro-list off 2>/dev/null || true
    fi
    local sysctl_conf="/etc/sysctl.d/99-network-optimizer.conf"
    log_message "INFO" "Creating network optimization configuration..."
    create_backup "$sysctl_conf"
    
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
        log_message "SUCCESS" "Network optimizations applied successfully."
    else
        log_message "ERROR" "Failed to apply network optimizations."
        return 1
    fi
    local current_cc
    current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    if [[ "$current_cc" == "bbr" ]]; then
        log_message "SUCCESS" "TCP BBR congestion control enabled."
    else
        log_message "WARN" "TCP BBR not available. Falling back to cubic."
        sysctl -w net.ipv4.tcp_congestion_control=cubic &>/dev/null
    fi
    if ip link set dev "$interface" txqueuelen 10000 2>/dev/null; then
        log_message "SUCCESS" "Increased TX queue length for $interface."
    else
        log_message "WARN" "Failed to set TX queue length."
    fi
    return 0
}

find_best_mtu() {
    local interface="$1"
    local target_ip="8.8.8.8"
    if [[ -z "$interface" ]]; then
        log_message "ERROR" "No interface specified for MTU optimization."
        return 1
    fi
    log_message "INFO" "Starting MTU optimization for interface $interface..."
    local current_mtu
    if ! current_mtu=$(cat "/sys/class/net/$interface/mtu" 2>/dev/null); then
        current_mtu=$(ip link show "$interface" 2>/dev/null | sed -n 's/.*mtu \([0-9]*\).*/\1/p')
    fi
    if [[ -z "$current_mtu" ]] || [[ ! "$current_mtu" =~ ^[0-9]+$ ]]; then
        log_message "ERROR" "Could not determine current MTU for $interface"
        return 1
    fi
    log_message "INFO" "Current MTU: $current_mtu"
    if ! ip addr show "$interface" 2>/dev/null | grep -q "inet "; then
        log_message "ERROR" "Interface $interface is not configured with an IP address"
        return 1
    fi
    log_message "INFO" "Testing basic connectivity..."
    if ! ping -c 1 -W 3 "$target_ip" &>/dev/null; then
        log_message "ERROR" "No internet connectivity. Cannot perform MTU optimization."
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
    log_message "INFO" "Testing common MTU sizes..."
    local common_mtus=(1500 1492 1480 1472 1468 1460 1450 1440 1430 1420 1400 1380 1360 1340 1300 1280 1200 1024)
    for size in "${common_mtus[@]}"; do
        if [[ "$size" -le "$current_mtu" ]]; then
            printf "  Testing MTU %d... " "$size"
            if test_mtu_size "$size"; then
                printf "${G}✓${N}\n"
                optimal_mtu="$size"; found_working=1; break
            else
                printf "${R}✗${N}\n"
            fi
        fi
    done
    if [[ "$found_working" -eq 0 ]]; then
        log_message "INFO" "Common MTUs failed. Performing binary search..."
        local min_mtu=576; local max_mtu="$current_mtu"; local test_mtu
        while [[ "$min_mtu" -le "$max_mtu" ]]; do
            test_mtu=$(( (min_mtu + max_mtu) / 2 ))
            printf "  Testing MTU %d... " "$test_mtu"
            if test_mtu_size "$test_mtu"; then
                printf "${G}✓${N}\n"
                optimal_mtu="$test_mtu"; min_mtu=$((test_mtu + 1)); found_working=1
            else
                printf "${R}✗${N}\n"
                max_mtu=$((test_mtu - 1))
            fi
        done
    fi
    if [[ "$found_working" -eq 1 ]]; then
        if [[ "$optimal_mtu" -ne "$current_mtu" ]]; then
            log_message "INFO" "Applying optimal MTU: $optimal_mtu"
            if ip link set "$interface" mtu "$optimal_mtu" 2>/dev/null; then
                log_message "SUCCESS" "MTU successfully set to $optimal_mtu"
                local new_mtu
                new_mtu=$(cat "/sys/class/net/$interface/mtu" 2>/dev/null)
                if [[ "$new_mtu" = "$optimal_mtu" ]]; then
                    log_message "SUCCESS" "MTU change verified: $new_mtu"
                else
                    log_message "WARN" "MTU verification failed. Reported: $new_mtu"
                fi
            else
                log_message "ERROR" "Failed to set MTU to $optimal_mtu"
                return 1
            fi
        else
            log_message "INFO" "Current MTU ($current_mtu) is already optimal"
        fi
    else
        log_message "WARN" "Could not find working MTU. Keeping current MTU: $current_mtu"
    fi
    return 0
}
restore_defaults() {
    log_message "INFO" "Restoring original settings..."
    printf "%b" "آیا مطمئنید که میخواهید به تنظیمات اولیه بازگردید؟ (Y/N): "
    read -r choice
    if [[ ! "$choice" =~ ^[Yy]$ ]]; then
        log_message "INFO" "Restoration cancelled."
        return 0
    fi
    local sysctl_backup hosts_backup resolv_backup
    sysctl_backup=$(find "$BACKUP_DIR" -name "99-network-optimizer.conf.bak*" -type f 2>/dev/null | sort -V | tail -n1)
    hosts_backup=$(find "$BACKUP_DIR" -name "hosts.bak*" -type f 2>/dev/null | sort -V | tail -n1)
    resolv_backup=$(find "$BACKUP_DIR" -name "resolv.conf.bak*" -type f 2>/dev/null | sort -V | tail -n1)
    if [[ -f "$sysctl_backup" ]]; then
        if cp -f "$sysctl_backup" "/etc/sysctl.d/99-network-optimizer.conf" 2>/dev/null; then
            sysctl -p "/etc/sysctl.d/99-network-optimizer.conf" &>/dev/null
            log_message "SUCCESS" "Restored sysctl settings"
        else
            log_message "ERROR" "Failed to restore sysctl settings"
        fi
    else
        log_message "WARN" "No sysctl backup found. Removing optimization file..."
        rm -f "/etc/sysctl.d/99-network-optimizer.conf"
        log_message "INFO" "Reset to system defaults"
    fi
    if [[ -f "$hosts_backup" ]]; then
        if cp -f "$hosts_backup" "/etc/hosts" 2>/dev/null; then
            log_message "SUCCESS" "Restored hosts file"
        else
            log_message "ERROR" "Failed to restore hosts file"
        fi
    else
        log_message "WARN" "No hosts backup found"
    fi
    if [[ -f "$resolv_backup" ]]; then
        if cp -f "$resolv_backup" "/etc/resolv.conf" 2>/dev/null; then
            log_message "SUCCESS" "Restored DNS settings"
        else
            log_message "ERROR" "Failed to restore DNS settings"
        fi
    else
        log_message "WARN" "No DNS backup found"
    fi
    log_message "SUCCESS" "Original settings restored successfully."
    log_message "INFO" "A system reboot is recommended for changes to take effect."
    printf "%b" "آیا مایل به ریبوت سیستم هستید؟ (Y/N): "
    read -r choice
    if [[ "$choice" =~ ^[Yy]$ ]]; then
        log_message "INFO" "Rebooting system now..."
        systemctl reboot
    fi
    return 0
}

run_diagnostics() {
    local interface="${PRIMARY_INTERFACE:-$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')}"
    clear
    printf "\n%s╔════════════════════════════════════════╗%s\n" "$C_CYAN" "$C_RESET"
    printf "%s║           NETWORK DIAGNOSTICS         ║%s\n" "$C_CYAN" "$C_RESET"
    printf "%s╚════════════════════════════════════════╝%s\n\n" "$C_CYAN" "$C_RESET"
    printf "%s┌─ [1] NETWORK INTERFACE STATUS%s\n" "$C_YELLOW" "$C_RESET"; printf "%s│%s\n" "$C_YELLOW" "$C_RESET"
    if [[ -n "$interface" ]]; then
        printf "%s│%s Interface: %s%s%s\n" "$C_YELLOW" "$C_RESET" "$C_GREEN" "$interface" "$C_RESET"
        local ip_info speed duplex link_status mtu
        ip_info=$(ip -4 addr show "$interface" 2>/dev/null | grep "inet " | awk '{print $2}' | cut -d/ -f1 | head -1)
        if [[ -n "$ip_info" ]]; then
            printf "%s│%s IPv4 Address: %s%s%s\n" "$C_YELLOW" "$C_RESET" "$C_GREEN" "$ip_info" "$C_RESET"
        else
            printf "%s│%s IPv4 Address: %sNot configured%s\n" "$C_YELLOW" "$C_RESET" "$C_RED" "$C_RESET"
        fi
        mtu=$(cat "/sys/class/net/$interface/mtu" 2>/dev/null || echo "Unknown")
        printf "%s│%s MTU: %s%s%s\n" "$C_YELLOW" "$C_RESET" "$C_GREEN" "$mtu" "$C_RESET"
        if command -v ethtool &>/dev/null; then
            local ethtool_output; ethtool_output=$(ethtool "$interface" 2>/dev/null)
            if [[ -n "$ethtool_output" ]]; then
                speed=$(echo "$ethtool_output" | grep "Speed:" | awk '{print $2}' | head -1)
                duplex=$(echo "$ethtool_output" | grep "Duplex:" | awk '{print $2}' | head -1)
                link_status=$(echo "$ethtool_output" | grep "Link detected:" | awk '{print $3}' | head -1)
                [[ "$speed" = "Unknown!" ]] && speed="Unknown"; [[ "$duplex" = "Unknown!" ]] && duplex="Unknown"
                printf "%s│%s Speed: %s%s%s\n" "$C_YELLOW" "$C_RESET" "$C_GREEN" "${speed:-Unknown}" "$C_RESET"
                printf "%s│%s Duplex: %s%s%s\n" "$C_YELLOW" "$C_RESET" "$C_GREEN" "${duplex:-Unknown}" "$C_RESET"
                printf "%s│%s Link: %s%s%s\n" "$C_YELLOW" "$C_RESET" "$C_GREEN" "${link_status:-Unknown}" "$C_RESET"
            fi
        fi
        local rx_bytes tx_bytes
        if [[ -f "/sys/class/net/$interface/statistics/rx_bytes" ]]; then
            rx_bytes=$(cat "/sys/class/net/$interface/statistics/rx_bytes" 2>/dev/null)
            tx_bytes=$(cat "/sys/class/net/$interface/statistics/tx_bytes" 2>/dev/null)
            if [[ -n "$rx_bytes" ]] && [[ -n "$tx_bytes" ]]; then
                local rx_human tx_human
                rx_human=$(numfmt --to=iec --suffix=B "$rx_bytes" 2>/dev/null || echo "$rx_bytes bytes")
                tx_human=$(numfmt --to=iec --suffix=B "$tx_bytes" 2>/dev/null || echo "$tx_bytes bytes")
                printf "%s│%s RX: %s%s%s, TX: %s%s%s\n" "$C_YELLOW" "$C_RESET" "$C_GREEN" "$rx_human" "$C_RESET" "$C_GREEN" "$tx_human" "$C_RESET"
            fi
        fi
    else
        printf "%s│%s %sNo interface detected%s\n" "$C_YELLOW" "$C_RESET" "$C_RED" "$C_RESET"
    fi
    printf "%s└─%s\n\n" "$C_YELLOW" "$C_RESET"
    printf "%s┌─ [2] DNS RESOLUTION TEST%s\n" "$C_YELLOW" "$C_RESET"; printf "%s│%s\n" "$C_YELLOW" "$C_RESET"
    local dns_pids=()
    for dns in "${TARGET_DNS[@]}"; do
        { local result="FAIL"; local time_taken="N/A"; if command -v dig &>/dev/null; then local dig_output; dig_output=$(dig +short +time=2 +tries=1 google.com @"$dns" 2>/dev/null); if [[ -n "$dig_output" ]] && [[ "$dig_output" != *"connection timed out"* ]]; then result="OK"; local query_time; query_time=$(dig +noall +stats google.com @"$dns" 2>/dev/null | grep "Query time:" | awk '{print $4}'); if [[ -n "$query_time" ]]; then time_taken="${query_time}ms"; fi; fi; else if nslookup google.com "$dns" &>/dev/null; then result="OK"; fi; fi; echo "$dns|$result|$time_taken" > "/tmp/dns_test_$$_$dns"; } &
        dns_pids+=($!)
    done
    for pid in "${dns_pids[@]}"; do wait "$pid" 2>/dev/null || true; done
    for dns in "${TARGET_DNS[@]}"; do if [[ -f "/tmp/dns_test_$$_$dns" ]]; then local dns_result; IFS='|' read -r dns_ip status query_time < "/tmp/dns_test_$$_$dns"; if [[ "$status" = "OK" ]]; then printf "%s│%s %s%s%s (%s) - %s%s%s" "$C_YELLOW" "$C_RESET" "$C_GREEN" "✓" "$C_RESET" "$dns_ip" "$C_GREEN" "$status" "$C_RESET"; if [[ "$query_time" != "N/A" ]]; then printf " [%s]" "$query_time"; fi; printf "\n"; else printf "%s│%s %s%s%s (%s) - %s%s%s\n" "$C_YELLOW" "$C_RESET" "$C_RED" "✗" "$C_RESET" "$dns_ip" "$C_RED" "$status" "$C_RESET"; fi; rm -f "/tmp/dns_test_$$_$dns"; fi; done
    printf "%s└─%s\n\n" "$C_YELLOW" "$C_RESET"
    printf "%s┌─ [3] INTERNET CONNECTIVITY%s\n" "$C_YELLOW" "$C_RESET"; printf "%s│%s\n" "$C_YELLOW" "$C_RESET"
    local test_hosts=("google.com" "github.com" "cloudflare.com" "quad9.net"); local conn_pids=()
    for host in "${test_hosts[@]}"; do { local result="FAIL"; local rtt="N/A"; local ping_output; ping_output=$(ping -c 1 -W 3 "$host" 2>/dev/null); if [[ $? -eq 0 ]]; then result="OK"; rtt=$(echo "$ping_output" | grep "time=" | sed 's/.*time=\([0-9.]*\).*/\1/'); if [[ -n "$rtt" ]]; then rtt="${rtt}ms"; fi; fi; echo "$host|$result|$rtt" > "/tmp/conn_test_$$_${host//\./_}"; } & conn_pids+=($!); done
    for pid in "${conn_pids[@]}"; do wait "$pid" 2>/dev/null || true; done
    for host in "${test_hosts[@]}"; do local temp_file="/tmp/conn_test_$$_${host//\./_}"; if [[ -f "$temp_file" ]]; then local conn_result; IFS='|' read -r hostname status rtt < "$temp_file"; if [[ "$status" = "OK" ]]; then printf "%s│%s %s%s%s %-15s - %s%s%s" "$C_YELLOW" "$C_RESET" "$C_GREEN" "✓" "$C_RESET" "$hostname" "$C_GREEN" "$status" "$C_RESET"; if [[ "$rtt" != "N/A" ]]; then printf " [%s]" "$rtt"; fi; printf "\n"; else printf "%s│%s %s%s%s %-15s - %s%s%s\n" "$C_YELLOW" "$C_RESET" "$C_RED" "✗" "$C_RESET" "$hostname" "$C_RED" "$status" "$C_RESET"; fi; rm -f "$temp_file"; fi; done
    printf "%s└─%s\n\n" "$C_YELLOW" "$C_RESET"
    printf "%s┌─ [4] NETWORK CONFIGURATION%s\n" "$C_YELLOW" "$C_RESET"; printf "%s│%s\n" "$C_YELLOW" "$C_RESET"
    local current_cc available_cc; current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "Unknown"); available_cc=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo "Unknown")
    printf "%s│%s TCP Congestion Control: %s%s%s\n" "$C_YELLOW" "$C_RESET" "$C_GREEN" "$current_cc" "$C_RESET"
    printf "%s│%s Available Algorithms: %s%s%s\n" "$C_YELLOW" "$C_RESET" "$C_CYAN" "$available_cc" "$C_RESET"
    local default_route gateway; default_route=$(ip route show default 2>/dev/null | head -1)
    if [[ -n "$default_route" ]]; then gateway=$(echo "$default_route" | awk '{print $3}'); printf "%s│%s Default Gateway: %s%s%s\n" "$C_YELLOW" "$C_RESET" "$C_GREEN" "${gateway:-Unknown}" "$C_RESET"; fi
    printf "%s└─%s\n\n" "$C_YELLOW" "$C_RESET"
    printf "%s┌─ [5] PERFORMANCE TEST%s\n" "$C_YELLOW" "$C_RESET"; printf "%s│%s\n" "$C_YELLOW" "$C_RESET"
    printf "%s│%s Testing packet loss and latency...\n" "$C_YELLOW" "$C_RESET"
    local ping_result; ping_result=$(ping -c 10 -i 0.2 8.8.8.8 2>/dev/null)
    if [[ $? -eq 0 ]]; then
        local packet_loss rtt_avg; packet_loss=$(echo "$ping_result" | grep "packet loss" | awk '{print $(NF-1)}'); rtt_avg=$(echo "$ping_result" | tail -1 | awk -F'/' '{print $5}')
        printf "%s│%s Packet Loss: %s%s%s\n" "$C_YELLOW" "$C_RESET" "$C_GREEN" "${packet_loss:-Unknown}" "$C_RESET"
        printf "%s│%s Average RTT: %s%s%sms\n" "$C_YELLOW" "$C_RESET" "$C_GREEN" "${rtt_avg:-Unknown}" "$C_RESET"
    else
        printf "%s│%s %sPerformance test failed%s\n" "$C_YELLOW" "$C_RESET" "$C_RED" "$C_RESET"
    fi
    printf "%s└─%s\n\n" "$C_YELLOW" "$C_RESET"
    read -n 1 -s -r -p "برای ادامه، کلیدی را فشار دهید..."
    printf "%s\n" "$C_RESET"
}

intelligent_optimize() {
    log_message "INFO" "Starting intelligent network optimization..."
    if ! check_internet_connection; then
        log_message "ERROR" "No internet connection available. Cannot apply optimizations."
        return 1
    fi
    local interface="${PRIMARY_INTERFACE}"
    if [[ -z "$interface" ]]; then
        log_message "ERROR" "Could not detect primary network interface."
        return 1
    fi
    if ! install_dependencies; then
        log_message "ERROR" "Failed to install required dependencies."
        return 1
    fi
    log_message "INFO" "Applying optimizations to interface $interface..."
    if ! fix_etc_hosts; then log_message "ERROR" "Failed to optimize hosts file."; return 1; fi
    if ! fix_dns; then log_message "ERROR" "Failed to optimize DNS settings."; return 1; fi
    if ! gather_system_info; then log_message "ERROR" "Failed to gather system information."; return 1; fi
    if ! optimize_network "$interface"; then log_message "ERROR" "Failed to apply network optimizations."; return 1; fi
    if ! find_best_mtu "$interface"; then log_message "ERROR" "Failed to optimize MTU."; return 1; fi
    log_message "SUCCESS" "All optimizations completed successfully."
    log_message "INFO" "A system reboot is recommended for changes to take effect."
    printf "%b" "آیا مایل به ریبوت سیستم هستید؟ (Y/N): "
    read -r choice
    if [[ "$choice" =~ ^[Yy]$ ]]; then
        log_message "INFO" "Rebooting system now..."
        systemctl reboot
    fi
    return 0
}

show_advanced_menu_as_bbr() {
    while true; do
        clear
        log_message "INFO" "Displaying advanced menu."
        printf "%sگزینه های پیشرفته:%s\n" "$C_CYAN" "$C_RESET"
        printf "%s۱. بهینه سازی دستی MTU%s\n" "$C_GREEN" "$C_RESET"
        printf "%s۲. تنظیمات سفارشی DNS%s\n" "$C_GREEN" "$C_RESET"
        printf "%s۳. تنظیمات کنترل ازدحام TCP%s\n" "$C_GREEN" "$C_RESET"
        printf "%s۴. تنظیمات رابط شبکه (NIC)%s\n" "$C_GREEN" "$C_RESET"
        printf "%s۵. مشاهده بهینه سازی های فعلی%s\n" "$C_GREEN" "$C_RESET"
        printf "%s0. بازگشت به منوی قبلی%s\n\n" "$C_GREEN" "$C_RESET"
        printf "%b" "لطفا گزینه خود را وارد کنید (0-5): "
        read -r choice
        
        if ! [[ "$choice" =~ ^[0-9]+$ ]]; then
            choice=-1
        fi
        
        case "$choice" in
            1) find_best_mtu "$PRIMARY_INTERFACE" ;;
            2) custom_dns_config ;;
            3)
                local available
                available=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null)
                printf "Available congestion control algorithms: %s\n" "$available"
                printf "%b" "Enter desired algorithm [bbr]: "
                read -r algo
                algo=${algo:-bbr}
                sysctl -w net.ipv4.tcp_congestion_control="$algo" 2>/dev/null
                ;;
            4)
                local interfaces
                interfaces=$(ip -br link show 2>/dev/null | awk '{print $1}' | grep -v "lo")
                printf "Available interfaces:\n%s\n" "$interfaces"
                printf "%b" "Enter interface to optimize: "
                read -r iface
                optimize_network "$iface"
                ;;
            5)
                printf "%sCurrent Network Optimizations:%s\n" "$C_CYAN" "$C_RESET"
                if [[ -f "/etc/sysctl.d/99-network-optimizer.conf" ]]; then
                    cat "/etc/sysctl.d/99-network-optimizer.conf"
                else
                    printf "%sNo network optimizations applied yet.%s\n" "$C_YELLOW" "$C_RESET"
                fi
                ;;
            0) return ;;
            *)
                printf "\n%sگزینه نامعتبر است. لطفا عددی بین 0 تا 5 وارد کنید.%s\n" "$C_RED" "$C_RESET"
                sleep 2
                ;;
        esac
        if [[ "$choice" != "0" ]]; then
            printf "\n%s" "${C_CYAN}"
            read -n 1 -s -r -p "برای ادامه، کلیدی را فشار دهید..."
            printf "%s\n" "$C_RESET"
        fi
    done
}

show_as_bbr_menu() {
    while true; do
        clear
        log_message "INFO" "Displaying main menu."
        printf "%sگزینه های موجود:%s\n" "$C_CYAN" "$C_RESET"
        printf "%s۱. اعمال بهینه سازی هوشمند (INTELLIGENT OPTIMIZATION)%s\n" "$C_GREEN" "$C_RESET"
        printf "%s۲. اجرای ابزار تشخیص شبکه (NETWORK DIAGNOSTICS)%s\n" "$C_GREEN" "$C_RESET"
        printf "%s۳. گزینه های پیشرفته (ADVANCED OPTIONS)%s\n" "$C_GREEN" "$C_RESET"
        printf "%s۴. بازگردانی به تنظیمات اولیه (RESTORE DEFAULTS)%s\n" "$C_GREEN" "$C_RESET"
        printf "%s0. بازگشت به منوی اصلی%s\n\n" "$C_GREEN" "$C_RESET"
        printf "%b" "لطفا گزینه خود را وارد کنید (0-4): "
        read -r choice
        
        if ! [[ "$choice" =~ ^[0-9]+$ ]]; then
            choice=-1
        fi

        case "$choice" in
            1)
                intelligent_optimize
                printf "\n%s" "${C_CYAN}"
                read -n 1 -s -r -p "برای ادامه کلیدی را فشار دهید..."
                printf "%s\n" "$C_RESET"
                ;;
            2) run_diagnostics ;;
            3) show_advanced_menu_as_bbr ;;
            4)
                restore_defaults
                printf "\n%s" "${C_CYAN}"
                read -n 1 -s -r -p "برای ادامه کلیدی را فشار دهید..."
                printf "%s\n" "$C_RESET"
                ;;
            0)
                log_message "INFO" "Returning to main menu."
                printf "\n%sدر حال بازگشت...%s\n" "$C_YELLOW" "$C_RESET"
                return
                ;;
            *)
                printf "\n%sگزینه نامعتبر است. لطفا عددی بین 0 تا 4 وارد کنید.%s\n" "$C_RED" "$C_RESET"
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
# --- END OF MERGED SCRIPT: AS-BBR.SH ---
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
        log_message "INFO" "در حال تنظیم DNS های زیر به صورت دائمی..."
        log_message "INFO" "DNS اصلی: $dns1"
        log_message "INFO" "DNS کمکی: $dns2"
        create_backup "$resolved_conf"
        touch "$resolved_conf"
        sed -i -E 's/^#?DNS=.*//' "$resolved_conf"
        sed -i -E 's/^#?FallbackDNS=.*//' "$resolved_conf"
        sed -i -E 's/^#?\[Resolve\]/\[Resolve\]/' "$resolved_conf"
        grep -v '^[[:space:]]*$' "$resolved_conf" > "${resolved_conf}.tmp" && mv "${resolved_conf}.tmp" "$resolved_conf"
        if grep -q "\[Resolve\]" "$resolved_conf"; then
            sed -i "/\[Resolve\]/a DNS=${dns1}" "$resolved_conf"
            if [ -n "$dns2" ]; then
                sed -i "/DNS=${dns1}/a FallbackDNS=${dns2}" "$resolved_conf"
            fi
        else
            echo "" >> "$resolved_conf"
            echo "[Resolve]" >> "$resolved_conf"
            echo "DNS=${dns1}" >> "$resolved_conf"
            if [ -n "$dns2" ]; then
                echo "FallbackDNS=${dns2}" >> "$resolved_conf"
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
            local ping_avg
            ping_avg=$(ping -c 3 -W 1 -q "$ip" | tail -1 | awk -F '/' '{print $5}' 2>/dev/null)
            if [ -n "$ping_avg" ]; then
                echo -e "پینگ ${C_YELLOW}$ip${C_RESET}: ${C_GREEN}${ping_avg} ms${C_RESET}"
                results+="${ping_avg} ${ip}\n"
            else
                echo -e "پینگ ${C_YELLOW}$ip${C_RESET}: ${C_RED}ناموفق${C_RESET}"
            fi
        done
        if [ -z "$results" ]; then
            log_message "ERROR" "هیچکدام از DNS ها پاسخ ندادند. لطفاً اتصال اینترنت را بررسی کنید."
            return
        fi
        mapfile -t best_ips < <(echo -e "${results}" | grep . | sort -n | awk '{print $2}')
        if [ "${#best_ips[@]}" -lt 2 ]; then
            log_message "ERROR" "حداقل دو DNS قابل دسترس برای تنظیم یافت نشد."
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
        printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"
        read -r choice

        if ! [[ "$choice" =~ ^[0-9]+$ ]]; then
            choice=-1
        fi

        case $choice in
            1) find_and_set_best_dns IRAN_DNS_LIST "ایران"; break ;;
            2) find_and_set_best_dns GLOBAL_DNS_LIST "جهانی"; break ;;
            3) clear; echo -e "${B_CYAN}--- وضعیت DNS فعال سیستم ---${C_RESET}"; resolvectl status; echo -e "${B_BLUE}-----------------------------------${C_RESET}"; break ;;
            4) nano "$resolved_conf"; break ;;
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
    printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"
    read -r choice

    if ! [[ "$choice" =~ ^[0-9]+$ ]]; then
        choice=-1
    fi

    case $choice in
        1)
            printf "%b" "${C_YELLOW}**هشدار:** این کار ممکن است اتصال شما را دچار اختلال کند. آیا مطمئن هستید؟ (Y/N): ${C_RESET}"
            read -r confirm
            if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
                log_message "INFO" "عملیات غیرفعال کردن IPV6 لغو شد."
            else
                create_backup "$sysctl_conf"
                touch "$sysctl_conf"
                sed -i '/net.ipv6.conf.all.disable_ipv6/d' "$sysctl_conf"
                sed -i '/net.ipv6.conf.default.disable_ipv6/d' "$sysctl_conf"
                sed -i '/net.ipv6.conf.lo.disable_ipv6/d' "$sysctl_conf"
                echo "net.ipv6.conf.all.disable_ipv6 = 1" >> "$sysctl_conf"
                echo "net.ipv6.conf.default.disable_ipv6 = 1" >> "$sysctl_conf"
                echo "net.ipv6.conf.lo.disable_ipv6 = 1" >> "$sysctl_conf"
                sysctl -p
                log_message "SUCCESS" "IPV6 با موفقیت غیرفعال شد."
            fi
            ;;
        2)
            create_backup "$sysctl_conf"
            touch "$sysctl_conf"
            if [ -f "$sysctl_conf" ]; then
                sed -i '/net.ipv6.conf.all.disable_ipv6/d' "$sysctl_conf"
                sed -i '/net.ipv6.conf.default.disable_ipv6/d' "$sysctl_conf"
                sed -i '/net.ipv6.conf.lo.disable_ipv6/d' "$sysctl_conf"
                sysctl -p
                log_message "SUCCESS" "تنظیمات غیرفعال‌سازی IPV6 حذف شد."
            else
                log_message "WARN" "فایل SYSCTL.CONF یافت نشد."
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
  printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"
  read -r choice

  if ! [[ "$choice" =~ ^[0-9]+$ ]]; then
      choice=-1
  fi

  case $choice in
    1)
      echo -e "\n${C_YELLOW}**هشدار:** فعال کردن ورود روت با رمز عبور، یک ریسک امنیتی است.${C_RESET}"
      printf "%b" "${B_MAGENTA}آیا برای ادامه مطمئن هستید؟ (Y/N) ${C_RESET}"
      read -r confirm
      if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
          log_message "INFO" "عملیات فعال کردن ورود روت لغو شد."
      else
          echo -e "\nابتدا باید برای کاربر ROOT یک رمز عبور تنظیم کنید."
          passwd root
          create_backup "$sshd_config"
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
      create_backup "$sshd_config"
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
  log_message "INFO" "--- آپدیت و نصب پکیج های لازم ---"
  echo "در حال به‌روزرسانی سیستم و نصب بسته‌های ضروری (CURL, SOCAT, WGET, JQ, BC, IPTABLES-PERSISTENT, LSB-RELEASE, UUID-RUNTIME)..."
  apt-get update && apt-get upgrade -y
  apt-get install -y curl socat wget jq bc iptables-persistent lsb-release uuid-runtime
  log_message "SUCCESS" "سیستم با موفقیت به‌روزرسانی و بسته‌ها نصب شدند."
  read -n 1 -s -r -p "برای ادامه، کلیدی را فشار دهید..."
}

manage_reboot_cron() {
    clear
    echo -e "${B_CYAN}--- مدیریت ریبوت خودکار سرور ---${C_RESET}\n"
    echo -e "${C_YELLOW}1)${C_WHITE} افزودن CRON JOB برای ریبوت هر 3 ساعت"
    echo -e "${C_YELLOW}2)${C_WHITE} افزودن CRON JOB برای ریبوت هر 7 ساعت"
    echo -e "${C_YELLOW}3)${C_WHITE} افزودن CRON JOB برای ریبوت هر 12 ساعت"
    echo -e "${C_YELLOW}4)${C_RED} حذف تمام CRON JOB های ریبوت خودکار"
    echo -e "${C_YELLOW}5)${C_WHITE} بازگشت به منوی امنیت"
    echo -e "${B_BLUE}-----------------------------------${C_RESET}"
    printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"
    read -r choice
    
    if ! [[ "$choice" =~ ^[0-9]+$ ]]; then
        choice=-1
    fi
    
    case $choice in
        1)
            (crontab -l 2>/dev/null | grep -v "/sbin/shutdown -r now"; echo "0 */3 * * * /sbin/shutdown -r now") | crontab -
            log_message "SUCCESS" "ریبوت خودکار هر 3 ساعت یک‌بار تنظیم شد."
            ;;
        2)
            (crontab -l 2>/dev/null | grep -v "/sbin/shutdown -r now"; echo "0 */7 * * * /sbin/shutdown -r now") | crontab -
            log_message "SUCCESS" "ریبوت خودکار هر 7 ساعت یک‌بار تنظیم شد."
            ;;
        3)
            (crontab -l 2>/dev/null | grep -v "/sbin/shutdown -r now"; echo "0 */12 * * * /sbin/shutdown -r now") | crontab -
            log_message "SUCCESS" "ریبوت خودکار هر 12 ساعت یک‌بار تنظیم شد."
            ;;
        4)
            crontab -l | grep -v "/sbin/shutdown -r now" | crontab -
            log_message "SUCCESS" "تمام جاب‌های کرون ریبوت خودکار حذف شدند."
            ;;
        5) return ;;
        *) echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}" ;;
    esac
    read -n 1 -s -r -p "برای ادامه، کلیدی را فشار دهید..."
}
# ###########################################################################
# --- START: NEW SELF-CONTAINED NETWORK OPTIMIZERS ---
# ###########################################################################

remove_tcp_optimizers() {
    clear
    log_message "INFO" "در حال حذف تمام بهینه‌سازهای TCP..."
    rm -f /etc/sysctl.d/99-bbr-optimizer.conf /etc/sysctl.d/99-hybla-optimizer.conf /etc/sysctl.d/99-cubic-optimizer.conf
    
    # بارگذاری مجدد تنظیمات پیش‌فرض کرنل
    sysctl --system
    
    local current_tcp_algo
    current_tcp_algo=$(sysctl -n net.ipv4.tcp_congestion_control)
    log_message "SUCCESS" "تمام کانفیگ‌های بهینه‌ساز حذف شدند. الگوریتم فعال به پیش‌فرض کرنل (${current_tcp_algo}) بازگشت."
    echo -e "${GREEN}تمام کانفیگ‌های بهینه‌ساز TCP حذف شدند.${NC}"
    echo -e "${GREEN}الگوریتم فعال فعلی: ${YELLOW}${current_tcp_algo}${NC}"
    read -n 1 -s -r -p "برای ادامه، کلیدی را فشار دهید..."
}

apply_cubic() {
    clear
    log_message "INFO" "در حال فعال‌سازی الگوریتم CUBIC..."
    # CUBIC الگوریتم پیش‌فرض در اکثر توزیع‌های جدید است. این دستور آن را به صورت قطعی فعال می‌کند.
    local conf_file="/etc/sysctl.d/99-cubic-optimizer.conf"
    
    # حذف کانفیگ‌های دیگر برای جلوگیری از تداخل
    rm -f /etc/sysctl.d/99-bbr-optimizer.conf /etc/sysctl.d/99-hybla-optimizer.conf
    
    echo "net.ipv4.tcp_congestion_control=cubic" > "$conf_file"
    
    if sysctl -p "$conf_file" &>/dev/null; then
        log_message "SUCCESS" "الگوریتم کنترل ازدحام TCP با موفقیت به CUBIC تغییر یافت."
    else
        log_message "ERROR" "خطا در اعمال تنظیمات CUBIC."
    fi
    read -n 1 -s -r -p "برای ادامه، کلیدی را فشار دهید..."
}

apply_bbr_simple() {
    clear
    log_message "INFO" "در حال فعال‌سازی الگوریتم BBR..."
    local conf_file="/etc/sysctl.d/99-bbr-optimizer.conf"

    # حذف کانفیگ‌های دیگر برای جلوگیری از تداخل
    rm -f /etc/sysctl.d/99-cubic-optimizer.conf /etc/sysctl.d/99-hybla-optimizer.conf

    cat > "$conf_file" << EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF

    if sysctl -p "$conf_file" &>/dev/null; then
        log_message "SUCCESS" "الگوریتم BBR با موفقیت فعال شد."
        echo -e "${GREEN}برای اعمال کامل تغییرات، لطفاً یک بار سرور را ریبوت کنید.${NC}"
    else
        log_message "ERROR" "خطا در فعال‌سازی BBR."
    fi
    read -n 1 -s -r -p "برای ادامه، کلیدی را فشار دهید..."
}

apply_hybla() {
    clear
    log_message "INFO" "در حال فعال‌سازی الگوریتم HYBLA..."
    local conf_file="/etc/sysctl.d/99-hybla-optimizer.conf"

    # حذف کانفیگ‌های دیگر برای جلوگیری از تداخل
    rm -f /etc/sysctl.d/99-cubic-optimizer.conf /etc/sysctl.d/99-bbr-optimizer.conf

    # بررسی وجود ماژول HYBLA
    if ! modprobe tcp_hybla; then
        log_message "ERROR" "ماژول TCP HYBLA در این کرنل یافت نشد یا قابل بارگذاری نیست."
        echo -e "${RED}نصب HYBLA ناموفق بود. کرنل شما از آن پشتیبانی نمی‌کند.${NC}"
        read -n 1 -s -r -p "برای ادامه، کلیدی را فشار دهید..."
        return
    fi
    
    echo "net.ipv4.tcp_congestion_control=hybla" > "$conf_file"
    
    if sysctl -p "$conf_file" &>/dev/null; then
        log_message "SUCCESS" "الگوریتم کنترل ازدحام TCP با موفقیت به HYBLA تغییر یافت."
    else
        log_message "ERROR" "خطا در اعمال تنظیمات HYBLA."
    fi
    read -n 1 -s -r -p "برای ادامه، کلیدی را فشار دهید..."
}

manage_tcp_optimizers() {
    while true; do
        clear
        echo -e "${B_CYAN}--- مدیریت بهینه‌سازهای TCP ---${C_RESET}\n"
        local current_tcp_algo
        current_tcp_algo=$(sysctl -n net.ipv4.tcp_congestion_control)
        echo -e "الگوریتم کنترل ازدحام فعال فعلی: ${B_GREEN}${current_tcp_algo}${C_RESET}\n"

        echo -e "${C_YELLOW}1)${C_WHITE} نصب بهینه ساز BBR"
        echo -e "${C_YELLOW}2)${C_WHITE} نصب بهینه ساز HYBLA"
        echo -e "${C_YELLOW}3)${C_WHITE} نصب بهینه ساز CUBIC (پیش‌فرض)"
        echo -e "${C_YELLOW}4)${C_RED} حذف تمام بهینه‌سازها و بازگشت به پیشفرض کرنل"
        echo -e "${C_YELLOW}5)${C_WHITE} بازگشت به منوی قبلی"
        echo -e "${B_BLUE}-----------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"
        read -r choice

        if ! [[ "$choice" =~ ^[0-9]+$ ]]; then
            choice=-1
        fi

        case $choice in
            1) apply_bbr_simple ;;
            2) apply_hybla ;;
            3) apply_cubic ;;
            4) remove_tcp_optimizers ;;
            5) return ;;
            *) echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}"; sleep 1 ;;
        esac
    done
}

manage_server_ping() {
    while true; do
        clear
        echo -e "${B_CYAN}--- مدیریت پینگ سرور (ICMP) ---${C_RESET}\n"
        
        local ping_status
        if iptables -C INPUT -p icmp --icmp-type echo-request -j DROP &>/dev/null; then
            ping_status="${R}غیرفعال (مسدود شده)${N}"
        else
            ping_status="${G}فعال (آزاد)${N}"
        fi
        
        echo -e "وضعیت فعلی پینگ: ${ping_status}\n"
        echo -e "${C_YELLOW}1)${C_WHITE} فعال کردن پینگ"
        echo -e "${C_YELLOW}2)${C_WHITE} غیرفعال کردن پینگ"
        echo -e "${C_YELLOW}3)${C_WHITE} بازگشت"
        echo -e "${B_BLUE}-----------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"
        read -r choice

        if ! [[ "$choice" =~ ^[0-9]+$ ]]; then
            choice=-1
        fi

        local change_made=0
        case $choice in
            1)
                if iptables -C INPUT -p icmp --icmp-type echo-request -j DROP &>/dev/null; then
                    iptables -D INPUT -p icmp --icmp-type echo-request -j DROP
                    log_message "SUCCESS" "پینگ سرور فعال شد."
                    echo -e "${GREEN}پینگ سرور اکنون فعال است.${NC}"
                    change_made=1
                else
                    echo -e "${YELLOW}پینگ سرور از قبل فعال است.${NC}"
                fi
                sleep 2
                ;;
            2)
                if ! iptables -C INPUT -p icmp --icmp-type echo-request -j DROP &>/dev/null; then
                    iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
                    log_message "SUCCESS" "پینگ سرور غیرفعال شد."
                    echo -e "${RED}پینگ سرور اکنون مسدود است.${NC}"
                    change_made=1
                else
                     echo -e "${YELLOW}پینگ سرور از قبل غیرفعال است.${NC}"
                fi
                sleep 2
                ;;
            3) return ;;
            *) echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}"; sleep 1 ;;
        esac
        
        if [[ "$change_made" -eq 1 ]]; then
            echo -e "\n${C_YELLOW}آیا مایلید این تغییر برای همیشه ذخیره شود (حتی پس از ریبوت)؟ (Y/N)${NC}"
            read -r save_choice
            if [[ "$save_choice" =~ ^[Yy]$ ]]; then
                if command -v netfilter-persistent &>/dev/null; then
                    netfilter-persistent save
                    log_message "SUCCESS" "قوانین IPTABLES با موفقیت ذخیره شدند."
                else
                    log_message "ERROR" "بسته IPTABLES-PERSISTENT نصب نیست. لطفاً از منوی 'نصب پکیج های لازم' آن را نصب کنید."
                fi
            fi
        fi
    done
}

fix_whatsapp_time() {
    clear
    log_message "INFO" "در حال تنظیم منطقه زمانی سرور برای رفع مشکل تاریخ واتس‌اپ..."
    timedatectl set-timezone Asia/Tehran
    log_message "SUCCESS" "منطقه زمانی به Asia/Tehran تغییر یافت."
    echo -e "${GREEN}منطقه زمانی سرور با موفقیت به تهران تنظیم شد.${NC}"
    read -n 1 -s -r -p "برای ادامه، کلیدی را فشار دهید..."
}


# ###########################################################################
# --- END: NEW SELF-CONTAINED NETWORK OPTIMIZERS ---
# ###########################################################################


manage_tc_script() {
  clear
  echo -e "${B_CYAN}--- بهینه سازی سرعت (TC) ---${C_RESET}\n"
  echo -e "${C_YELLOW}1)${C_WHITE} نصب و تست اسکریپت بهینه‌سازی TC"
  echo -e "${C_YELLOW}2)${C_WHITE} حذف اسکریپت بهینه‌سازی TC"
  echo -e "${C_YELLOW}3)${C_WHITE} بازگشت به منوی بهینه‌سازی"
  echo -e "${B_BLUE}-----------------------------------${C_RESET}"
  printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"
  read -r choice
  
  if ! [[ "$choice" =~ ^[0-9]+$ ]]; then
      choice=-1
  fi
  
  local SCRIPT_PATH="/usr/local/bin/tc_optimize.sh"
  case $choice in
    1)
      cat > "$SCRIPT_PATH" << 'EOF'
#!/bin/bash
INTERFACE=$(ip route get 8.8.8.8 | awk '/dev/ {print $5; exit}')
tc qdisc del dev $INTERFACE root 2>/dev/null
tc qdisc del dev $INTERFACE ingress 2>/dev/null
ip link set dev $INTERFACE mtu 1500 2>/dev/null
echo 1000 > /sys/class/net/$INTERFACE/tx_queue_len 2>/dev/null
if tc qdisc add dev $INTERFACE root cake bandwidth 1000mbit rtt 20ms nat dual-dsthost 2>/dev/null; then
    echo "$(date): CAKE optimization complete" >> /var/log/tc_smart.log
    echo 'CAKE OPTIMIZATION COMPLETE'
elif tc qdisc add dev $INTERFACE root fq_codel limit 10240 flows 1024 target 5ms interval 100ms 2>/dev/null; then
    echo "$(date): FQ_CODEL optimization complete" >> /var/log/tc_smart.log
    echo 'FQ_CODEL OPTIMIZATION COMPLETE'
elif tc qdisc add dev $INTERFACE root handle 1: htb default 11 2>/dev/null && \
     tc class add dev $INTERFACE parent 1: classid 1:1 htb rate 1000mbit ceil 1000mbit 2>/dev/null && \
     tc class add dev $INTERFACE parent 1:1 classid 1:11 htb rate 1000mbit ceil 1000mbit 2>/dev/null && \
     tc qdisc add dev $INTERFACE parent 1:11 netem delay 1ms loss 0.005% duplicate 0.05% reorder 0.5% 2>/dev/null; then
    echo "$(date): HTB+NETEM optimization complete" >> /var/log/tc_smart.log
    echo 'HTB+NETEM OPTIMIZATION COMPLETE'
else
    tc qdisc add dev $INTERFACE root netem delay 1ms loss 0.005% duplicate 0.05% reorder 0.5% 2>/dev/null
    echo "$(date): FALLBACK NETEM optimization complete" >> /var/log/tc_smart.log
    echo 'FALLBACK NETEM OPTIMIZATION COMPLETE'
fi
tc qdisc show dev $INTERFACE | grep -E 'cake|fq_codel|htb|netem'
echo -e "\e[38;5;208mCY3ER\e[0m"
EOF
      chmod +x "$SCRIPT_PATH"
      (crontab -l 2>/dev/null | grep -v "$SCRIPT_PATH"; echo "@reboot sleep 30 && $SCRIPT_PATH") | crontab -
      log_message "SUCCESS" "اسکریپت بهینه‌سازی TC با موفقیت نصب شد."
      echo -e "\n${C_YELLOW}--- اجرای خودکار تست برای تایید نصب ---${C_RESET}"
      bash "$SCRIPT_PATH" && echo "تست موفق بود." && tail -5 /var/log/tc_smart.log
      ;;
    2)
      rm -f "$SCRIPT_PATH"
      crontab -l | grep -v "$SCRIPT_PATH" | crontab -
      log_message "SUCCESS" "اسکریپت بهینه‌سازی TC و CRON JOB مربوطه حذف شدند."
      ;;
    3) return ;;
    *) echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}" ;;
  esac
  read -n 1 -s -r -p "برای ادامه، کلیدی را فشار دهید..."
}

run_packet_loss_test() {
    clear
    echo -e "${B_CYAN}--- تست پکت لاست، پینگ و مسیر شبکه (MTR) ---${C_RESET}\n"
    if ! command -v mtr &> /dev/null; then
        log_message "ERROR" "ابزار MTR نصب نیست. لطفاً ابتدا از طریق منوی 'آپدیت و نصب پکیج های لازم' یا دستور 'apt install mtr-tiny' آن را نصب کنید."
        read -n 1 -s -r -p "برای ادامه، کلیدی را فشار دهید..."
        return
    fi

    printf "%b" "${B_MAGENTA}لطفاً آدرس IP سرور مقصد را وارد کنید: ${C_RESET}"
    read -r target_ip

    if ! is_valid_ip "$target_ip"; then
        log_message "ERROR" "آدرس IP وارد شده معتبر نیست."
        sleep 2
        return
    fi

    echo -e "\n${C_YELLOW}در حال اجرای تست به سمت ${target_ip}... این تست حدود 1 دقیقه طول می‌کشد.${C_RESET}"
    echo -e "${C_WHITE}این تست، پینگ و درصد بسته‌های گمشده (LOSS%) را در هر مرحله از مسیر نشان می‌دهد.${C_RESET}"
    echo -e "${C_WHITE}برای توقف دستی، کلیدهای CTRL+C را فشار دهید.${C_RESET}"
    echo -e "${B_BLUE}------------------------------------------------------------${C_RESET}"
    
    local mtr_output
    mtr_output=$(mtr -r -c 50 --no-dns "$target_ip")
    
    echo -e "$mtr_output"
    
    echo -e "${B_BLUE}------------------------------------------------------------${C_RESET}"
    log_message "SUCCESS" "تست به پایان رسید."
    
    echo -e "${B_CYAN}--- تحلیل خودکار نتیجه ---${C_RESET}"

    local last_hop_stats
    last_hop_stats=$(echo "$mtr_output" | awk '$1 ~ /^[0-9]+(\.|\?)/' | tail -n 1)

    if [ -z "$last_hop_stats" ]; then
        echo -e "${C_RED}❌ تحلیل ناموفق بود. امکان استخراج اطلاعات از خروجی MTR وجود ندارد.${C_RESET}"
    else
        local avg_loss
        avg_loss=$(echo "$last_hop_stats" | awk '{print $3}' | tr -d '[:alpha:]%')
        avg_loss=${avg_loss%.*}

        local avg_ping
        avg_ping=$(echo "$last_hop_stats" | awk '{print $5}')
        avg_ping=${avg_ping%.*}

        echo -e "${C_WHITE}▪️ میانگین پکت لاست تا مقصد: ${C_YELLOW}${avg_loss:-0}%${C_RESET}"
        echo -e "${C_WHITE}▪️ میانگین پینگ تا مقصد: ${C_YELLOW}${avg_ping:-0} ms${C_RESET}"
        echo ""

        local loss_status=""
        if [ "${avg_loss:-0}" -eq 0 ]; then
            loss_status="${G}عالی (بدون پکت لاست)${N}"
        elif [ "${avg_loss:-0}" -le 2 ]; then
            loss_status="${Y}قابل قبول (پکت لاست کم)${N}"
        else
            loss_status="${R}ضعیف (پکت لاست بالا)${N}"
        fi
        echo -e "${C_WHITE}وضعیت پکت لاست: ${loss_status}"

        local ping_status=""
        if [ "${avg_ping:-999}" -le 80 ]; then
            ping_status="${G}عالی (پینگ بسیار پایین)${N}"
        elif [ "${avg_ping:-999}" -le 150 ]; then
            ping_status="${Y}خوب (پینگ مناسب)${N}"
        else
            ping_status="${R}ضعیف (پینگ بالا)${N}"
        fi
        echo -e "${C_WHITE}وضعیت پینگ: ${ping_status}"

        echo -e "\n${B_MAGENTA}نتیجه‌گیری کلی:${C_RESET}"
        if [ "${avg_loss:-0}" -gt 2 ]; then
            echo -e "${R}این سرور به دلیل پکت لاست بالا (${avg_loss}%) برای کارهای حساس به پایداری مانند بازی یا تماس تصویری مناسب نیست.${N}"
        elif [ "${avg_loss:-0}" -eq 0 ] && [ "${avg_ping:-999}" -le 80 ]; then
            echo -e "${G}این سرور وضعیت بسیار خوبی دارد. هم پایدار است و هم پینگ پایینی دارد.${N}"
        elif [ "${avg_loss:-0}" -le 2 ] && [ "${avg_ping:-999}" -le 150 ]; then
            echo -e "${Y}این سرور وضعیت خوبی دارد و برای اکثر کاربری‌ها مناسب است.${N}"
        else
            echo -e "${Y}این سرور از نظر پایداری قابل قبول است اما ممکن است پینگ آن برای برخی کاربردها کمی بالا باشد.${N}"
        fi
    fi
    
    read -n 1 -s -r -p $'\nبرای ادامه، کلیدی را فشار دهید...'
}
# --- ADVANCED MIRROR TEST ---
declare -a MIRROR_LIST_CACHE

test_mirror_speed() {
    local url="$1/ls-lR.gz"
    local result
    result=$(wget --timeout=5 --tries=1 -O /dev/null "$url" 2>&1 | grep -o '[0-9.]\+ [KM]B/s' | tail -1)

    if [[ -z $result ]]; then
        echo "0"
    else
        if [[ $result == *K* ]]; then
            echo "$result" | sed 's/ KB\/s//'
        elif [[ $result == *M* ]]; then
            local speed_mb
            speed_mb=$(echo "$result" | sed 's/ MB\/s//')
            if command -v bc &>/dev/null; then
                 echo "scale=0; $speed_mb * 1024" | bc
            else
                 awk -v speed="$speed_mb" 'BEGIN { print int(speed * 1024) }'
            fi
        fi
    fi
}
check_mirror_release_date() {
    local mirror_url="$1"
    if ! command -v lsb_release &> /dev/null; then echo "N/A"; return; fi
    local codename
    codename=$(lsb_release -cs)
    local release_url="${mirror_url}/dists/${codename}/Release"
    local release_info
    release_info=$(curl --max-time 3 -sI "$release_url" 2>/dev/null | grep -i "last-modified" | head -1)

    if [ -n "$release_info" ]; then
        echo "$release_info" | sed -e 's/^[Ll]ast-[Mm]odified: //I' -e 's/\r//'
    else
        echo "N/A"
    fi
}

apply_selected_mirror() {
    local mirror_url="$1"
    local mirror_name="$2"

    log_message "INFO" "در حال اعمال مخزن: $mirror_name..."
    create_backup /etc/apt/sources.list
    
    if ! command -v lsb_release &> /dev/null; then
        log_message "ERROR" "بسته LSB-RELEASE نصب نیست. نمی‌توان فایل SOURCES.LIST را بروزرسانی کرد."
        return 1
    fi

    local codename
    codename=$(lsb_release -cs)
    tee /etc/apt/sources.list > /dev/null <<EOF
deb ${mirror_url} ${codename} main restricted universe multiverse
deb ${mirror_url} ${codename}-updates main restricted universe multiverse
deb ${mirror_url} ${codename}-backports main restricted universe multiverse
deb ${mirror_url} ${codename}-security main restricted universe multiverse
EOF
    
    log_message "INFO" "در حال بروزرسانی لیست بسته‌ها..."
    if apt-get update -o Acquire::AllowInsecureRepositories=true -o Acquire::AllowDowngradeToInsecureRepositories=true; then
        log_message "SUCCESS" "✅ مخزن با موفقیت به $mirror_name تغییر یافت و لیست بسته‌ها بروز شد."
    else
        log_message "ERROR" "❌ خطا در بروزرسانی لیست بسته‌ها. در حال بازگردانی به نسخه پشتیبان..."
        mv /etc/apt/sources.list.bak /etc/apt/sources.list
        apt-get update
    fi
}

choose_custom_mirror_from_list() {
    echo -e "\n${Y}--- انتخاب دستی مخزن ---${N}"
    local option_num=1
    for result in "${MIRROR_LIST_CACHE[@]}"; do
        local name
        name=$(echo "$result" | cut -d'|' -f3)
        local speed
        speed=$(echo "$result" | cut -d'|' -f1)
        local mbps
        if command -v bc &>/dev/null; then
             mbps=$(echo "scale=2; $speed * 8 / 1024" | bc)
        else
             mbps=$(awk -v speed="$speed" 'BEGIN { printf "%.2f", speed * 8 / 1024 }')
        fi
        printf "${G}%2d${N}. %-35s (${C}%.1f MBPS${N})\n" "$option_num" "$name" "$mbps"
        option_num=$((option_num + 1))
    done

    printf "%b" "${B_MAGENTA}لطفاً شماره مخزن مورد نظر را انتخاب کنید (یا برای لغو ENTER بزنید): ${C_RESET}"
    read -r custom_choice

    if [[ "$custom_choice" =~ ^[0-9]+$ ]] && [ "$custom_choice" -ge 1 ] && [ "$custom_choice" -lt "$option_num" ]; then
        local selected_info="${MIRROR_LIST_CACHE[$((custom_choice-1))]}"
        local selected_mirror
        selected_mirror=$(echo "$selected_info" | cut -d'|' -f2)
        local selected_name
        selected_name=$(echo "$selected_info" | cut -d'|' -f3)
        apply_selected_mirror "$selected_mirror" "$selected_name"
    else
        log_message "INFO" "انتخاب لغو شد."
    fi
}

advanced_mirror_test() {
    clear
    log_message "INFO" "--- آنالیز پیشرفته مخازن APT ---"
    
    local mirrors=(
        "https://mirrors.pardisco.co/ubuntu/" "http://mirror.aminidc.com/ubuntu/" "http://mirror.faraso.org/ubuntu/"
        "https://ir.ubuntu.sindad.cloud/ubuntu/" "https://ubuntu-mirror.kimiahost.com/" "https://archive.ubuntu.petiak.ir/ubuntu/"
        "https://ubuntu.hostiran.ir/ubuntuarchive/" "https://ubuntu.bardia.tech/" "https://mirror.iranserver.com/ubuntu/"
        "https://ir.archive.ubuntu.com/ubuntu/" "https://mirror.0-1.cloud/ubuntu/" "http://linuxmirrors.ir/pub/ubuntu/"
        "http://repo.iut.ac.ir/repo/Ubuntu/" "https://ubuntu.shatel.ir/ubuntu/" "http://ubuntu.byteiran.com/ubuntu/"
        "https://mirror.rasanegar.com/ubuntu/" "http://mirrors.sharif.ir/ubuntu/" "http://mirror.ut.ac.ir/ubuntu/"
        "http://archive.ubuntu.com/ubuntu/"
    )
    mirrors=($(printf "%s\n" "${mirrors[@]}" | awk '!x[$0]++'))

    echo -e "${Y}فاز ۱: تست سرعت و تاریخ بروزرسانی ${#mirrors[@]} مخزن...${N}"
    local temp_speed_file="/tmp/mirror_speeds_$$"
    
    for mirror in "${mirrors[@]}"; do
        (
            local speed
            speed=$(test_mirror_speed "$mirror")
            if [[ "$speed" != "0" ]]; then
                local release_date
                release_date=$(check_mirror_release_date "$mirror")
                local name
                name=$(echo "$mirror" | sed -E 's/https?:\/\///' | sed -E 's/(\.com|\.ir|\.co|\.tech|\.org|\.net|\.ac\.ir|\.cloud).*//' | sed -E 's/(mirrors?|archive|ubuntu|repo)\.//g' | awk '{print toupper(substr($0,1,1))substr($0,2)}')
                echo "$speed|$mirror|$name|$release_date" >> "$temp_speed_file"
                echo -n -e "${G}.${N}"
            else
                echo -n -e "${R}x${N}"
            fi
        ) &
    done
    wait
    echo -e "\n\n${G}فاز ۱ تکمیل شد.${N}"

    if [ ! -s "$temp_speed_file" ]; then
        log_message "ERROR" "[X] هیچ مخزن فعالی یافت نشد. لطفاً اتصال اینترنت را بررسی کنید."
        rm -f "$temp_speed_file"
        return 1
    fi

    mapfile -t MIRROR_LIST_CACHE < <(sort -t'|' -k1 -nr "$temp_speed_file")
    rm -f "$temp_speed_file"

    echo -e "\n${Y}--- نتایج آنالیز مخازن (مرتب شده بر اساس سرعت) ---${N}"
    printf "%-4s %-35s %-15s %-30s\n" "رتبه" "نام مخزن" "سرعت (MBPS)" "تاریخ بروزرسانی"
    printf "%.0s-" {1..90}; echo

    local rank=1
    for result in "${MIRROR_LIST_CACHE[@]}"; do
        local speed name release_date mbps
        speed=$(echo "$result" | cut -d'|' -f1)
        name=$(echo "$result" | cut -d'|' -f3)
        release_date=$(echo "$result" | cut -d'|' -f4)
        if command -v bc &>/dev/null; then
             mbps=$(echo "scale=2; $speed * 8 / 1024" | bc)
        else
             mbps=$(awk -v speed="$speed" 'BEGIN { printf "%.2f", speed * 8 / 1024 }')
        fi
        
        printf "%-4s %-35s ${G}%-15s${N} %-30s\n" "$rank." "$name" "$mbps" "$release_date"
        rank=$((rank + 1))
    done
    printf "%.0s-" {1..90}; echo

    local best_mirror_info="${MIRROR_LIST_CACHE[0]}"
    local best_mirror_url
    best_mirror_url=$(echo "$best_mirror_info" | cut -d'|' -f2)
    local best_mirror_name
    best_mirror_name=$(echo "$best_mirror_info" | cut -d'|' -f3)

    echo -e "\n${B_CYAN}--- گزینه‌ها ---${C_RESET}"
    echo -e "${C_YELLOW}1) ${C_WHITE} اعمال سریع‌ترین مخزن (${best_mirror_name})"
    echo -e "${C_YELLOW}2) ${C_WHITE} انتخاب دستی یک مخزن از لیست"
    echo -e "${C_YELLOW}3) ${C_WHITE} بازگشت به منوی بهینه‌سازی"
    echo -e "${B_BLUE}-----------------------------------${C_RESET}"
    printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"
    read -r mirror_choice
    
    if ! [[ "$mirror_choice" =~ ^[0-9]+$ ]]; then
        mirror_choice=-1
    fi

    case $mirror_choice in
        1) apply_selected_mirror "$best_mirror_url" "$best_mirror_name" ;;
        2) choose_custom_mirror_from_list ;;
        3) return ;;
        *) echo -e "${R}گزینه نامعتبر است!${N}" ;;
    esac
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
            echo -e "PING TO ${C_YELLOW}$ip${C_RESET}: ${C_GREEN}SUCCESSFUL${C_RESET}"
        else
            echo -e "PING TO ${C_YELLOW}$ip${C_RESET}: ${C_RED}FAILED${C_RESET}"
        fi
    done
    read -n 1 -s -r -p $'\nبرای ادامه، کلیدی را فشار دهید...'
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
    echo -e "${C_YELLOW}1)${C_WHITE} نصب ابزار مورد نیاز (NMAP)"
    echo -e "${C_YELLOW}2)${C_WHITE} اسکن سریع پورت‌های باز با NMAP (پیشنهادی)"
    echo -e "${C_YELLOW}3)${C_WHITE} بازگشت به منوی امنیت"
    echo -e "${B_BLUE}-----------------------------------${C_RESET}"
    printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"
    read -r choice

    if ! [[ "$choice" =~ ^[0-9]+$ ]]; then
        choice=-1
    fi

    case $choice in
        1)
            log_message "INFO" "در حال نصب NMAP..."
            apt-get update
            apt-get install -y nmap
            log_message "SUCCESS" "ابزار NMAP با موفقیت نصب شد."
            ;;
        2)
            printf "%b" "${B_MAGENTA}آدرس IP هدف را وارد کنید: ${C_RESET}"
            read -r target_ip
            if ! is_valid_ip "$target_ip"; then
                log_message "ERROR" "آدرس IP وارد شده معتبر نیست."
            elif ! command -v nmap &> /dev/null; then
                log_message "ERROR" "NMAP نصب نیست. لطفاً ابتدا از گزینه ۱ آن را نصب کنید."
            else
                log_message "INFO" "در حال اسکن سریع پورت‌های باز روی $target_ip با NMAP..."
                nmap -p- --open "$target_ip"
                log_message "SUCCESS" "اسکن با NMAP به پایان رسید."
            fi
            ;;
        3) return ;;
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
        log_message "WARN" "فایروال UFW نصب نیست. در حال نصب..."
        apt-get update
        apt-get install -y ufw
        log_message "SUCCESS" "UFW با موفقیت نصب شد."
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
        printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"
        read -r choice

        if ! [[ "$choice" =~ ^[0-9]+$ ]]; then
            choice=-1
        fi

        case $choice in
            1)
                clear
                echo -e "${B_CYAN}--- وضعیت کامل فایروال و قوانین ---${C_RESET}"
                ufw status verbose
                read -n 1 -s -r -p $'\nبرای ادامه کلیدی را فشار دهید...'
                ;;
            2)
                printf "%b" "${B_MAGENTA}پورت مورد نظر را وارد کنید: ${C_RESET}"
                read -r port
                if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
                    log_message "ERROR" "شماره پورت نامعتبر است."
                else
                    ufw allow "$port"
                    log_message "SUCCESS" "قانون برای پورت $port روی هر دو پروتکل TCP و UDP اضافه شد."
                fi
                sleep 2
                ;;
            3)
                clear
                echo -e "${B_CYAN}--- حذف قانون فایروال ---${C_RESET}"
                ufw status numbered
                echo -e "${B_BLUE}-----------------------------------${C_RESET}"
                printf "%b" "${B_MAGENTA}شماره قانونی که می‌خواهید حذف شود را وارد کنید: ${C_RESET}"
                read -r rule_num
                if ! [[ "$rule_num" =~ ^[0-9]+$ ]]; then
                    log_message "ERROR" "ورودی باید یک عدد باشد."
                else
                    yes | ufw delete "$rule_num"
                    log_message "SUCCESS" "قانون شماره $rule_num (در صورت وجود) حذف شد."
                fi
                sleep 2
                ;;
            4)
                log_message "INFO" "در حال یافتن و آزاد کردن پورت‌های فعال (LISTEN)..."
                mapfile -t ports < <(ss -lntu | grep 'LISTEN' | awk '{print $5}' | rev | cut -d: -f1 | rev | sort -un)
                if [ "${#ports[@]}" -eq 0 ]; then
                    log_message "WARN" "هیچ پورت فعالی برای آزاد کردن یافت نشد."
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
                log_message "INFO" "در حال فعال کردن فایروال..."
                yes | ufw enable
                ;;
            6)
                log_message "INFO" "در حال غیرفعال کردن فایروال..."
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
        printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"
        read -r choice

        if ! [[ "$choice" =~ ^[0-9]+$ ]]; then
            choice=-1
        fi

        case $choice in
            1)
                local xui_archive="/root/x-ui-linux-amd64.tar.gz"
                if [ ! -f "$xui_archive" ]; then
                    log_message "ERROR" "فایل ${xui_archive} یافت نشد!"
                    read -n 1 -s -r -p "برای ادامه، کلیدی را فشار دهید..."
                    return
                fi
                
                (
                    set -e
                    log_message "INFO" "در حال آماده سازی و نصب پنل..."
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
                    log_message "SUCCESS" "✅ پنل با موفقیت نصب و اجرا شد!"
                    echo -e "${C_YELLOW}در حال ورود به منوی مدیریت پنل...${C_RESET}"
                    sleep 2
                    clear
                    x-ui
                    echo -e "\n${B_CYAN}از پنل خارج شدید. بازگشت به منوی اصلی...${C_RESET}"
                    sleep 2
                else
                    log_message "ERROR" "نصب ناموفق بود یا سرویس اجرا نشد."
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
                echo -e "پس از نصب، با آی‌پی سرور و پورت ${C_YELLOW}2053${C_RESET} وارد پنل شوید (نام کاربری و رمز: ${C_YELLOW}ADMIN${C_RESET})."
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
        log_message "WARN" "ابزار NMAP برای این کار لازم است. در حال نصب..."
        apt-get update
        apt-get install -y nmap
        log_message "SUCCESS" "NMAP با موفقیت نصب شد."
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
        printf "%s--> برای اسکن رنج [" "${B_YELLOW}"
        printf "%s%s" "${C_CYAN}" "${range}"
        printf "%s] کلید ENTER را بزنید (S=رد کردن, Q=خروج): %s" "${B_YELLOW}" "${C_RESET}"
        read -r choice
        case "$choice" in
            s|S) continue;;
            q|Q) break;;
        esac

        log_message "INFO" "در حال اسکن ${range}..."
        mapfile -t ip_list < <(nmap -sL -n "$range" | awk '/Nmap scan report for/{print $NF}')

        for ip in "${ip_list[@]}"; do
            echo -ne "    ${C_YELLOW}تست IP: ${ip}   \r${C_RESET}"

            if ping -c 1 -W 1 "$ip" &> /dev/null; then
                echo -e "    ${C_GREEN}✅ IP فعال: ${ip}${C_RESET}                "
            fi
        done
        log_message "INFO" "اسکن رنج ${range} تمام شد."
    done

    echo -e "\n${B_GREEN}عملیات اسکن به پایان رسید.${C_RESET}"
    read -n 1 -s -r -p "برای ادامه، کلیدی را فشار دهید..."
}

scan_warp_endpoints() {
    clear
    if ! command -v nc &> /dev/null; then
        log_message "WARN" "ابزار NETCAT (NC) برای این کار لازم است. در حال نصب..."
        apt-get update
        apt-get install -y netcat-openbsd
        log_message "SUCCESS" "NETCAT با موفقیت نصب شد."
        sleep 2
        clear
    fi

    echo -e "${B_CYAN}--- اسکن اندپوینت های WARP ---${C_RESET}\n"
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
        local ip_host port
        if [[ $endpoint == \[* ]]; then
            ip_host=$(echo "$endpoint" | cut -d']' -f1 | tr -d '[')
            port=$(echo "$endpoint" | cut -d']' -f2 | tr -d ':')
        else
            ip_host=$(echo "$endpoint" | cut -d: -f1)
            port=$(echo "$endpoint" | cut -d: -f2)
        fi
        echo -ne "    ${C_YELLOW}تست اندپوینت: ${ip_host}:${port}   \r${C_RESET}"
        if nc -u -z -w 1 "$ip_host" "$port" &> /dev/null; then
            local ping_avg
            ping_avg=$(ping -c 1 -W 1 "$ip_host" | tail -1 | awk -F '/' '{print $5}' 2>/dev/null)
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
        echo -e "${C_YELLOW}1)${C_WHITE} تست اول (IP.CHECK.PLACE)"
        echo -e "${C_YELLOW}2)${C_WHITE} تست دوم (BENCH.OPENODE.XYZ)"
        echo -e "${C_YELLOW}3)${C_WHITE} تست سوم (GIT.IO/JRW8R)"
        echo -e "${C_YELLOW}4)${C_WHITE} بازگشت به منوی امنیت"
        echo -e "${B_BLUE}-----------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"
        read -r choice

        if ! [[ "$choice" =~ ^[0-9]+$ ]]; then
            choice=-1
        fi

        case $choice in
            1)
                clear; log_message "INFO" "در حال اجرای تست اول..."
                bash <(curl -Ls IP.Check.Place) -l en -4; break ;;
            2)
                clear; log_message "INFO" "در حال اجرای تست دوم..."
                bash <(curl -L -s https://bench.openode.xyz/multi_check.sh); break ;;
            3)
                clear; log_message "INFO" "در حال اجرای تست سوم..."
                bash <(curl -L -s https://git.io/JRw8R) -E en -M 4; break ;;
            4) return ;;
            *) echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}"; sleep 1 ;;
        esac
    done
    read -n 1 -s -r -p "برای ادامه، کلیدی را فشار دهید..."
}

run_iperf3_test() {
    clear
    echo -e "${B_CYAN}--- ابزار تست سرعت خودکار IPERF3 ---${C_RESET}\n"
    if ! command -v iperf3 &> /dev/null; then
        log_message "WARN" "ابزار IPERF3 نصب نیست. در حال نصب..."
        apt-get update > /dev/null 2>&1
        apt-get install -y iperf3
        log_message "SUCCESS" "IPERF3 با موفقیت نصب شد."
    fi

    echo -e "${C_WHITE}لطفاً نقش این سرور را در تست مشخص کنید:${C_RESET}"
    echo -e "${C_YELLOW}1) ${C_WHITE}سرور (مقصد تست - معمولاً سرور خارج)"
    echo -e "${C_YELLOW}2) ${C_WHITE}کلاینت (شروع کننده تست - معمولاً سرور ایران)"
    echo -e "${C_YELLOW}3) ${C_WHITE}بازگشت"
    echo -e "${B_BLUE}-----------------------------------${C_RESET}"
    printf "%b" "${B_MAGENTA}نقش این سرور چیست؟ ${C_RESET}"
    read -r iperf_choice

    if ! [[ "$iperf_choice" =~ ^[0-9]+$ ]]; then
        iperf_choice=-1
    fi

    case $iperf_choice in
        1)
            local public_ip
            public_ip=$(curl -s -4 ifconfig.me || ip -4 addr show scope global | awk '{print $2}' | cut -d/ -f1 | head -n1)
            clear
            echo -e "${B_YELLOW}حالت سرور (SERVER MODE) انتخاب شد.${C_RESET}"
            echo -e "\n${C_WHITE}آدرس IP عمومی این سرور: ${C_GREEN}${public_ip}${C_RESET}"
            echo -e "${C_WHITE}این آدرس را در سرور کلاینت (ایران) خود وارد کنید."
            echo -e "\n${C_YELLOW}برای شروع تست، IPERF3 در حالت سرور اجرا می‌شود..."
            echo -e "برای توقف، کلیدهای ${C_RED}CTRL+C${C_YELLOW} را فشار دهید.${C_RESET}"
            echo -e "${B_BLUE}-----------------------------------${C_RESET}"
            iperf3 -s
            ;;
        2)
            clear
            echo -e "${B_YELLOW}حالت کلاینت (CLIENT MODE) انتخاب شد.${C_RESET}\n"
            printf "%b" "${B_MAGENTA}لطفاً آدرس IP سرور مقصد (سرور خارج) را وارد کنید: ${C_RESET}"
            read -r server_ip
            if ! is_valid_ip "$server_ip"; then
                log_message "ERROR" "آدرس IP وارد شده معتبر نیست."
            else
                log_message "INFO" "--- شروع تست سرعت دانلود از ${server_ip} ---"
                iperf3 -c "$server_ip" -i 1 -t 10 -P 20
                log_message "INFO" "--- شروع تست سرعت آپلود به ${server_ip} ---"
                iperf3 -c "$server_ip" -R -i 1 -t 10 -P 20
                log_message "SUCCESS" "--- تست به پایان رسید ---"
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

manage_sanction_dns() {
    clear
    echo -e "${B_CYAN}--- دی ان اس رفع تحریم داخلی ---${C_RESET}\n"

    local -a providers=("SHECAN" "RADAR" "ELECTRO" "BEGZAR" "DNS PRO" "403" "GOOGLE" "CLOUDFLARE" "RESET TO DEFAULT")
    local -A dns_servers=(
        ["SHECAN"]="178.22.122.100 185.51.200.2"
        ["RADAR"]="10.202.10.10 10.202.10.11"
        ["ELECTRO"]="78.157.42.100 78.157.42.101"
        ["BEGZAR"]="185.55.226.26 185.55.226.25"
        ["DNS PRO"]="87.107.110.109 87.107.110.110"
        ["403"]="10.202.10.202 10.202.10.102"
        ["GOOGLE"]="8.8.8.8 8.8.4.4"
        ["CLOUDFLARE"]="1.1.1.1 1.0.0.1"
        ["RESET TO DEFAULT"]=""
    )

    show_current_dns_smart() {
        echo -e "\n${B_YELLOW}دی ان اس های فعلی سیستم:${C_RESET}"
        if command -v resolvectl &>/dev/null && systemd-resolve --status &>/dev/null; then
            resolvectl status | grep 'Current DNS Server' | awk '{print "  • " $4}' | sort -u
        elif command -v nmcli &>/dev/null; then
            nmcli dev show | grep 'IP4.DNS' | awk '{ for (i=2; i<=NF; i++) printf "  • %s\n", $i }'
        else
            grep "^nameserver" /etc/resolv.conf 2>/dev/null | awk '{print "  •", $2}' || echo "  (یافت نشد)"
        fi
        echo
    }

    apply_dns_changes_smart() {
        local provider="$1"
        local dns_list="$2"

        if command -v resolvectl &>/dev/null && systemd-resolve --status &>/dev/null; then
            local interface
            interface=$(ip route get 8.8.8.8 | awk -- '{print $5; exit}')
            log_message "INFO" "در حال استفاده از SYSTEMD-RESOLVED روی اینترفیس '$interface'..."
            if [[ "$provider" == "RESET TO DEFAULT" ]]; then
                sudo resolvectl revert "$interface"
                log_message "SUCCESS" "DNS برای '$interface' به حالت پیشفرض بازنشانی شد."
            else
                sudo resolvectl dns "$interface" $dns_list
                log_message "SUCCESS" "DNS برای '$interface' روی $provider ($dns_list) تنظیم شد."
            fi
            sudo systemctl restart systemd-resolved

        elif command -v nmcli &>/dev/null; then
            local conn_name
            conn_name=$(nmcli -t -f NAME,DEVICE con show --active | head -n 1 | cut -d: -f1)
            log_message "INFO" "در حال استفاده از NETWORKMANAGER برای کانکشن '$conn_name'..."
            if [[ "$provider" == "RESET TO DEFAULT" ]]; then
                sudo nmcli con mod "$conn_name" ipv4.dns ""
                sudo nmcli con mod "$conn_name" ipv4.ignore-auto-dns no
                log_message "SUCCESS" "DNS برای '$conn_name' به حالت خودکار بازنشانی شد."
            else
                sudo nmcli con mod "$conn_name" ipv4.dns "$dns_list"
                sudo nmcli con mod "$conn_name" ipv4.ignore-auto-dns yes
                log_message "SUCCESS" "DNS برای '$conn_name' روی $provider ($dns_list) تنظیم شد."
            fi
            log_message "INFO" "در حال فعالسازی مجدد کانکشن برای اعمال تغییرات..."
            sudo nmcli con down "$conn_name" && sudo nmcli con up "$conn_name"

        else
            log_message "WARN" "سرویس SYSTEMD-RESOLVED یا NETWORKMANAGER یافت نشد."
            echo "در حال استفاده از روش جایگزین (ویرایش مستقیم /etc/resolv.conf)."
            log_message "ERROR" "این تغییرات به احتمال زیاد موقتی بوده و پس از ریبوت پاک خواهند شد!"
            
            create_backup "/etc/resolv.conf"

            if [[ "$provider" == "RESET TO DEFAULT" ]]; then
                log_message "ERROR" "در این حالت امکان بازنشانی خودکار وجود ندارد. لطفاً نسخه پشتیبان را بازگردانید."
                return 1
            fi
            
            {
                echo "# Generated by DNS script on $(date)"
                echo "# Provider: $provider"
                for dns in $dns_list; do echo "nameserver $dns"; done
                echo "options edns0 trust-ad"
            } | sudo tee /etc/resolv.conf > /dev/null
            log_message "SUCCESS" "DNS روی $provider ($dns_list) تنظیم شد. (تغییر موقتی)"
        fi
    }

    show_current_dns_smart
    
    echo -e "${B_CYAN}سرویس دهندگان DNS موجود:${C_RESET}"
    for i in "${!providers[@]}"; do
        local name="${providers[$i]}"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %-17s ${C_CYAN}%s${C_RESET}\n" $((i + 1)) "$name" "${dns_servers[$name]}"
    done
    echo -e "   ${C_YELLOW}0)${C_WHITE} بازگشت به منوی قبلی${C_RESET}"
    echo -e "${B_BLUE}-----------------------------------${C_RESET}"
    
    printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"
    read -r choice

    if [[ ! "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -gt "${#providers[@]}" ]; then
        log_message "ERROR" "انتخاب نامعتبر است. عملیات لغو شد."
        sleep 2
        return
    fi

    if [ "$choice" -eq 0 ]; then
        return
    fi

    local provider="${providers[$((choice - 1))]}"
    apply_dns_changes_smart "$provider" "${dns_servers[$provider]}"
    
    log_message "INFO" "عملیات تکمیل شد. در حال بررسی تنظیمات جدید DNS..."
    show_current_dns_smart
    read -n 1 -s -r -p "برای ادامه، کلیدی را فشار دهید..."
}


manage_rathole_monitoring() {
    while true; do
        clear
        echo -e "${B_CYAN}--- بهینه ساز و مونیتورینگ RATHOLE ---${C_RESET}\n"
        echo -e "${C_YELLOW}1)${C_WHITE} مانیتورینگ چند سرور با TLS از طریق RATHOLE"
        echo -e "${C_YELLOW}2)${C_WHITE} پایش تونل بک‌هال (BACKHAUL) بین دو VPS برای عبور از فیلترینگ"
        echo -e "${C_YELLOW}3)${C_WHITE} بازگشت به منوی قبلی"
        echo -e "${B_BLUE}-----------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"
        read -r choice

        if ! [[ "$choice" =~ ^[0-9]+$ ]]; then
            choice=-1
        fi

        case $choice in
            1)
                log_message "INFO" "در حال اجرای اسکریپت مانیتورینگ چند سرور..."
                bash <(curl -s https://raw.githubusercontent.com/naseh42/tunnel_watchdog/main/rathole_watchdog.sh)
                read -n 1 -s -r -p $'\nبرای ادامه، کلیدی را فشار دهید...'
                ;;
            2)
                log_message "INFO" "در حال اجرای اسکریپت پایش تونل بک‌هال..."
                bash <(curl -s https://raw.githubusercontent.com/naseh42/tunnel_watchdog/main/bachaul_watchdog.sh)
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

manage_rat_hole_tunnel() {
    while true; do
        clear
        echo -e "${B_CYAN}--- تانل RATHOLE بهینه ایران ---${C_RESET}\n"
        echo -e "${C_YELLOW}1)${C_WHITE} نصب تونل RATHOLE (با اسکریپت اصلی)"
        echo -e "${C_YELLOW}2)${C_WHITE} بهینه ساز و مونیتورینگ RATHOLE"
        echo -e "${C_YELLOW}3)${C_WHITE} راهنما"
        echo -e "${C_YELLOW}4)${C_WHITE} بازگشت به منوی اصلی"
        echo -e "${B_BLUE}-----------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"
        read -r tunnel_choice

        if ! [[ "$tunnel_choice" =~ ^[0-9]+$ ]]; then
            tunnel_choice=-1
        fi

        case $tunnel_choice in
            1)
                log_message "INFO" "در حال دانلود و اجرای اسکریپت نصب رسمی RATHOLE..."
                bash <(curl -s https://raw.githubusercontent.com/cy33r/IR-NET/refs/heads/main/rathole_v2.sh)
                read -n 1 -s -r -p $'\nبرای ادامه، کلیدی را فشار دهید...'
                ;;
            2)
                manage_rathole_monitoring
                ;;
            3)
                clear
                echo -e "${B_CYAN}--- راهنما ---${C_RESET}\n"
                
                echo -e "${B_YELLOW}اسکریپت مانیتورینگ چند سرور با TLS از طریق RATHOLE :${C_RESET}"
                echo -e "${C_WHITE}✅ پس از اجرای منو:"
                echo -e "${C_WHITE}   گزینه [1] را انتخاب کن"
                echo -e "${C_WHITE}   تعداد سرورها و IP:PORT های TLS را وارد کن"
                echo -e "${C_WHITE}   سرویس rathole_watchdog.service ساخته و فعال می‌شود"
                echo ""
                echo -e "${C_WHITE}   مشاهده لاگ‌ها:"
                echo -e "${C_CYAN}   cat /var/log/rathole_watchdog.log${C_RESET}"
                echo -e "${B_BLUE}------------------------------------------------------------${C_RESET}"

                echo -e "${B_YELLOW}پایش تونل بک‌هال بین دو VPS برای عبور از فیلترینگ :${C_RESET}"
                echo -e "${C_WHITE}✅ پس از اجرای منو:"
                echo -e "${C_WHITE}   گزینه [1] را انتخاب کن"
                echo -e "${C_WHITE}   IP:PORT بک‌هال‌ها را وارد کن"
                echo -e "${C_WHITE}   سرویس backhaul_watchdog.service ساخته و فعال می‌شود"
                echo ""
                echo -e "${C_WHITE}   مشاهده لاگ‌ها:"
                echo -e "${C_CYAN}   cat /var/log/backhaul_watchdog.log${C_RESET}"
                
                read -n 1 -s -r -p $'\nبرای بازگشت به منو، کلیدی را فشار دهید...'
                ;;
            4)
                return
                ;;
            *)
                echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}"
                sleep 1
                ;;
        esac
    done
}

# ###########################################################################
# --- START: ADVANCED IRNET TUNNEL FUNCTIONS (NEW AND REFACTORED) ---
# ###########################################################################

# این تابع یک اسکریپت داخلی برای مدیریت کامل یک نوع تونل خاص ایجاد و اجرا می‌کند
run_tunnel_manager() {
    local role="$1"       # 'iran' or 'kharej'
    local protocol="$2"   # 'h2', 'quic', or 'vless'

    local script_path="/tmp/setup_${protocol}_${role}.sh"
    local menu_title=""
    local service_name=""
    local binary_path="/usr/local/bin/irnet"
    local config_dir="/etc/irnet"
    local config_file="${config_dir}/${protocol}-${role}-config.json"
    
    # تعیین نام سرویس و عنوان منو بر اساس نقش و پروتکل
    if [[ "$role" == "kharej" ]]; then
        service_name="irnet-${protocol}-server.service"
        menu_title="مدیریت سرور تونل IRNET (${protocol^^}) - (خارج)"
    else
        service_name="irnet-${protocol}-client.service"
        menu_title="مدیریت کلاینت تونل IRNET (${protocol^^}) - (ایران)"
    fi
    
    # --- START OF SCRIPT GENERATION (HEREDOC) ---
    cat > "$script_path" << EOF
#!/bin/bash
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
BLUE='\\033[0;34m'
CYAN='\\033[0;36m'
L_RED='\\033[1;31m'
NC='\\033[0m'
SERVICE_NAME="$service_name"
BINARY_PATH="$binary_path"
CONFIG_FILE="$config_file"
ROLE="$role"
PROTOCOL="$protocol"

# تابع نصب و بروزرسانی هسته Gost
function install_or_update_gost() {
    echo -e "\${YELLOW}شروع فرآیند نصب/بروزرسانی هسته GOST... \${NC}"
    echo -e "\${BLUE}نصب ابزارهای مورد نیاز... (CURL, TAR, OPENSSL, UUID-RUNTIME)\${NC}"
    apt update > /dev/null 2>&1
    apt install -y curl tar openssl uuid-runtime > /dev/null 2>&1
    ARCH=\$(uname -m)
    case \$ARCH in
        x86_64) ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        *) echo -e "\${L_RED}معماری سیستم (\$ARCH) پشتیبانی نمی‌شود.\${NC}"; exit 1 ;;
    esac
    echo -e "\${BLUE}دانلود هسته اصلی تونل GOST... \${NC}"
    LATEST_VERSION=\$(curl -s "https://api.github.com/repos/go-gost/gost/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\\1/' | sed 's/v//')
    DOWNLOAD_URL="https://github.com/go-gost/gost/releases/download/v\${LATEST_VERSION}/gost_\${LATEST_VERSION}_linux_\${ARCH}.tar.gz"
    curl -L -o gost.tar.gz \$DOWNLOAD_URL
    tar -zxvf gost.tar.gz
    mv gost \${BINARY_PATH}
    chmod +x \${BINARY_PATH}
    rm gost.tar.gz README.md
    echo -e "\${GREEN}هسته GOST نسخه \${LATEST_VERSION} با موفقیت نصب شد.\${NC}"
}

# تابع حذف کامل
function uninstall() {
    echo -e "\${YELLOW}آیا از حذف کامل این تونل مطمئن هستید؟ (Y/N)\${NC}"
    read -r -p " " response
    if [[ "\$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        systemctl stop \${SERVICE_NAME}
        systemctl disable \${SERVICE_NAME}
        rm -f /etc/systemd/system/\${SERVICE_NAME}
        rm -f \${CONFIG_FILE}
        # اگر هیچ سرویس irnet دیگری فعال نباشد، باینری را حذف کن
        if ! systemctl list-units --full -all | grep -q 'irnet-.*.service'; then
            rm -f \${BINARY_PATH}
            echo -e "\${BLUE}باینری اصلی GOST نیز حذف شد چون سرویس دیگری از آن استفاده نمی‌کرد.\${NC}"
        fi
        systemctl daemon-reload
        echo -e "\${GREEN}✔ تونل با موفقیت حذف شد.\${NC}"
    else
        echo -e "\${L_RED}عملیات حذف لغو شد.\${NC}"
    fi
}

# توابع مدیریت سرویس
function show_logs() { journalctl -u \${SERVICE_NAME} -f; }
function show_status() { systemctl status \${SERVICE_NAME} --no-pager; }
function restart_service() { systemctl restart \${SERVICE_NAME}; echo -e "\${GREEN}✔ سرویس با موفقیت راه‌اندازی مجدد شد.\${NC}"; sleep 1; show_status; }

# تابع بررسی تداخل سرویس‌ها
function check_service_conflict() {
    local current_service="\$SERVICE_NAME"
    mapfile -t running_services < <(find /etc/systemd/system/ -name "irnet-*.service" -exec basename {} \\; | grep -v "\$current_service")
    
    for service in "\${running_services[@]}"; do
        if systemctl is-active --quiet "\$service"; then
            echo -e "\${L_RED}اخطار: یک تونل IRNET دیگر (\${YELLOW}\$service\${L_RED}) در حال حاضر فعال است."
            echo -e "\${YELLOW}ادامه کار ممکن است باعث تداخل شود. آیا مایل به ادامه و غیرفعال کردن سرویس قبلی هستید؟ (Y/N)\${NC}"
            read -r -p " " confirm_disable
            if [[ "\$confirm_disable" =~ ^([yY][eE][sS]|[yY])$ ]]; then
                echo -e "\${BLUE}در حال غیرفعال کردن سرویس \${service}...\${NC}"
                systemctl disable --now "\$service"
            else
                echo -e "\${L_RED}عملیات لغو شد.${NC}"
                exit 1
            fi
        fi
    done
}

# تابع اصلی تنظیمات
function configure_tunnel() {
    check_service_conflict
    install_or_update_gost
    mkdir -p "$config_dir"
    
    local exec_start=""
    
    if [[ "\$ROLE" == "kharej" ]]; then
        # --- تنظیمات سرور خارج ---
        read -p "لطفاً یک پورت برای تونل وارد کنید (پیشنهادی: 443 یا 10000-65000): " port
        
        if [[ "\$PROTOCOL" == "vless" ]]; then
            read -p "لطفاً دامنه خود را وارد کنید (باید به IP این سرور اشاره کند): " domain
            read -p "یک مسیر برای پنهان‌سازی وارد کنید (مثلا /SECRET-PATH): " path
            local uuid=\$(uuidgen)
            exec_start="\${BINARY_PATH} -L \\"vless://\${uuid}@:\${port}?transport=ws&path=\${path}&host=\${domain}\\""
            echo "{\\"port\\":\\"\${port}\\",\\"uuid\\":\\"\${uuid}\\",\\"path\\":\\"\${path}\\",\\"domain\\":\\"\${domain}\\"}" > \${CONFIG_FILE}
            
            echo -e "\${GREEN}✔ تنظیمات با موفقیت اعمال و سرویس راه‌اندازی شد.\${NC}"
            echo -e "\n\${BLUE}============================================================\${NC}"
            echo -e "\${CYAN}      اطلاعات اتصال برای سرور ایران      \${NC}"
            echo -e "\${BLUE}============================================================\${NC}"
            echo -e "\${GREEN}دامنه سرور خارج:\${NC} \${YELLOW}\${domain}\${NC}"
            echo -e "\${GREEN}پورت سرور خارج:\${NC} \${YELLOW}\${port}\${NC}"
            echo -e "\${GREEN}UUID:\${NC} \${YELLOW}\${uuid}\${NC}"
            echo -e "\${GREEN}مسیر (PATH):\${NC} \${YELLOW}\${path}\${NC}"
            echo -e "\${BLUE}============================================================\${NC}\n"
        else
            local pass=\$(openssl rand -base64 16)
            exec_start="\${BINARY_PATH} -L \\"\${PROTOCOL}://:\${pass}@:\${port}\\""
            echo "{\\"port\\":\\"\${port}\\",\\"password\\":\\"\${pass}\\"}" > \${CONFIG_FILE}

            echo -e "\${GREEN}✔ تنظیمات با موفقیت اعمال و سرویس راه‌اندازی شد.\${NC}"
            echo -e "\n\${BLUE}============================================================\${NC}"
            echo -e "\${CYAN}      اطلاعات جدید برای اتصال سرور ایران      \${NC}"
            echo -e "\${BLUE}============================================================\${NC}"
            echo -e "\${GREEN}پورت سرور خارج:\${NC} \${YELLOW}\${port}\${NC}"
            echo -e "\${GREEN}پسورد تونل:\${NC} \${YELLOW}\${pass}\${NC}"
            echo -e "\${BLUE}============================================================\${NC}\n"
        fi
    else
        # --- تنظیمات سرور ایران ---
        read -p "یک پورت برای پراکسی محلی وارد کنید (مثلا 1080): " local_port
        if [[ "\$PROTOCOL" == "vless" ]]; then
            read -p "لطفاً دامنه سرور خارج را وارد کنید: " domain
            read -p "لطفاً پورت سرور خارج را وارد کنید: " port
            read -p "لطفاً UUID را وارد کنید: " uuid
            read -p "لطفاً مسیر (PATH) را وارد کنید: " path
            exec_start="\${BINARY_PATH} -L socks5://:\${local_port} -F \\"vless://\${uuid}@\${domain}:\${port}?transport=ws&path=\${path}&host=\${domain}\\""
            echo "{\\"local_port\\":\\"\${local_port}\\"}" > \${CONFIG_FILE}
        else
            read -p "لطفاً آدرس IP سرور خارج را وارد کنید: " abroad_ip
            read -p "لطفاً پورت سرور خارج را وارد کنید: " port
            read -p "لطفاً پسورد تونل را وارد کنید: " pass
            exec_start="\${BINARY_PATH} -L socks5://:\${local_port} -F \\"\${PROTOCOL}://\${pass}@\${abroad_ip}:\${port}\\""
            echo "{\\"local_port\\":\\"\${local_port}\\"}" > \${CONFIG_FILE}
        fi
        echo -e "\${GREEN}✔ تنظیمات با موفقیت اعمال و سرویس راه‌اندازی شد.\${NC}"
    fi

    # ایجاد فایل سرویس
    cat > /etc/systemd/system/\${SERVICE_NAME} << EOL
[Unit]
Description=IRNET \${PROTOCOL^^} \${ROLE^} Tunnel
After=network.target
[Service]
Type=simple
ExecStart=\${exec_start}
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOL

    systemctl daemon-reload
    systemctl enable \${SERVICE_NAME}
    systemctl restart \${SERVICE_NAME}
}

# تابع نمایش اطلاعات اتصال
function show_connection_info() {
    if [[ "\$ROLE" == "kharej" ]]; then
        if [ -f \${CONFIG_FILE} ]; then
            echo -e "\n\${BLUE}--- اطلاعات کانفیگ فعلی سرور ---\${NC}"
            if command -v jq &>/dev/null; then cat \${CONFIG_FILE} | jq .; else cat \${CONFIG_FILE}; fi
            echo -e "\${BLUE}--------------------------------\${NC}"
        else
            echo -e "\${L_RED}اطلاعاتی یافت نشد. لطفاً ابتدا تونل را نصب کنید.\${NC}"
        fi
    else
        if [ -f \${CONFIG_FILE} ]; then
            local local_port=\$(cat \${CONFIG_FILE} | jq -r '.local_port')
            echo -e "\n\${BLUE}==================================================================\${NC}"
            echo -e "\${CYAN}      اطلاعات اتصال شما      \${NC}"
            echo -e "\${BLUE}==================================================================\${NC}"
            echo -e "\${GREEN}آدرس پراکسی:\${NC} \${YELLOW}آدرس IP سرور ایران شما\${NC}"
            echo -e "\${GREEN}پورت پراکسی:\${NC} \${YELLOW}\${local_port}\${NC}"
            echo -e "\${GREEN}پروتکل:\${NC} \${YELLOW}SOCKS5\${NC}"
            echo -e "\${BLUE}==================================================================\${NC}\n"
        else
            echo -e "\${L_RED}اطلاعاتی یافت نشد. لطفاً ابتدا تونل را نصب کنید.\${NC}"
        fi
    fi
}

# حلقه اصلی منو
while true; do
    clear
    echo -e "\${CYAN}===========================================\${NC}"
    echo -e "\${YELLOW}   $menu_title   \${NC}"
    echo -e "\${CYAN}===========================================\${NC}"
    echo -e " 1. نصب یا بروزرسانی تونل"
    echo -e " 2. تغییر تنظیمات"
    echo -e " 3. نمایش اطلاعات اتصال"
    echo -e " 4. حذف کامل تونل"
    echo -e " 5. مشاهده لاگ‌ها (برای خروج CTRL+C را بزنید)"
    echo -e " 6. بررسی وضعیت سرویس"
    echo -e " 7. راه‌اندازی مجدد"
    echo -e " 8. خروج"
    echo -e "\${CYAN}===========================================\${NC}"
    read -p "لطفاً یک گزینه را انتخاب کنید: " choice
    if ! [[ "\$choice" =~ ^[0-9]+$ ]]; then
        choice=-1
    fi
    case \$choice in
        1|2) configure_tunnel ;;
        3) show_connection_info ;;
        4) uninstall ;;
        5) show_logs ;;
        6) show_status ;;
        7) restart_service ;;
        8) exit 0 ;;
        *) echo -e "\${L_RED}انتخاب نامعتبر است. لطفاً دوباره تلاش کنید.\${NC}" ; sleep 2 ;;
    esac
    read -n 1 -s -r -p "برای بازگشت به منو، هر کلیدی را فشار دهید..."
done
EOF
    # --- END OF SCRIPT GENERATION ---

    chmod +x "$script_path"
    clear
    bash "$script_path"
    rm -f "$script_path" &>/dev/null
    log_message "INFO" "مدیر تونل برای پروتکل $protocol و نقش $role اجرا شد."
    read -n 1 -s -r -p $'\nبرای ادامه، کلیدی را فشار دهید...'
}

manage_irnet_tunnel() {
    while true; do
        clear
        echo -e "${B_CYAN}--- مدیریت تانل IRNET (مبتنی بر GOST) ---${C_RESET}\n"
        echo -e "${C_WHITE}لطفاً پروتکل مورد نظر خود را برای ایجاد تونل انتخاب کنید:${C_RESET}"
        echo -e "${B_BLUE}-------------------------------------------------${C_RESET}"
        echo -e "${C_YELLOW}1) ${C_WHITE}پروتکل H2 (استاندارد و سریع)"
        echo -e "${C_YELLOW}2) ${C_WHITE}پروتکل QUIC (پایداری بیشتر در شبکه ضعیف)"
        echo -e "${C_YELLOW}3) ${C_WHITE}پروتکل VLESS (حالت پنهان‌کاری، نیاز به دامنه)"
        echo -e "${B_BLUE}-------------------------------------------------${C_RESET}"
        echo -e "${C_YELLOW}4) ${C_WHITE}بازگشت به منوی اصلی"
        echo -e "${B_BLUE}-------------------------------------------------${C_RESET}"
        
        printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"
        read -r protocol_choice
        
        local protocol=""
        case $protocol_choice in
            1) protocol="h2" ;;
            2) protocol="quic" ;;
            3) protocol="vless" ;;
            4) return ;;
            *)
                echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}"; sleep 1; continue ;;
        esac

        clear
        echo -e "${B_CYAN}--- انتخاب نقش سرور برای پروتکل ${protocol^^} ---${C_RESET}\n"
        echo -e "${C_WHITE}این سرور چه نقشی در تونل دارد؟${C_RESET}"
        echo -e "${C_YELLOW}1) ${C_WHITE}سرور خارج (مقصد)"
        echo -e "${C_YELLOW}2) ${C_WHITE}سرور ایران (مبدأ)"
        echo -e "${C_YELLOW}3) ${C_WHITE}بازگشت به انتخاب پروتکل"
        echo -e "${B_BLUE}-------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"
        read -r role_choice

        local role=""
        case $role_choice in
            1) role="kharej" ;;
            2) role="iran" ;;
            3) continue ;;
            *)
                echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}"; sleep 1; continue ;;
        esac
        
        run_tunnel_manager "$role" "$protocol"
    done
}
# --- MAIN MENUS ---

manage_network_optimization() {
    while true; do
        clear
        echo -e "${B_CYAN}--- بهینه سازی شبکه و اتصال ---${C_RESET}\n"
        echo -e "${C_YELLOW}1) ${C_WHITE}مدیریت بهینه سازهای TCP (BBR, HYBLA, CUBIC)"
        echo -e "${C_YELLOW}2) ${C_WHITE}قابلیت خاموش و روشن کردن پینگ سرور"
        echo -e "${C_YELLOW}3) ${C_WHITE}رفع مشکل تاریخ واتس‌اپ"
        echo -e "${B_BLUE}-----------------------------------${C_RESET}"
        echo -e "${C_YELLOW}4) ${C_WHITE}بهینه سازی سرعت (TC)"
        echo -e "${C_YELLOW}5) ${B_YELLOW}بهینه سازی بستر شبکه (پیشرفته)"
        echo -e "${C_YELLOW}6) ${C_WHITE}مدیریت و یافتن بهترین DNS"
        echo -e "${C_YELLOW}7) ${C_WHITE}یافتن سریعترین مخزن APT (پیشرفته)"
        echo -e "${C_YELLOW}8) ${C_WHITE}تست پینگ سرورهای DNS"
        echo -e "${C_YELLOW}9) ${C_WHITE}پینگ خارج به داخل"
        echo -e "${C_YELLOW}10) ${C_WHITE}پینگ داخل به خارج"
        echo -e "${C_YELLOW}11) ${B_WHITE}تست پکت لاست بین سرور (MTR)"
        echo -e "${C_YELLOW}12) ${C_WHITE}تست سرعت خودکار ایران و خارج (IPERF3)"
        echo -e "${C_YELLOW}13) ${B_GREEN}دی ان اس رفع تحریم داخلی"
        echo -e "${C_YELLOW}14) ${C_WHITE}بازگشت به منوی اصلی"
        echo -e "${B_BLUE}-----------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"
        read -r choice

        if ! [[ "$choice" =~ ^[0-9]+$ ]]; then
            choice=-1
        fi

        case $choice in
            1) manage_tcp_optimizers ;;
            2) manage_server_ping ;;
            3) fix_whatsapp_time ;;
            4) manage_tc_script ;;
            5) run_as_bbr_optimization ;;
            6) manage_dns ;;
            7) advanced_mirror_test ;;
            8) ping_test_ips ;;
            9) ping_iran_hosts ;;
            10) ping_external_hosts ;;
            11) run_packet_loss_test ;;
            12) run_iperf3_test ;;
            13) manage_sanction_dns ;;
            14) return ;;
            *) echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}"; sleep 1 ;;
        esac
    done
}

manage_ssh_port() {
    clear
    local sshd_config="/etc/ssh/sshd_config"
    echo -e "${B_CYAN}--- تغییر پورت SSH ---${C_RESET}\n"
    
    local current_port
    current_port=$(grep -i "^#*port" "$sshd_config" | tail -n 1 | awk '{print $2}')
    echo -e "${C_WHITE}پورت SSH فعلی: ${C_GREEN}${current_port:-22}${C_RESET}"
    
    printf "%b" "${B_MAGENTA}پورت جدید SSH را وارد کنید (یا برای لغو ENTER بزنید): ${C_RESET}"
    read -r new_port

    if [ -z "$new_port" ]; then
        log_message "INFO" "عملیات تغییر پورت لغو شد."
    elif ! [[ "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -lt 1 ] || [ "$new_port" -gt 65535 ]; then
        log_message "ERROR" "شماره پورت نامعتبر است. باید عددی بین 1 و 65535 باشد."
    else
        log_message "INFO" "در حال تغییر پورت به ${new_port}..."
        create_backup "$sshd_config"
        
        sed -i -E 's/^[ ]*#?[ ]*Port[ ].*/#&/' "$sshd_config"
        echo "Port ${new_port}" >> "$sshd_config"
        
        log_message "SUCCESS" "پورت در فایل کانفیگ SSH تغییر یافت."
        
        if command -v ufw &> /dev/null && ufw status | grep -q "Status: active"; then
            log_message "INFO" "فایروال UFW فعال است. در حال افزودن قانون برای پورت ${new_port}..."
            ufw allow "${new_port}/tcp"
        fi

        systemctl restart sshd
        check_service_status "sshd"
        
        echo -e "\n${B_YELLOW}**مهم:** لطفاً اتصال SSH خود را با پورت جدید (${new_port}) تست کنید قبل از اینکه این ترمینال را ببندید.${C_RESET}"
    fi
    
    read -n 1 -s -r -p $'\nبرای ادامه، کلیدی را فشار دهید...'
}

manage_xray_auto_restart() {
    clear
    echo -e "${B_CYAN}--- ریستارت خودکار سرویس XRAY ---${C_RESET}\n"

    local xray_service=""
    local possible_services=("xray.service" "x-ui.service" "tx-ui.service")

    for service in "${possible_services[@]}"; do
        if systemctl list-units --full -all | grep -q "${service}"; then
            xray_service=$service
            log_message "INFO" "سرویس فعال XRAY یافت شد: ${xray_service}"
            break
        fi
    done

    if [ -z "$xray_service" ]; then
        log_message "ERROR" "هیچ سرویس XRAY یا پنل شناخته شده‌ای روی سرور شما یافت نشد."
        read -n 1 -s -r -p "برای ادامه، کلیدی را فشار دهید..."
        return
    fi
    
    echo -e "${C_WHITE}سرویس فعال شناسایی شده: ${B_GREEN}${xray_service}${C_RESET}\n"
    echo -e "${C_YELLOW}1)${C_WHITE} افزودن CRON JOB برای ریستارت هر 15 دقیقه"
    echo -e "${C_YELLOW}2)${C_WHITE} افزودن CRON JOB برای ریستارت هر 30 دقیقه"
    echo -e "${C_YELLOW}3)${C_RED} حذف CRON JOB ریستارت خودکار XRAY"
    echo -e "${C_YELLOW}4)${C_WHITE} بازگشت به منوی امنیت"
    echo -e "${B_BLUE}-----------------------------------${C_RESET}"
    printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"
    read -r choice

    if ! [[ "$choice" =~ ^[0-9]+$ ]]; then
        choice=-1
    fi

    case $choice in
        1)
            (crontab -l 2>/dev/null | grep -v "systemctl restart ${xray_service}"; echo "*/15 * * * * systemctl restart ${xray_service}") | crontab -
            log_message "SUCCESS" "ریستارت خودکار سرویس ${xray_service} هر 15 دقیقه یک‌بار تنظیم شد."
            ;;
        2)
            (crontab -l 2>/dev/null | grep -v "systemctl restart ${xray_service}"; echo "*/30 * * * * systemctl restart ${xray_service}") | crontab -
            log_message "SUCCESS" "ریستارت خودکار سرویس ${xray_service} هر 30 دقیقه یک‌بار تنظیم شد."
            ;;
        3)
            crontab -l | grep -v "systemctl restart ${xray_service}" | crontab -
            log_message "SUCCESS" "ریبوت خودکار برای سرویس ${xray_service} حذف شد."
            ;;
        4) return ;;
        *) echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}" ;;
    esac
    read -n 1 -s -r -p "برای ادامه، کلیدی را فشار دهید..."
}

manage_security() {
    while true; do
        clear
        echo -e "${B_CYAN}--- امنیت و دسترسی ---${C_RESET}\n"
        echo -e "${C_YELLOW}1) ${C_WHITE}مدیریت فایروال (UFW)"
        echo -e "${C_YELLOW}2) ${C_WHITE}مدیریت ورود کاربر روت"
        echo -e "${C_YELLOW}3) ${C_WHITE}تغییر پورت SSH"
        echo -e "${C_YELLOW}4) ${B_GREEN}ریستارت خودکار XRAY"
        echo -e "${C_YELLOW}5) ${C_WHITE}مدیریت ریبوت خودکار سرور"
        echo -e "${C_YELLOW}6) ${C_WHITE}فعال/غیرفعال کردن IPV6"
        echo -e "${C_YELLOW}7) ${C_WHITE}اسکنر پورت"
        echo -e "${C_YELLOW}8) ${C_WHITE}اسکن رنج آروان کلود"
        echo -e "${C_YELLOW}9) ${C_WHITE}تشخیص سالم بودن آی پی"
        echo -e "${C_YELLOW}10) ${C_WHITE}اسکن اندپوینت های WARP"
        echo -e "${C_YELLOW}11) ${C_WHITE}بازگشت به منوی اصلی"
        echo -e "${B_BLUE}-----------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"
        read -r choice

        if ! [[ "$choice" =~ ^[0-9]+$ ]]; then
            choice=-1
        fi

        case $choice in
            1) manage_firewall ;;
            2) manage_ssh_root ;;
            3) manage_ssh_port ;;
            4) manage_xray_auto_restart ;;
            5) manage_reboot_cron ;;
            6) manage_ipv6 ;;
            7) port_scanner_menu ;;
            8) scan_arvan_ranges ;;
            9) manage_ip_health_check ;;
            10) scan_warp_endpoints ;;
            11) return ;;
            *) echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}"; sleep 1 ;;
        esac
    done
}


# --- SCRIPT MAIN LOOP ---
check_dependencies_at_start() {
    local missing=""
    command -v curl >/dev/null 2>&1 || missing+=" CURL"
    command -v wget >/dev/null 2>&1 || missing+=" WGET"
    command -v bc >/dev/null 2>&1 || missing+=" BC"
    command -v jq >/dev/null 2>&1 || missing+=" JQ"
    command -v lsb_release >/dev/null 2>&1 || missing+=" LSB-RELEASE"
    command -v iptables >/dev/null 2>&1 || missing+=" IPTABLES"
    command -v uuidgen >/dev/null 2>&1 || missing+=" UUID-RUNTIME"

    if [ -n "$missing" ]; then
        echo -e "${R}بسته‌های پیش‌نیاز یافت نشدند:$missing${N}"
        echo -e "لطفاً با دستور 'apt install$missing' آنها را نصب کنید یا از گزینه 3 منوی اصلی استفاده کنید."
        read -n 1 -s -r -p "برای خروج کلیدی را فشار دهید..."
        exit 1
    fi
}

# --- SCRIPT ENTRY POINT ---
main() {
    init_environment
    check_dependencies_at_start
    clear
    progress_bar "درحال بارگذاری اسکریپت..." 2

    while true; do
      clear
      show_banner
      show_enhanced_system_status

      echo -e "   ${C_YELLOW}1) ${B_CYAN}بهینه سازی شبکه و اتصال"
      echo -e "   ${C_YELLOW}2) ${B_CYAN}امنیت و دسترسی"
      echo -e "   ${C_YELLOW}3) ${C_WHITE}آپدیت و نصب پکیج های لازم"
      echo -e "   ${C_YELLOW}4) ${B_GREEN}نصب آفلاین پنل TX-UI"
      echo -e "   ${C_YELLOW}5) ${B_CYAN}تانل ایرنت (IRNET TUNNEL)"
      echo -e "   ${C_YELLOW}6) ${B_CYAN}تانل رت هول بهینه ایران"
      echo ""
      echo -e "   ${C_YELLOW}7) ${C_RED}خروج"
      echo -e "${B_BLUE}------------------------------------------------------------${C_RESET}"
      printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"
      read -r main_choice

      if ! [[ "$main_choice" =~ ^[0-9]+$ ]]; then
          main_choice=-1
      fi

      case $main_choice in
        1) manage_network_optimization ;;
        2) manage_security ;;
        3) install_core_packages ;;
        4) manage_xui_offline_install ;;
        5) manage_irnet_tunnel ;;
        6) manage_rat_hole_tunnel ;;
        7)
          clear
          log_message "INFO" "خروج از اسکریپت."
          echo -e "\n${B_CYAN}خدا نگهدار!${C_RESET}\n"
          exit 0
          ;;
        *)
          echo -e "\n${C_RED}گزینه نامعتبر است! لطفاً عددی بین 1 تا 7 وارد کنید.${C_RESET}"
          read -n 1 -s -r -p "برای ادامه، کلیدی را فشار دهید..."
          ;;
      esac
    done
}

main "$@"
