#!/bin/bash

# CHECK FOR ROOT USER
if [ "$(id -u)" -ne 0 ]; then
  echo "این اسکریپت باید با دسترسی ریشه (ROOT) اجرا شود."
  echo "لطفاً از دستور 'sudo bash MENU-FA.sh' استفاده کنید."
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
# --- START OF CORE FRAMEWORK ---
# #############################################################################

readonly LOG_FILE="/var/log/network_optimizer.log"
readonly BACKUP_DIR="/var/backups/network_optimizer"
readonly CONFIG_DIR="/etc/irnet" # DIRECTORY FOR PERSISTENT CONFIGS
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
    # CONVERT MESSAGE TO UPPERCASE
    local upper_message="${message^^}"
    local log_line="[$timestamp] [$level] $upper_message"
    printf "%s%s%s\n" "$color" "$log_line" "$C_RESET" | tee -a "$LOG_FILE"
}

create_backup() {
    local file_path="$1"
    if [ ! -f "$file_path" ]; then
        log_message "INFO" "FILE $file_path NOT FOUND FOR BACKUP, SKIPPING."
        return 1
    fi
    local backup_name
    printf -v backup_name '%s.bak.%(%s)T' "$(basename "$file_path")" -1
    if cp -f "$file_path" "$BACKUP_DIR/$backup_name" 2>/dev/null; then
        log_message "SUCCESS" "BACKUP OF $file_path CREATED AT $BACKUP_DIR/$backup_name."
        echo "$BACKUP_DIR/$backup_name"
        return 0
    else
        log_message "ERROR" "BACKUP FAILED FOR $file_path."
        return 1
    fi
}

restore_backup() {
    local original_file="$1"
    local backup_file="$2"
    if cp -f "$backup_file" "$original_file" 2>/dev/null; then
        log_message "SUCCESS" "FILE $original_file RESTORED FROM BACKUP."
        return 0
    else
        log_message "ERROR" "FAILED TO RESTORE FROM BACKUP."
        return 1
    fi
}

check_service_status() {
    local service_name="$1"
    if systemctl is-active --quiet "$service_name"; then
        log_message "SUCCESS" "SERVICE $service_name IS ACTIVE AND RUNNING."
    else
        log_message "ERROR" "SERVICE $service_name FAILED TO RUN. PLEASE CHECK MANUALLY: SYSTEMCTL STATUS $service_name"
    fi
}

handle_interrupt() {
    log_message "WARN" "SCRIPT INTERRUPTED. CLEANING UP..."
    stty sane # RESTORE TERMINAL SETTINGS ON EXIT
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

    mkdir -p "$BACKUP_DIR" "$(dirname "$LOG_FILE")" "$CONFIG_DIR" 2>/dev/null
    chmod 700 "$BACKUP_DIR" "$CONFIG_DIR" 2>/dev/null
    : >> "$LOG_FILE"
    chmod 640 "$LOG_FILE" 2>/dev/null

    trap 'handle_interrupt' INT TERM

    PRIMARY_INTERFACE=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
}
# #############################################################################
# --- END OF CORE FRAMEWORK ---
# #############################################################################
# --- HEADER AND BANNER ---
show_banner() {
    echo -e "${B_BLUE}║${B_CYAN}  مدیریت جامع بهینه سازی لینوکس اوبونتو${B_BLUE}     ${C_RESET}"
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
        echo "DISABLED"
    else
        echo "ENABLED"
    fi
}

check_ping_status() {
    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
        # CHECK FOR OUR SPECIFIC RULE IN UFW CHAIN OR THE MAIN INPUT CHAIN
        if iptables -C ufw-before-input -p icmp --icmp-type echo-request -j DROP &>/dev/null || \
           iptables -C INPUT -p icmp --icmp-type echo-request -j DROP &>/dev/null || \
           ip6tables -C ufw6-before-input -p icmpv6 --icmpv6-type echo-request -j DROP &>/dev/null || \
           ip6tables -C INPUT -p icmpv6 --icmpv6-type echo-request -j DROP &>/dev/null; then
            echo "BLOCKED"
        else
            echo "ALLOWED"
        fi
    else
        # IF UFW IS NOT ACTIVE, PING IS ALLOWED BY DEFAULT
        echo "ALLOWED"
    fi
}

is_valid_ip() {
    local ip="$1"
    if [[ "$ip" =~ ^([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}$ || "$ip" =~ ^(([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])) || "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 0
    else
        return 1
    fi
}
# --- SYSTEM STATUS ---
show_enhanced_system_status() {
    get_visual_length() {
        local clean_string
        clean_string=$(echo -e "$1" | sed 's/\x1b\[[0-9;]*m//g')
        echo -n "$clean_string" | wc -m
    }

    # --- START: PARALLEL NETWORK CHECKS WITH LOCAL FALLBACK ---
    local TMP_IPV4="/tmp/public_ipv4_$$"
    local TMP_IPV6="/tmp/public_ipv6_$$"
    local TMP_ISP="/tmp/public_isp_$$"
    
    # RUN NETWORK CHECKS IN THE BACKGROUND SIMULTANEOUSLY
    curl -s -4 --connect-timeout 3 ip.sb > "$TMP_IPV4" &
    curl -s -6 --connect-timeout 3 ip.sb > "$TMP_IPV6" &
    curl -s -4 --connect-timeout 3 ip.sb/isp > "$TMP_ISP" &

    # WAIT FOR ALL BACKGROUND JOBS TO COMPLETE
    wait
    
    local public_ipv4
    public_ipv4=$(cat "$TMP_IPV4")
    local public_ipv6
    public_ipv6=$(cat "$TMP_IPV6")
    local provider
    provider=$(cat "$TMP_ISP")
    
    # CLEAN UP TEMPORARY FILES
    rm -f "$TMP_IPV4" "$TMP_IPV6" "$TMP_ISP"
    
    # --- FALLBACK LOGIC: IF CURL FAILS, GET IP LOCALLY ---
    if [[ -z "$public_ipv4" ]]; then
        public_ipv4=$(ip -4 addr show "$PRIMARY_INTERFACE" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
        [ -z "$public_ipv4" ] && public_ipv4="N/A"
    fi
    
    if [[ -z "$public_ipv6" ]]; then
        public_ipv6=$(ip -6 addr show "$PRIMARY_INTERFACE" 2>/dev/null | grep -oP '(?<=inet6\s)[\da-f:]+(?=\/)' | grep -vi 'fe80')
        [ -z "$public_ipv6" ] && public_ipv6="N/A"
    fi
    
    [ -z "$provider" ] && provider="N/A"
    # --- END: FALLBACK LOGIC ---


    # USE A WIDER CUT FOR CPU MODEL TO PREVENT AWKWARD WRAPPING
    local cpu_model
    cpu_model=$(grep "model name" /proc/cpuinfo | head -1 | cut -d':' -f2 | sed 's/^ *//' | cut -c1-45)
    local cpu_cores
    cpu_cores=$(nproc)
    local cpu_usage
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1 2>/dev/null || echo "N/A")
    local mem_total
    mem_total=$(free -h | grep "Mem:" | awk '{print $2}')
    local mem_used
    mem_used=$(free -h | grep "Mem:" | awk '{print $3}')
    local mem_percent
    mem_percent=$(free | grep "Mem:" | awk '{printf "%.0f", ($3/$2)*100.0}')
    local load_avg
    load_avg=$(uptime | awk -F'load average:' '{print $2}' | sed 's/^ *//' | cut -d',' -f1)
    local uptime_str
    uptime_str=$(uptime -p 2>/dev/null | sed 's/up //')
    local ipv6_status_val
    ipv6_status_val=$(check_ipv6_status)
    local ping_status_val
    ping_status_val=$(check_ping_status)
    local ubuntu_version
    ubuntu_version=$(lsb_release -sr 2>/dev/null || echo 'N/A')
    
    local current_mirror_uri
    if [[ -f /etc/apt/sources.list.d/ubuntu.sources ]]; then
        current_mirror_uri=$(grep -m1 "^URIs:" /etc/apt/sources.list.d/ubuntu.sources 2>/dev/null | awk '{print $2}')
    else
        current_mirror_uri=$(grep -m1 -oP '^(deb|deb-src)\s+\K(https?://[^\s]+)' /etc/apt/sources.list 2>/dev/null)
    fi
    local current_mirror_host
    if [[ -n "$current_mirror_uri" ]]; then
        current_mirror_host=$(echo "$current_mirror_uri" | awk -F/ '{print $3}')
    else
        current_mirror_host="N/A"
    fi

    local private_ips
    private_ips=$(ip -o addr show | awk '{print $4}' | cut -d/ -f1 | grep -E '(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)' | tr '\n' ' ' | xargs)
    [ -z "$private_ips" ] && private_ips="N/A"
    
    local dns_servers
    if command -v resolvectl &>/dev/null && systemctl is-active --quiet systemd-resolved; then
        dns_servers=$(resolvectl status | grep "DNS Servers" | grep -v '127.0.0.53' | awk '{for(i=3; i<=NF; i++) print $i}' | tr '\n' ' ' | xargs)
    fi
    if [[ -z "$dns_servers" ]]; then
        dns_servers=$(grep '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' | grep -v '127.0.0.53' | tr '\n' ' ' | xargs)
    fi
    [ -z "$dns_servers" ] && dns_servers="N/A"

    local ipv6_display="$ipv6_status_val"
    [[ "$ipv6_status_val" == "ENABLED" ]] && ipv6_display="${G}${ipv6_display}${N}" || ipv6_display="${R}${ipv6_display}${N}"
    local ping_display="$ping_status_val"
    [[ "$ping_status_val" == "ALLOWED" ]] && ping_display="${G}${ping_display}${N}" || ping_display="${R}${ping_display}${N}"

    local labels=( "CPU" "PERFORMANCE" "MEMORY" "UPTIME" "IPV6 STATUS" "PING STATUS" "DNS" "PROVIDER" "APT MIRROR" "UBUNTU VERSION" "PRIVATE IP(S)" "PUBLIC IPV4" "PUBLIC IPV6" )
    
    local cpu_model_upper="${cpu_model^^}"
    local uptime_str_upper="${uptime_str^^}"
    local provider_upper="${provider^^}"
    local current_mirror_host_upper="${current_mirror_host^^}"
    
    local values=(
        "$cpu_model_upper"
        "CORES: ${G}${cpu_cores}${N} | USAGE: ${Y}${cpu_usage}%${N} | LOAD: ${C}${load_avg}${N}"
        "${B}${mem_used^^}${N} / ${C}${mem_total^^}${N} (${Y}${mem_percent}%${N})"
        "$uptime_str_upper"
        "$ipv6_display"
        "$ping_display"
        "$dns_servers"
        "$provider_upper"
        "$current_mirror_host_upper"
        "${C}${ubuntu_version}${N}"
        "${G}${private_ips}${N}"
        "${G}${public_ipv4}${N}"
        "${G}${public_ipv6}${N}"
    )

    local max_label_len=0
    for label in "${labels[@]}"; do
        (( ${#label} > max_label_len )) && max_label_len=${#label}
    done
    
    local terminal_width
    terminal_width=$(tput cols 2>/dev/null || echo 80)
    local max_value_width=$(( terminal_width - max_label_len - 7 ))
    [[ $max_value_width -lt 20 ]] && max_value_width=20

    printf "${B_BLUE}╔%s╗\n" "$(printf '═%.0s' $(seq 1 $((max_label_len + max_value_width + 5)) ))"
    for i in "${!labels[@]}"; do
        local label="${labels[$i]}"
        local value="${values[$i]}"
        local clean_value
        clean_value=$(echo -e "$value" | sed 's/\x1b\[[0-9;]*m//g')
        
        if (( ${#clean_value} > max_value_width )); then
            local value_part
            value_part=$(echo -e "${value}" | cut -c 1-$((max_value_width - 3)))
            value="${value_part}...${N}"
        fi
        
        local visual_value_len
        visual_value_len=$(get_visual_length "$value")
        
        printf "${B_BLUE}║${C_WHITE} %s" "$label"
        printf "%*s" "$((max_label_len - ${#label}))" ""
        
        printf " ${B_BLUE}│${C_CYAN} %s" "$value"

        local padding=$(( max_value_width - visual_value_len ))
        [[ $padding -lt 0 ]] && padding=0
        printf "%*s" "$padding" ""
        
        printf " ${B_BLUE}║\n"
    done
    printf "${B_BLUE}╚%s╝\n" "$(printf '═%.0s' $(seq 1 $((max_label_len + max_value_width + 5)) ))"
}
# #############################################################################
# --- NETWORK OPTIMIZER CORE ---
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
            log_message "ERROR" "TIMEOUT WAITING FOR PACKAGE MANAGER."
            log_message "ERROR" "PLEASE MANUALLY KILL THE APT/DPKG PROCESS AND TRY AGAIN."
            return 1
        fi
        if [[ $((waited % 30)) -eq 0 ]]; then
            log_message "WARN" "PACKAGE MANAGER IS LOCKED. WAITING... (${waited}S/${max_wait}S)"
        fi
        sleep 5
        waited=$((waited + 5))
    done
    return 0
}

reset_environment() {
    log_message "INFO" "RESETTING ENVIRONMENT AFTER PACKAGE INSTALLATION..."
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
    
    log_message "WARN" "IF PACKAGE MANAGER ISSUES PERSIST, A MANUAL PROCESS CHECK OR REBOOT MIGHT BE REQUIRED."

    sleep 3
    log_message "SUCCESS" "ENVIRONMENT RESET COMPLETED."
    if ! test_environment_health; then
        suggest_reconnection
        return 1
    fi
    return 0
}

test_environment_health() {
    log_message "INFO" "TESTING ENVIRONMENT HEALTH..."
    local test_commands=("ping" "dig" "ethtool" "ip" "sysctl")
    local failed_commands=()
    for cmd in "${test_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            failed_commands+=("$cmd")
        fi
    done
    if ! echo "test" >/dev/null 2>&1; then
        log_message "WARN" "TERMINAL OUTPUT TEST FAILED."
        return 1
    fi
    if ! touch "/tmp/netopt_test_$$" 2>/dev/null; then
        log_message "WARN" "FILE SYSTEM ACCESS TEST FAILED."
        return 1
    fi
    rm -f "/tmp/netopt_test_$$" 2>/dev/null
    if [[ "${#failed_commands[@]}" -gt 0 ]]; then
        log_message "WARN" "SOME COMMANDS NOT FOUND: ${failed_commands[*]}"
        return 1
    fi
    log_message "SUCCESS" "ENVIRONMENT HEALTH CHECK PASSED."
    return 0
}

suggest_reconnection() {
    printf "\n%s╔════════════════════════════════════════════════════════╗%s\n" "$C_RED" "$C_RESET"
    printf "%s║                    ATTENTION REQUIRED                 ║%s\n" "$C_RED" "$C_RESET"
    printf "%s╚════════════════════════════════════════════════════════╝%s\n\n" "$C_RED" "$C_RESET"
    log_message "WARN" "ENVIRONMENTAL ISSUES DETECTED AFTER PACKAGE INSTALLATION."
    printf "%sFOR OPTIMAL PERFORMANCE, PLEASE:%s\n\n" "$C_YELLOW" "$C_RESET"
    printf "%s1. %sPRESS CTRL+C TO EXIT THIS SCRIPT%s\n" "$C_CYAN" "$C_WHITE" "$C_RESET"
    printf "%s2. %sRECONNECT YOUR SSH SESSION%s\n" "$C_CYAN" "$C_WHITE" "$C_RESET"
    printf "%s3. %sRUN THE SCRIPT AGAIN%s\n\n" "$C_CYAN" "$C_WHITE" "$C_RESET"
    printf "%sTHIS ENSURES ALL ENVIRONMENT CHANGES TAKE EFFECT PROPERLY.%s\n\n" "$C_YELLOW" "$C_RESET"
    local countdown=30
    while [[ $countdown -gt 0 ]]; do
        printf "\r%sCONTINUING ANYWAY IN %d SECONDS (PRESS CTRL+C TO EXIT)...%s" "$C_YELLOW" "$countdown" "$C_RESET"
        sleep 1
        ((countdown--))
    done
    printf "\n\n"
    printf "%b" "${C_YELLOW}CONTINUE WITH POTENTIAL ISSUES? (Y/N): ${C_RESET}"
    read -e -r choice
    if [[ ! "$choice" =~ ^[Yy]$ ]]; then
        log_message "INFO" "SCRIPT PAUSED FOR SSH RECONNECTION. PLEASE RUN AGAIN AFTER RECONNECTING."
        exit 0
    fi
    log_message "WARN" "CONTINUING DESPITE ENVIRONMENT ISSUES..."
}

# [+] CONSOLIDATED DEPENDENCY INSTALLER (MODIFIED TO INCLUDE NEW TOOLS)
install_dependencies() {
    log_message "INFO" "CHECKING AND INSTALLING REQUIRED DEPENDENCIES..."
    if ! check_internet_connection; then
        log_message "ERROR" "NO INTERNET CONNECTION AVAILABLE."
        return 1
    fi

    local deps=("curl" "wget" "socat" "ethtool" "net-tools" "dnsutils" "mtr-tiny" "iperf3" "jq" "bc" "lsb-release" "netcat-openbsd" "nmap" "fping" "uuid-runtime" "iptables-persistent" "python3" "python3-pip" "fail2ban" "chkrootkit" "unzip" "rkhunter" "lynis" "htop" "btop" "ncdu" "iftop" "git" "certbot" "xtables-addons-common" "geoip-database" "gnupg")
    local missing_deps=()
    
    for dep in "${deps[@]}"; do
        local cmd_name="$dep"
        [[ "$dep" == "dnsutils" ]] && cmd_name="dig"
        [[ "$dep" == "net-tools" ]] && cmd_name="ifconfig"
        [[ "$dep" == "mtr-tiny" ]] && cmd_name="mtr"
        [[ "$dep" == "netcat-openbsd" ]] && cmd_name="nc"
        [[ "$dep" == "uuid-runtime" ]] && cmd_name="uuidgen"
        [[ "$dep" == "iptables-persistent" ]] && cmd_name="netfilter-persistent"
        [[ "$dep" == "xtables-addons-common" ]] && cmd_name="xtables-addons-info"


        if ! command -v "$cmd_name" &>/dev/null; then
            if [[ "$dep" == "netcat-openbsd" ]] && (command -v "ncat" >/dev/null || command -v "netcat" >/dev/null); then
                continue
            fi
            missing_deps+=("$dep")
        fi
    done

    if [[ "${#missing_deps[@]}" -gt 0 ]]; then
        log_message "WARN" "INSTALLING MISSING DEPENDENCIES: ${missing_deps[*]}"
        if ! wait_for_dpkg_lock; then
            log_message "ERROR" "COULD NOT ACQUIRE PACKAGE LOCK."
            return 1
        fi

        apt-get update -qq
        
        if ! DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" "${missing_deps[@]}"; then
            log_message "ERROR" "FAILED TO INSTALL SOME DEPENDENCIES. PLEASE TRY INSTALLING THEM MANUALLY."
            return 1
        else
            log_message "SUCCESS" "DEPENDENCIES INSTALLED SUCCESSFULLY."
            if ! reset_environment; then
                return 1
            fi
        fi
    else
        log_message "INFO" "ALL DEPENDENCIES ARE ALREADY INSTALLED."
    fi
    return 0
}

fix_etc_hosts() {
    local host_path="${1:-/etc/hosts}"
    local hostname_cached
    log_message "INFO" "STARTING TO FIX THE HOSTS FILE..."
    hostname_cached=$(hostname 2>/dev/null || echo "localhost")
    local backup_path
    if ! backup_path=$(create_backup "$host_path"); then
        log_message "ERROR" "FAILED TO CREATE BACKUP OF HOSTS FILE."
        return 1
    fi
    if lsattr "$host_path" 2>/dev/null | grep -q 'i'; then
        log_message "WARN" "FILE $host_path IS IMMUTABLE. ATTEMPTING TO MAKE IT MUTABLE..."
        if ! chattr -i "$host_path" 2>/dev/null; then
            log_message "ERROR" "FAILED TO REMOVE IMMUTABLE ATTRIBUTE."
            return 1
        fi
    fi
    if [[ ! -w "$host_path" ]]; then
        log_message "ERROR" "CANNOT WRITE TO $host_path. CHECK PERMISSIONS."
        return 1
    fi
    if ! grep -q "$hostname_cached" "$host_path" 2>/dev/null; then
        local hostname_entry="127.0.1.1 $hostname_cached"
        if printf '%s\n' "$hostname_entry" >> "$host_path"; then
            log_message "SUCCESS" "HOSTNAME ENTRY ADDED TO HOSTS FILE."
        else
            log_message "ERROR" "FAILED TO ADD HOSTNAME ENTRY."
            restore_backup "$host_path" "$backup_path"
            return 1
        fi
    else
        log_message "INFO" "HOSTNAME ENTRY ALREADY PRESENT."
    fi
    return 0
}

apply_dns_persistent() {
    local dns1="$1"
    local dns2="$2"
    local dns_list_str="$dns1"
    [[ -n "$dns2" ]] && dns_list_str+=" $dns2"

    if [[ -z "$dns1" ]]; then
        log_message "INFO" "RESETTING DNS TO SYSTEM DEFAULT..."
    else
        log_message "INFO" "APPLYING PERSISTENT DNS: $dns_list_str"
    fi

    if command -v resolvectl &>/dev/null && systemctl is-active --quiet systemd-resolved; then
        if [[ -z "$PRIMARY_INTERFACE" ]]; then
            log_message "ERROR" "COULD NOT DETECT PRIMARY NETWORK INTERFACE FOR RESOLVECTL."
            return 1
        fi
        log_message "INFO" "USING SYSTEMD-RESOLVED ON INTERFACE '$PRIMARY_INTERFACE'..."
        if resolvectl dns "$PRIMARY_INTERFACE" $dns_list_str; then
             log_message "SUCCESS" "DNS FOR '$PRIMARY_INTERFACE' SET VIA RESOLVECTL."
             systemctl restart systemd-resolved
             return 0
        else
             log_message "ERROR" "FAILED TO SET DNS VIA RESOLVECTL."
             return 1
        fi
    fi

    if command -v nmcli &>/dev/null && systemctl is-active --quiet NetworkManager; then
        local conn_name
        conn_name=$(nmcli -t -f NAME,DEVICE con show --active | head -n 1 | cut -d: -f1)
        if [[ -z "$conn_name" ]]; then
            log_message "ERROR" "COULD NOT DETECT ACTIVE NETWORKMANAGER CONNECTION."
            return 1
        fi
        log_message "INFO" "USING NETWORKMANAGER FOR CONNECTION '$conn_name'..."
        if nmcli con mod "$conn_name" ipv4.dns "$dns_list_str" && nmcli con mod "$conn_name" ipv4.ignore-auto-dns yes; then
            log_message "SUCCESS" "DNS FOR '$conn_name' SET VIA NMCLI."
            log_message "INFO" "RE-ACTIVATING CONNECTION TO APPLY CHANGES..."
            ( nmcli con down "$conn_name" && nmcli con up "$conn_name" ) &
            return 0
        else
            log_message "ERROR" "FAILED TO SET DNS VIA NMCLI."
            return 1
        fi
    fi

    log_message "WARN" "SYSTEMD-RESOLVED OR NETWORKMANAGER NOT FOUND/ACTIVE."
    log_message "WARN" "FALLING BACK TO DIRECT /ETC/RESOLV.CONF EDIT. THIS MAY BE TEMPORARY."
    local dns_file="/etc/resolv.conf"
    create_backup "$dns_file"
    if lsattr "$dns_file" 2>/dev/null | grep -q 'i'; then
        chattr -i "$dns_file" 2>/dev/null
    fi

    if [[ -z "$dns1" ]]; then
        log_message "WARN" "CANNOT AUTOMATICALLY REVERT RESOLV.CONF. PLEASE RESTORE BACKUP MANUALLY IF NEEDED."
        return 1
    fi

    local current_time
    printf -v current_time '%(%Y-%m-%d %H:%M:%S)T' -1
    if cat > "$dns_file" << EOF
# GENERATED BY LINUX OPTIMIZER SCRIPT ON $current_time
# WARNING: THIS CHANGE MIGHT BE OVERWRITTEN BY YOUR SYSTEM'S NETWORK MANAGER.
nameserver $dns1
nameserver $dns2
options rotate timeout:1 attempts:3
EOF
    then
        log_message "SUCCESS" "DNS CONFIGURATION UPDATED SUCCESSFULLY (FALLBACK METHOD)."
        return 0
    else
        log_message "ERROR" "FAILED TO UPDATE DNS CONFIGURATION (FALLBACK METHOD)."
        return 1
    fi
}
# ###########################################################################
# --- NEW FUNCTIONS (ADVANCED & WEB TOOLS) ---
# ###########################################################################

manage_docker() {
    _install_docker() {
        log_message "INFO" "CHECKING AND INSTALLING DOCKER..."
        if command -v docker &>/dev/null; then
            log_message "INFO" "DOCKER IS ALREADY INSTALLED."
            return 0
        fi

        log_message "INFO" "INSTALLING DOCKER PREREQUISITES (VIA CENTRAL FUNCTION)..."
        if ! install_dependencies; then
            log_message "ERROR" "FAILED TO INSTALL DOCKER PREREQUISITES."
            return 1
        fi

        log_message "INFO" "ADDING DOCKER'S OFFICIAL GPG KEY..."
        install -m 0755 -d /etc/apt/keyrings
        if ! curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc; then
            log_message "ERROR" "FAILED TO DOWNLOAD DOCKER GPG KEY."
            return 1
        fi
        chmod a+r /etc/apt/keyrings/docker.asc

        log_message "INFO" "SETTING UP DOCKER'S APT REPOSITORY..."
        echo \
          "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
          $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
          tee /etc/apt/sources.list.d/docker.list > /dev/null
        
        log_message "INFO" "INSTALLING DOCKER ENGINE..."
        apt-get update -qq
        if ! apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; then
            log_message "ERROR" "FAILED TO INSTALL DOCKER ENGINE PACKAGES."
            return 1
        fi

        systemctl enable --now docker
        check_service_status "docker"
        log_message "SUCCESS" "DOCKER INSTALLED AND STARTED SUCCESSFULLY."
        return 0
    }

    _manage_docker_containers() {
        while true; do
            clear
            echo -e "${B_CYAN}--- مدیریت کانتینرها ---${C_RESET}\n"
            echo -e "${C_WHITE}لیست کانتینرهای موجود:${C_RESET}"
            docker ps -a
            echo -e "\n${B_BLUE}----------------------------------------------------${C_RESET}"
            printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "اجرای کانتینر (START)"
            printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "توقف کانتینر (STOP)"
            printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "ری استارت کانتینر (RESTART)"
            printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "4" "مشاهده لاگ‌های کانتینر (LOGS)"
            printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "5" "بازگشت به منوی DOCKER"
            echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
            printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"; read -e -r choice

            local container_id
            case $choice in
                1|2|3)
                    printf "%b" "${B_MAGENTA}نام یا ID کانتینر مورد نظر را وارد کنید: ${C_RESET}"; read -e -r container_id
                    if [ -z "$container_id" ]; then
                        log_message "WARN" "NO CONTAINER ID PROVIDED. ABORTING."
                        sleep 2; continue
                    fi
                    if [ "$choice" -eq 1 ]; then
                        log_message "INFO" "STARTING CONTAINER: $container_id"
                        docker start "$container_id"
                    elif [ "$choice" -eq 2 ]; then
                        log_message "INFO" "STOPPING CONTAINER: $container_id"
                        docker stop "$container_id"
                    elif [ "$choice" -eq 3 ]; then
                        log_message "INFO" "RESTARTING CONTAINER: $container_id"
                        docker restart "$container_id"
                    fi
                    read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                    ;;
                4)
                    printf "%b" "${B_MAGENTA}نام یا ID کانتینر مورد نظر را وارد کنید: ${C_RESET}"; read -e -r container_id
                    if [ -z "$container_id" ]; then
                        log_message "WARN" "NO CONTAINER ID PROVIDED. ABORTING."
                        sleep 2; continue
                    fi
                    log_message "INFO" "VIEWING LOGS FOR CONTAINER: $container_id (PRESS CTRL+C TO EXIT LOGS)"
                    ( trap '' INT; docker logs -f "$container_id" )
                    log_message "INFO" "LOG VIEWING EXITED."
                    read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                    ;;
                5)
                    return 0
                    ;;
                *)
                    echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}"; sleep 1
                    ;;
            esac
        done
    }

    while true; do
        clear
        echo -e "${B_CYAN}--- نصب و مدیریت DOCKER ---${C_RESET}\n"
        echo -e "${C_WHITE}این منو ابزارهای لازم برای مدیریت DOCKER و کانتینرهای آن را فراهم می‌کند.${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "نصب DOCKER و DOCKER-COMPOSE"
        printf "  ${C_YELLOW}%2d)${B_GREEN} %s\n" "2" "مدیریت کانتینرها (شروع، توقف، لاگ)"
        printf "  ${C_YELLOW}%2d)${C_RED}   %s\n" "3" "پاکسازی سیستم DOCKER (حذف کانتینرها و ایمیج‌های بی‌استفاده)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "4" "بازگشت"
        echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"; read -e -r choice

        case $choice in
            1)
                _install_docker
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            2)
                if ! command -v docker &>/dev/null; then
                    log_message "ERROR" "DOCKER IS NOT INSTALLED. PLEASE INSTALL IT FIRST."
                else
                    _manage_docker_containers
                fi
                ;;
            3)
                if ! command -v docker &>/dev/null; then
                    log_message "ERROR" "DOCKER IS NOT INSTALLED."
                else
                    printf "%b" "${C_RED}**هشدار:** این عملیات تمام کانتینرهای متوقف شده، شبکه‌ها و ایمیج‌های بدون استفاده را حذف می‌کند. آیا مطمئن هستید؟ (y/n): ${C_RESET}"
                    read -e -r confirm
                    if [[ "$confirm" =~ ^[yY]$ ]]; then
                        log_message "WARN" "PRUNING DOCKER SYSTEM..."
                        docker system prune -a -f
                        log_message "SUCCESS" "DOCKER SYSTEM PRUNED."
                    else
                        log_message "INFO" "DOCKER PRUNE CANCELED."
                    fi
                fi
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            4)
                return
                ;;
            *)
                echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}"; sleep 1
                ;;
        esac
    done
}
manage_geoip_blocking() {
    local COMMENT_TAG="IRNET-GEOIP-BLOCK"

    _install_geoip_deps() {
        log_message "INFO" "INSTALLING GEOIP DEPENDENCIES..."
        if ! install_dependencies; then
            log_message "ERROR" "FAILED TO INSTALL GEOIP DEPENDENCIES."
            return 1
        fi
        if [ ! -d "/usr/share/xt_geoip" ]; then
            log_message "ERROR" "GEOIP DATABASE DIRECTORY NOT FOUND AFTER INSTALLATION."
            echo -e "${R}خطا: پایگاه داده GEOIP پس از نصب یافت نشد. ممکن است این قابلیت توسط سیستم عامل شما پشتیبانی نشود.${N}"
            return 1
        fi
        log_message "SUCCESS" "GEOIP DEPENDENCIES ARE INSTALLED."
        return 0
    }

    while true; do
        clear
        echo -e "${B_CYAN}--- مسدودسازی بر اساس موقعیت جغرافیایی (GEO-IP) ---${C_RESET}\n"
        echo -e "${C_WHITE}این ابزار به شما امکان می‌دهد ترافیک ورودی از کشورهای مشخص را مسدود کنید.${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "نصب پیش‌نیازها"
        printf "  ${C_YELLOW}%2d)${C_RED}   %s\n" "2" "مسدودسازی یک کشور"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "مشاهده کشورهای مسدود شده"
        printf "  ${C_YELLOW}%2d)${C_GREEN} %s\n" "4" "حذف تمام قوانین مسدودسازی GEO-IP"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "5" "بازگشت"
        echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"; read -e -r choice

        case $choice in
            1)
                _install_geoip_deps
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            2)
                printf "%b" "${B_MAGENTA}کد دو حرفی کشور مورد نظر را وارد کنید (مثال: CN برای چین، US برای آمریکا): ${C_RESET}"
                read -e -r country_code
                if [[ -z "$country_code" || ${#country_code} -ne 2 ]]; then
                    log_message "ERROR" "INVALID COUNTRY CODE PROVIDED."
                else
                    local upper_cc="${country_code^^}"
                    if ! iptables -C INPUT -m geoip --src-cc "$upper_cc" -m comment --comment "$COMMENT_TAG" -j DROP &>/dev/null; then
                        log_message "INFO" "BLOCKING COUNTRY: $upper_cc"
                        iptables -I INPUT 1 -m geoip --src-cc "$upper_cc" -m comment --comment "$COMMENT_TAG" -j DROP
                        log_message "SUCCESS" "IPTABLES RULE ADDED TO BLOCK $upper_cc."
                    else
                        log_message "INFO" "RULE TO BLOCK $upper_cc ALREADY EXISTS. SKIPPING."
                    fi
                fi
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            3)
                clear
                echo -e "${B_CYAN}--- لیست قوانین مسدودسازی GEO-IP ---${C_RESET}\n"
                iptables -L INPUT -v -n | grep "$COMMENT_TAG"
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            4)
                printf "%b" "${C_RED}آیا از حذف تمام قوانین GEO-IP مطمئن هستید؟ (y/n): ${C_RESET}"
                read -e -r confirm
                if [[ "$confirm" =~ ^[yY]$ ]]; then
                    log_message "WARN" "REMOVING ALL GEOIP BLOCK RULES..."
                    while true; do
                        local rule_line_num
                        rule_line_num=$(iptables -L INPUT -v -n --line-numbers | grep "$COMMENT_TAG" | awk '{print $1}' | head -n1)
                        if [[ -n "$rule_line_num" ]]; then
                            iptables -D INPUT "$rule_line_num"
                        else
                            break
                        fi
                    done
                    log_message "SUCCESS" "ALL GEOIP BLOCK RULES REMOVED."
                else
                    log_message "INFO" "GEOIP RULE DELETION CANCELED."
                fi
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            5)
                return
                ;;
            *)
                echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}"; sleep 1
                ;;
        esac
    done
}

manage_caddy() {
    _install_caddy() {
        log_message "INFO" "STARTING CADDY WEB SERVER INSTALLATION..."
        if command -v caddy &>/dev/null; then
            log_message "INFO" "CADDY IS ALREADY INSTALLED."
            return 0
        fi

        log_message "INFO" "INSTALLING CADDY PREREQUISITES (VIA CENTRAL FUNCTION)..."
        if ! install_dependencies; then
             log_message "ERROR" "FAILED TO INSTALL CADDY PREREQUISITES."
             return 1
        fi

        log_message "INFO" "ADDING CADDY'S OFFICIAL GPG KEY..."
        curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
        
        log_message "INFO" "SETTING UP CADDY'S APT REPOSITORY..."
        curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list > /dev/null
        
        log_message "INFO" "INSTALLING CADDY..."
        apt-get update -qq
        if ! apt-get install -y -qq caddy; then
            log_message "ERROR" "FAILED TO INSTALL CADDY."
            return 1
        fi
        
        systemctl enable --now caddy
        check_service_status "caddy"
        log_message "SUCCESS" "CADDY INSTALLED AND STARTED SUCCESSFULLY."
        return 0
    }

    while true; do
        clear
        echo -e "${B_CYAN}--- مدیریت وب سرور CADDY ---${C_RESET}\n"
        echo -e "${C_WHITE}این منو به شما کمک می‌کند وب سرور CADDY را نصب و برای پنل خود یک REVERSE PROXY با SSL خودکار راه‌اندازی کنید.${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "نصب CADDY (با SSL خودکار)"
        printf "  ${C_YELLOW}%2d)${B_GREEN} %s\n" "2" "ایجاد کانفیگ REVERSE PROXY برای پنل"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "مدیریت سرویس (START/STOP/RESTART)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "4" "مشاهده وضعیت و لاگ‌ها"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "5" "بازگشت"
        echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"; read -e -r choice

        case $choice in
            1)
                _install_caddy
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            2)
                if ! command -v caddy &>/dev/null; then
                     log_message "ERROR" "CADDY IS NOT INSTALLED. PLEASE INSTALL IT FIRST."
                else
                    printf "%b" "${B_MAGENTA}نام دامنه خود را وارد کنید (مثال: my.domain.com): ${C_RESET}"; read -e -r domain_name
                    printf "%b" "${B_MAGENTA}پورت پنل خود را وارد کنید (مثال: 54321): ${C_RESET}"; read -e -r panel_port
                    if [[ -z "$domain_name" || -z "$panel_port" ]]; then
                        log_message "ERROR" "DOMAIN AND PORT CANNOT BE EMPTY."
                    else
                        log_message "INFO" "CREATING CADDYFILE FOR DOMAIN $domain_name"
                        local caddyfile="/etc/caddy/Caddyfile"
                        create_backup "$caddyfile"
                        
                        local temp_sed_domain
                        temp_sed_domain=$(echo "$domain_name" | sed 's/[&/\]/\\&/g')
                        if grep -q "^$temp_sed_domain" "$caddyfile"; then
                            sed -i -e "/^$temp_sed_domain/,/}/d" "$caddyfile"
                            log_message "INFO" "REMOVED EXISTING CONFIGURATION FOR $domain_name."
                        fi

                        tee -a "$caddyfile" > /dev/null <<EOF

$domain_name {
    reverse_proxy localhost:$panel_port
}
EOF
                        caddy fmt --overwrite "$caddyfile"
                        log_message "INFO" "RELOADING CADDY SERVICE..."
                        systemctl reload caddy
                        log_message "SUCCESS" "CADDY CONFIGURATION APPLIED. CADDY WILL NOW ATTEMPT TO GET AN SSL CERT FOR YOUR DOMAIN."
                    fi
                fi
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            3)
                printf "%b" "${B_MAGENTA}عملیات مورد نظر را انتخاب کنید (start/stop/restart): ${C_RESET}"; read -e -r action
                if [[ "$action" == "start" || "$action" == "stop" || "$action" == "restart" ]]; then
                    systemctl "$action" caddy
                    check_service_status "caddy"
                else
                    log_message "ERROR" "INVALID ACTION."
                fi
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            4)
                (
                    trap '' INT
                    clear
                    echo -e "${B_CYAN}--- وضعیت سرویس CADDY ---${C_RESET}\n"
                    systemctl status caddy --no-pager
                    echo -e "\n${B_CYAN}--- 50 خط آخر لاگ CADDY ---${C_RESET}\n"
                    journalctl -u caddy -n 50 --no-pager
                    read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                )
                ;;
            5)
                return
                ;;
            *)
                echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}"; sleep 1
                ;;
        esac
    done
}
manage_certbot() {
    while true; do
        clear
        echo -e "${B_CYAN}--- مدیریت گواهی SSL با CERTBOT ---${C_RESET}\n"
        echo -e "${C_WHITE}این ابزار به شما امکان دریافت و مدیریت گواهی‌های رایگان SSL از LET'S ENCRYPT را می‌دهد.${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "نصب CERTBOT"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "دریافت گواهی جدید"
        printf "  ${C_YELLOW}%2d)${B_GREEN} %s\n" "3" "مشاهده لیست گواهی‌های موجود"
        printf "  ${C_YELLOW}%2d)${B_YELLOW} %s\n" "4" "تمدید اجباری یک گواهی (FORCE RENEW)"
        printf "  ${C_YELLOW}%2d)${C_RED}   %s\n" "5" "حذف یک گواهی"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "6" "بازگشت"
        echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"; read -e -r choice

        case $choice in
            1)
                log_message "INFO" "INSTALLING CERTBOT..."
                install_dependencies
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            2)
                echo -e "\n${B_CYAN}لطفاً روش دریافت گواهی را انتخاب کنید:${C_RESET}"
                echo "  1) STANDALONE (وب سرور شما را موقتاً متوقف می‌کند)"
                echo "  2) WEBROOT (نیاز به مسیر روت وب سرور فعال دارد)"
                printf "%b" "${B_MAGENTA}انتخاب شما: ${C_RESET}"; read -e -r method_choice

                printf "%b" "${B_MAGENTA}نام دامنه را وارد کنید (مثال: my.domain.com): ${C_RESET}"; read -e -r domain_name
                if [ -z "$domain_name" ]; then
                    log_message "ERROR" "DOMAIN NAME CANNOT BE EMPTY."
                elif [ "$method_choice" -eq 1 ]; then
                    log_message "INFO" "GETTING NEW CERTIFICATE FOR $domain_name USING STANDALONE METHOD..."
                    certbot certonly --standalone -d "$domain_name"
                elif [ "$method_choice" -eq 2 ]; then
                    printf "%b" "${B_MAGENTA}مسیر کامل WEBROOT را وارد کنید (مثال: /var/www/html): ${C_RESET}"; read -e -r webroot_path
                    log_message "INFO" "GETTING NEW CERTIFICATE FOR $domain_name USING WEBROOT METHOD..."
                    certbot certonly --webroot -w "$webroot_path" -d "$domain_name"
                else
                    log_message "ERROR" "INVALID SELECTION."
                fi
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            3)
                clear
                log_message "INFO" "LISTING CERTBOT CERTIFICATES..."
                certbot certificates
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            4)
                printf "%b" "${B_MAGENTA}نام دامنه‌ای که می‌خواهید گواهی آن تمدید شود را وارد کنید: ${C_RESET}"; read -e -r domain_to_renew
                if [ -n "$domain_to_renew" ]; then
                    log_message "WARN" "FORCE-RENEWING CERTIFICATE FOR $domain_to_renew..."
                    certbot renew --force-renewal -d "$domain_to_renew"
                fi
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            5)
                printf "%b" "${B_MAGENTA}نام دامنه‌ای که می‌خواهید گواهی آن حذف شود را وارد کنید: ${C_RESET}"; read -e -r domain_to_delete
                if [ -n "$domain_to_delete" ]; then
                    log_message "WARN" "DELETING CERTIFICATE FOR $domain_to_delete..."
                    certbot delete --cert-name "$domain_to_delete"
                fi
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            6)
                return
                ;;
            *)
                echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}"; sleep 1
                ;;
        esac
    done
}
# ###########################################################################
# --- NEW FUNCTIONS (SECURITY TOOLS) ---
# ###########################################################################

manage_malware_scanners() {
    while true; do
        clear
        echo -e "${B_CYAN}--- اسکنرهای بدافزار و روت‌کیت ---${C_RESET}\n"
        echo -e "${C_WHITE}این منو ابزارهایی برای اسکن سیستم جهت یافتن بدافزارها و روت‌کیت‌های احتمالی ارائه می‌دهد.${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "اجرای اسکن با CHKROOTKIT (سریع)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "نصب و اجرای اسکن با RKHUNTER (جامع)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "بازگشت"
        echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"; read -e -r choice

        case $choice in
            1)
                clear
                log_message "INFO" "STARTING CHKROOTKIT SCAN..."
                echo -e "${C_YELLOW}در حال اجرای اسکنر CHKROOTKIT... این عملیات ممکن است چند دقیقه طول بکشد.${C_RESET}"
                echo -e "${C_CYAN}برای لغو اسکن و بازگشت به منو، کلیدهای CTRL+C را فشار دهید.${C_RESET}\n"
                local scan_output
                scan_output=$( (trap '' INT; chkrootkit) 2>&1 )
                
                echo -e "${B_CYAN}--- تحلیل خودکار نتیجه CHKROOTKIT ---${C_RESET}"
                if echo "$scan_output" | grep -q "INFECTED"; then
                    echo -e "${R}نتیجه: هشدار! موارد آلوده (INFECTED) یافت شد.${N}"
                    echo -e "${Y}لطفاً خروجی کامل اسکن را با دقت بررسی کرده و اقدامات لازم را انجام دهید.${N}"
                else
                    echo -e "${G}نتیجه: مورد آلوده یا خطرناک مشخصی یافت نشد.${N}"
                fi
                log_message "INFO" "CHKROOTKIT SCAN FINISHED OR WAS CANCELED."
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            2)
                clear
                if ! command -v rkhunter &>/dev/null; then
                    log_message "WARN" "RKHUNTER NOT FOUND. ATTEMPTING TO INSTALL..."
                    install_dependencies
                fi
                log_message "INFO" "STARTING RKHUNTER SCAN..."
                echo -e "${C_YELLOW}در حال اجرای اسکنر RKHUNTER... این عملیات ممکن است بسیار زمان‌بر باشد.${C_RESET}"
                echo -e "${C_YELLOW}لطفاً تا پایان اسکن و مشاهده گزارش صبور باشید.${C_RESET}"
                echo -e "${C_CYAN}برای لغو اسکن و بازگشت به منو، کلیدهای CTRL+C را فشار دهید.${C_RESET}\n"
                
                (
                    trap '' INT
                    rkhunter --check --sk
                )
                
                log_message "INFO" "RKHUNTER SCAN FINISHED OR WAS CANCELED."
                echo -e "\n${B_CYAN}--- تحلیل خودکار نتیجه RKHUNTER ---${C_RESET}"
                if grep -q "Warning:" /var/log/rkhunter.log; then
                    echo -e "${Y}نتیجه: اسکنر یک یا چند هشدار (Warning) ثبت کرده است.${N}"
                    echo -e "${Y}بسیاری از این هشدارها ممکن است کاذب باشند (False Positive)، اما توصیه می‌شود فایل لاگ را برای بررسی دقیق‌تر مشاهده کنید.${N}"
                else
                    echo -e "${G}نتیجه: در بررسی لاگ‌ها، هشدار مشخصی یافت نشد.${N}"
                fi
                echo -e "\n${C_GREEN}اسکن RKHUNTER به پایان رسید. برای مشاهده جزئیات لاگ، فایل زیر را بررسی کنید:${C_RESET}"
                echo -e "${C_WHITE}/var/log/rkhunter.log${C_RESET}"
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            3)
                return
                ;;
            *)
                echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}"; sleep 1
                ;;
        esac
    done
}

manage_lynis_audit() {
    while true; do
        clear
        echo -e "${B_CYAN}--- ابزار ممیزی امنیتی LYNIS ---${C_RESET}\n"
        echo -e "${C_WHITE}ابزار LYNIS یک ممیزی امنیتی جامع از سیستم شما انجام داده و پیشنهاداتی برای بهبود امنیت ارائه می‌دهد.${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "نصب یا به‌روزرسانی LYNIS"
        printf "  ${C_YELLOW}%2d)${B_GREEN} %s\n" "2" "اجرای اسکن کامل سیستم"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "بازگشت"
        echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"; read -e -r choice

        case $choice in
            1)
                clear
                log_message "INFO" "INSTALLING/UPDATING LYNIS..."
                install_dependencies
                log_message "SUCCESS" "LYNIS INSTALLATION/UPDATE PROCESS COMPLETED."
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            2)
                clear
                if ! command -v lynis &>/dev/null; then
                    log_message "ERROR" "LYNIS IS NOT INSTALLED. PLEASE INSTALL IT FIRST USING OPTION 1."
                    echo -e "\n${C_RED}خطا: LYNIS نصب نیست. لطفاً ابتدا با استفاده از گزینه ۱ آن را نصب کنید.${N}"
                else
                    log_message "INFO" "STARTING LYNIS SYSTEM AUDIT..."
                    echo -e "${C_YELLOW}در حال اجرای ممیزی امنیتی LYNIS... این عملیات ممکن است چند دقیقه طول بکشد.${C_RESET}"
                    echo -e "${C_CYAN}برای لغو اسکن و بازگشت به منو، کلیدهای CTRL+C را فشار دهید.${C_RESET}\n"
                    (
                        trap '' INT
                        lynis audit system
                    )
                    log_message "INFO" "LYNIS SYSTEM AUDIT FINISHED OR WAS CANCELED."
                    echo -e "\n${C_GREEN}اسکن LYNIS به پایان رسید. گزارش‌ها و پیشنهادات در خروجی بالا نمایش داده شده است.${C_RESET}"
                    echo -e "${C_WHITE}جزئیات کامل در فایل /var/log/lynis.log ذخیره شده است.${C_RESET}"
                fi
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            3)
                return
                ;;
            *)
                echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}"; sleep 1
                ;;
        esac
    done
}
# ###########################################################################
# --- NEW FUNCTIONS (MONITORING & DIAGNOSTICS) ---
# ###########################################################################

manage_system_monitors() {
    while true; do
        clear
        echo -e "${B_CYAN}--- مانیتورینگ پیشرفته منابع سیستم ---${C_RESET}\n"
        echo -e "${C_WHITE}این ابزارها به شما امکان مشاهده زنده و دقیق پردازنده، حافظه و فرآیندهای در حال اجرا را می‌دهند.${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${B_GREEN} %s\n" "1" "اجرای BTOP (پیشرفته و گرافیکی)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "اجرای HTOP (کلاسیک و سبک)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "بازگشت"
        echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"; read -e -r choice

        case $choice in
            1)
                clear
                if ! command -v btop &>/dev/null; then
                    log_message "WARN" "BTOP NOT FOUND. ATTEMPTING TO INSTALL..."
                    install_dependencies
                    if ! command -v btop &>/dev/null; then
                        log_message "ERROR" "BTOP INSTALLATION FAILED. PLEASE CHECK APT LOGS. IT MAY NOT BE SUPPORTED ON YOUR OS."
                        read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                        continue
                    fi
                fi
                log_message "INFO" "LAUNCHING BTOP SYSTEM MONITOR..."
                echo -e "${C_WHITE}در حال اجرای مانیتور BTOP...${C_RESET}"
                echo -e "${B_YELLOW}نکته: BTOP به ترمینال مدرن نیاز دارد. در صورت مشاهده خطاهای نمایشی، از HTOP استفاده کنید.${C_RESET}"
                echo -e "${C_CYAN}برای خروج از برنامه و بازگشت به منو، کلید 'q' را فشار دهید.${C_RESET}\n"
                sleep 2
                btop
                log_message "INFO" "BTOP SESSION FINISHED."
                ;;
            2)
                clear
                if ! command -v htop &>/dev/null; then
                    log_message "WARN" "HTOP NOT FOUND. ATTEMPTING TO INSTALL..."
                    install_dependencies
                     if ! command -v htop &>/dev/null; then
                        log_message "ERROR" "HTOP INSTALLATION FAILED. PLEASE CHECK APT LOGS."
                        read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                        continue
                    fi
                fi
                log_message "INFO" "LAUNCHING HTOP SYSTEM MONITOR..."
                echo -e "${C_WHITE}در حال اجرای مانیتور HTOP...${C_RESET}"
                echo -e "${C_CYAN}برای خروج از برنامه و بازگشت به منو، کلید 'q' را فشار دهید.${C_RESET}\n"
                sleep 2
                htop
                log_message "INFO" "HTOP SESSION FINISHED."
                ;;
            3)
                return
                ;;
            *)
                echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}"; sleep 1
                ;;
        esac
    done
}

manage_disk_analyzer() {
    clear
    if ! command -v ncdu &>/dev/null; then
        log_message "WARN" "NCDU NOT FOUND. ATTEMPTING TO INSTALL..."
        install_dependencies
        if ! command -v ncdu &>/dev/null; then
            log_message "ERROR" "NCDU INSTALLATION FAILED. PLEASE CHECK APT LOGS."
            read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
            return
        fi
    fi
    log_message "INFO" "STARTING NCDU DISK USAGE ANALYZER..."
    echo -e "${B_CYAN}--- تحلیلگر فضای دیسک (NCDU) ---${C_RESET}\n"
    echo -e "${C_YELLOW}در حال اسکن فضای دیسک از مسیر روت (/) ... این عملیات ممکن است کمی طول بکشد.${C_RESET}"
    echo -e "${C_WHITE}پس از نمایش، می‌توانید با کلیدهای جهت‌نما در پوشه‌ها حرکت کنید.${C_RESET}"
    echo -e "${C_CYAN}برای خروج از برنامه و بازگشت به منو، کلید 'q' را فشار دهید.${C_RESET}\n"
    sleep 2
    ncdu /
    log_message "SUCCESS" "NCDU SESSION FINISHED."
    read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
}

manage_network_traffic() {
    clear
    if ! command -v iftop &>/dev/null; then
        log_message "WARN" "IFTOP NOT FOUND. ATTEMPTING TO INSTALL..."
        install_dependencies
        if ! command -v iftop &>/dev/null; then
            log_message "ERROR" "IFTOP INSTALLATION FAILED. PLEASE CHECK APT LOGS."
            read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
            return
        fi
    fi
    if [[ -z "$PRIMARY_INTERFACE" ]]; then
        log_message "ERROR" "PRIMARY NETWORK INTERFACE NOT FOUND."
        read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
        return
    fi
    log_message "INFO" "LAUNCHING IFTOP ON INTERFACE $PRIMARY_INTERFACE..."
    echo -e "${B_CYAN}--- مشاهده زنده ترافیک شبکه (IFTOP) ---${C_RESET}\n"
    echo -e "${C_WHITE}در حال نمایش ترافیک بر روی کارت شبکه: ${B_YELLOW}${PRIMARY_INTERFACE}${C_RESET}"
    echo -e "${C_CYAN}برای خروج از برنامه و بازگشت به منو، کلید 'q' را فشار دهید.${C_RESET}\n"
    sleep 2
    iftop -i "$PRIMARY_INTERFACE"
    log_message "SUCCESS" "IFTOP SESSION FINISHED."
}

# ###########################################################################
# --- NEW FUNCTIONS (SYSTEM & UTILITY TOOLS) ---
# ###########################################################################

manage_swap() {
    while true; do
        clear
        echo -e "${B_CYAN}--- مدیریت حافظه SWAP ---${C_RESET}\n"
        echo -e "${C_WHITE}حافظه SWAP به عنوان یک حافظه مجازی روی دیسک عمل کرده و در زمان کمبود RAM به پایداری سیستم کمک می‌کند.${C_RESET}\n"
        echo -e "${C_WHITE}وضعیت فعلی SWAP:${C_RESET}"
        swapon --show
        free -h | grep -i "SWAP"
        echo -e "\n${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "ایجاد فایل SWAP"
        printf "  ${C_YELLOW}%2d)${C_RED}   %s\n" "2" "حذف فایل SWAP"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "بازگشت"
        echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"; read -e -r choice

        case $choice in
            1)
                printf "%b" "${B_MAGENTA}حجم فایل SWAP را به گیگابایت وارد کنید (مثال: 2): ${C_RESET}"
                read -e -r swap_size
                if ! [[ "$swap_size" =~ ^[0-9]+$ ]] || [ "$swap_size" -eq 0 ]; then
                    log_message "ERROR" "INVALID SWAP SIZE."
                    echo -e "\n${C_RED}مقدار وارد شده نامعتبر است.${N}"
                else
                    log_message "INFO" "CREATING A ${swap_size}GB SWAP FILE..."
                    fallocate -l "${swap_size}G" /swapfile
                    chmod 600 /swapfile
                    mkswap /swapfile
                    swapon /swapfile
                    if ! grep -q "/swapfile" /etc/fstab; then
                        echo '/swapfile none swap sw 0 0' >> /etc/fstab
                    fi
                    log_message "SUCCESS" "${swap_size}GB SWAP FILE CREATED AND ENABLED."
                fi
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            2)
                if [ -f /swapfile ]; then
                    log_message "WARN" "DELETING SWAP FILE..."
                    swapoff /swapfile
                    sed -i '\|/swapfile|d' /etc/fstab
                    rm -f /swapfile
                    log_message "SUCCESS" "SWAP FILE DELETED SUCCESSFULLY."
                else
                    log_message "INFO" "NO SWAP FILE FOUND TO DELETE."
                    echo -e "\n${C_YELLOW}فایل SWAP ای برای حذف یافت نشد.${N}"
                fi
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            3)
                return
                ;;
            *)
                echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}"; sleep 1
                ;;
        esac
    done
}

manage_system_cleanup() {
    clear
    log_message "INFO" "STARTING SYSTEM CLEANUP PROCESS..."
    echo -e "${B_CYAN}--- پاکسازی سیستم ---${C_RESET}\n"
    echo -e "${C_WHITE}این عملیات فایل‌های کش APT و پکیج‌های غیرضروری را برای آزاد کردن فضای دیسک حذف می‌کند.${C_RESET}\n"
    
    echo -e "${C_YELLOW}وضعیت دیسک قبل از پاکسازی:${C_RESET}"
    df -h / | tail -n 1
    
    echo -e "\n${C_YELLOW}در حال حذف پکیج‌های غیرضروری و فایل‌های کش APT...${C_RESET}"
    
    log_message "INFO" "RUNNING APT CLEAN..."
    apt-get clean > /dev/null 2>&1
    
    log_message "INFO" "RUNNING APT AUTOREMOVE..."
    apt-get autoremove -y --purge > /dev/null 2>&1
    
    log_message "SUCCESS" "SYSTEM CLEANUP COMPLETED."
    echo -e "\n${C_GREEN}✅ پاکسازی با موفقیت انجام شد.${C_RESET}"

    echo -e "\n${C_YELLOW}وضعیت دیسک بعد از پاکسازی:${C_RESET}"
    df -h / | tail -n 1

    read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
}
# #############################################################################
# --- MAIN OPTIMIZATION FUNCTIONS (NOW MODIFIED AND IMPROVED) ---
# #############################################################################

gather_system_info() {
    log_message "INFO" "GATHERING SYSTEM INFORMATION..."
    local cpu_cores total_ram
    cpu_cores=$(nproc 2>/dev/null | head -1)
    cpu_cores=$(printf '%s' "$cpu_cores" | tr -cd '0-9')
    if [[ -z "$cpu_cores" ]] || ! [[ "$cpu_cores" =~ ^[0-9]+$ ]] || [[ "$cpu_cores" -eq 0 ]]; then
        log_message "WARN" "CPU CORE DETECTION FAILED. USING FALLBACK VALUE."
        cpu_cores=1
    fi
    total_ram=$(awk '/MemTotal:/ {print int($2/1024); exit}' /proc/meminfo 2>/dev/null | head -1)
    total_ram=$(printf '%s' "$total_ram" | tr -cd '0-9')
    if [[ -z "$total_ram" ]] || ! [[ "$total_ram" =~ ^[0-9]+$ ]] || [[ "$total_ram" -eq 0 ]]; then
        log_message "WARN" "RAM DETECTION FAILED. USING FALLBACK VALUE."
        total_ram=1024
    fi
    log_message "INFO" "SYSTEM INFORMATION:"
    log_message "INFO" "CPU CORES: $cpu_cores"
    log_message "INFO" "TOTAL RAM: ${total_ram}MB"
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
        log_message "ERROR" "NO INTERFACE SPECIFIED."
        return 1
    fi
    log_message "INFO" "OPTIMIZING NETWORK INTERFACE $interface..."
    if [[ -z "$SYSTEM_OPTIMAL_BACKLOG" ]]; then
        gather_system_info
    fi
    local max_mem=$SYSTEM_OPTIMAL_MEM
    if [[ "$max_mem" -gt 16777216 ]]; then
        max_mem=16777216
    fi
    log_message "INFO" "CONFIGURING NIC OFFLOAD SETTINGS..."
    {
        ethtool -K "$interface" tso on gso on gro on 2>/dev/null
        ethtool -G "$interface" rx 4096 tx 4096 2>/dev/null
    } || true
    if ethtool -k "$interface" 2>/dev/null | grep -q "rx-udp-gro-forwarding"; then
        log_message "INFO" "ENABLING UDP GRO FORWARDING..."
        ethtool -K "$interface" rx-udp-gro-forwarding on rx-gro-list off 2>/dev/null || true
    fi
    local sysctl_conf="/etc/sysctl.d/99-network-optimizer.conf"
    log_message "INFO" "CREATING NETWORK OPTIMIZATION CONFIGURATION..."
    create_backup "$sysctl_conf"
    
    local current_time
    printf -v current_time '%(%Y-%m-%d %H:%M:%S)T' -1
    cat > "$sysctl_conf" << EOF
# NETWORK OPTIMIZATIONS ADDED ON $current_time
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
        log_message "SUCCESS" "NETWORK OPTIMIZATIONS APPLIED SUCCESSFULLY."
    else
        log_message "ERROR" "FAILED TO APPLY NETWORK OPTIMIZATIONS."
        return 1
    fi
    local current_cc
    current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    if [[ "$current_cc" == "bbr" ]]; then
        log_message "SUCCESS" "TCP BBR CONGESTION CONTROL ENABLED."
    else
        log_message "WARN" "TCP BBR NOT AVAILABLE. FALLING BACK TO CUBIC."
        sysctl -w net.ipv4.tcp_congestion_control=cubic &>/dev/null
    fi
    if ip link set dev "$interface" txqueuelen 10000 2>/dev/null; then
        log_message "SUCCESS" "INCREASED TX QUEUE LENGTH FOR $interface."
    else
        log_message "WARN" "FAILED TO SET TX QUEUE LENGTH."
    fi
    return 0
}
find_best_mtu() {
    local interface="$1"
    local target_ip="8.8.8.8"
    if [[ -z "$interface" ]]; then
        log_message "ERROR" "NO INTERFACE SPECIFIED FOR MTU OPTIMIZATION."
        return 1
    fi
    log_message "INFO" "STARTING MTU OPTIMIZATION FOR INTERFACE $interface..."
    local current_mtu
    if ! current_mtu=$(cat "/sys/class/net/$interface/mtu" 2>/dev/null); then
        current_mtu=$(ip link show "$interface" 2>/dev/null | sed -n 's/.*mtu \([0-9]*\).*/\1/p')
    fi
    if [[ -z "$current_mtu" ]] || [[ ! "$current_mtu" =~ ^[0-9]+$ ]]; then
        log_message "ERROR" "COULD NOT DETERMINE CURRENT MTU FOR $interface."
        return 1
    fi
    log_message "INFO" "CURRENT MTU: $current_mtu"
    if ! ip addr show "$interface" 2>/dev/null | grep -q "inet "; then
        log_message "ERROR" "INTERFACE $interface IS NOT CONFIGURED WITH AN IP ADDRESS."
        return 1
    fi
    log_message "INFO" "TESTING BASIC CONNECTIVITY..."
    if ! ping -c 1 -W 3 "$target_ip" &>/dev/null; then
        log_message "ERROR" "NO INTERNET CONNECTIVITY. CANNOT PERFORM MTU OPTIMIZATION."
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
    log_message "INFO" "TESTING COMMON MTU SIZES..."
    local common_mtus=(1500 1492 1480 1472 1468 1460 1450 1440 1430 1420 1400 1380 1360 1340 1300 1280 1200 1024)
    for size in "${common_mtus[@]}"; do
        if [[ "$size" -le "$current_mtu" ]]; then
            printf "  TESTING MTU %d... " "$size"
            if test_mtu_size "$size"; then
                printf "${G}✓${N}\n"
                optimal_mtu="$size"; found_working=1; break
            else
                printf "${R}✗${N}\n"
            fi
        fi
    done
    if [[ "$found_working" -eq 0 ]]; then
        log_message "INFO" "COMMON MTUS FAILED. PERFORMING BINARY SEARCH..."
        local min_mtu=576; local max_mtu="$current_mtu"; local test_mtu
        while [[ "$min_mtu" -le "$max_mtu" ]]; do
            test_mtu=$(( (min_mtu + max_mtu) / 2 ))
            printf "  TESTING MTU %d... " "$test_mtu"
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
            log_message "INFO" "APPLYING OPTIMAL MTU: $optimal_mtu"
            if ip link set "$interface" mtu "$optimal_mtu" 2>/dev/null; then
                log_message "SUCCESS" "MTU SUCCESSFULLY SET TO $optimal_mtu."
                log_message "INFO" "MAKING MTU SETTING PERSISTENT ACROSS REBOOTS..."
                cat > "$CONFIG_DIR/mtu.conf" << EOF
# OPTIMAL MTU CONFIGURATION SAVED BY SCRIPT
INTERFACE=$interface
OPTIMAL_MTU=$optimal_mtu
EOF
                cat > /etc/systemd/system/irnet-mtu-persistent.service << EOF
[Unit]
Description=Persistent MTU Setter by IRNET Script
After=network.target
Wants=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c "source \"$CONFIG_DIR/mtu.conf\" && /sbin/ip link set dev \\\$INTERFACE mtu \\\$OPTIMAL_MTU"

[Install]
WantedBy=multi-user.target
EOF
                systemctl daemon-reload
                systemctl enable --now irnet-mtu-persistent.service
                check_service_status "irnet-mtu-persistent.service"
            else
                log_message "ERROR" "FAILED TO SET MTU TO $optimal_mtu."
                return 1
            fi
        else
            log_message "INFO" "CURRENT MTU ($current_mtu) IS ALREADY OPTIMAL."
        fi
    else
        log_message "WARN" "COULD NOT FIND WORKING MTU. KEEPING CURRENT MTU: $current_mtu."
    fi
    return 0
}
restore_defaults() {
    log_message "INFO" "RESTORING ORIGINAL SETTINGS..."
    local choice
    while true; do
        read -p "آیا از بازگردانی تنظیمات پیشفرض مطمئن هستید؟ (y/n): " -n 1 -r choice
        echo
        case "$choice" in
            [Yy]*)
                break
                ;;
            [Nn]*)
                log_message "INFO" "RESTORE OPERATION CANCELED."
                return 0
                ;;
            *)
                printf "\n%b" "${C_RED}لطفاً با y یا n پاسخ دهید.${C_RESET}\n"
                ;;
        esac
    done

    log_message "INFO" "REMOVING ALL PERSISTENT SERVICES CREATED BY THIS SCRIPT..."
    systemctl disable --now irnet-mtu-persistent.service &>/dev/null
    rm -f /etc/systemd/system/irnet-mtu-persistent.service
    rm -f "$CONFIG_DIR/mtu.conf"

    systemctl disable --now irnet-tc-persistent.service &>/dev/null
    rm -f /etc/systemd/system/irnet-tc-persistent.service
    rm -f "$CONFIG_DIR/tc.conf"
    systemctl daemon-reload

    local sysctl_backup hosts_backup resolv_backup
    sysctl_backup=$(find "$BACKUP_DIR" -name "99-network-optimizer.conf.bak*" -type f 2>/dev/null | sort -V | tail -n1)
    hosts_backup=$(find "$BACKUP_DIR" -name "hosts.bak*" -type f 2>/dev/null | sort -V | tail -n1)
    resolv_backup=$(find "$BACKUP_DIR" -name "resolv.conf.bak*" -type f 2>/dev/null | sort -V | tail -n1)
    if [[ -f "$sysctl_backup" ]]; then
        if cp -f "$sysctl_backup" "/etc/sysctl.d/99-network-optimizer.conf" 2>/dev/null; then
            sysctl -p "/etc/sysctl.d/99-network-optimizer.conf" &>/dev/null
            log_message "SUCCESS" "RESTORED SYSCTL SETTINGS."
        else
            log_message "ERROR" "FAILED TO RESTORE SYSCTL SETTINGS."
        fi
    else
        log_message "WARN" "NO SYSCTL BACKUP FOUND. REMOVING OPTIMIZATION FILE..."
        rm -f "/etc/sysctl.d/99-network-optimizer.conf"
        sysctl --system &>/dev/null
        log_message "INFO" "RESET TO SYSTEM DEFAULTS."
    fi
    if [[ -f "$hosts_backup" ]]; then
        if cp -f "$hosts_backup" "/etc/hosts" 2>/dev/null; then
            log_message "SUCCESS" "RESTORED HOSTS FILE."
        else
            log_message "ERROR" "FAILED TO RESTORE HOSTS FILE."
        fi
    else
        log_message "WARN" "NO HOSTS BACKUP FOUND."
    fi
    if [[ -f "$resolv_backup" ]]; then
        if cp -f "$resolv_backup" "/etc/resolv.conf" 2>/dev/null; then
            log_message "SUCCESS" "RESTORED DNS SETTINGS."
        else
            log_message "ERROR" "FAILED TO RESTORE DNS SETTINGS."
        fi
    else
        log_message "WARN" "NO DNS BACKUP FOUND."
    fi
    log_message "SUCCESS" "ORIGINAL SETTINGS RESTORED SUCCESSFULLY."
    log_message "INFO" "A SYSTEM REBOOT IS RECOMMENDED FOR CHANGES TO TAKE FULL EFFECT."
    
    local reboot_choice
    while true; do
        read -p "آیا مایل به ریبوت سیستم هستید؟ (y/n): " -n 1 -r reboot_choice
        echo
        case "$reboot_choice" in
            [Yy]*)
                log_message "INFO" "REBOOTING SYSTEM NOW..."
                systemctl reboot
                break
                ;;
            [Nn]*)
                break
                ;;
            *)
                printf "\n%b" "${C_RED}لطفاً با y یا n پاسخ دهید.${C_RESET}\n"
                ;;
        esac
    done
    return 0
}
intelligent_optimize() {
    log_message "INFO" "STARTING INTELLIGENT NETWORK OPTIMIZATION..."
    
    if ! install_dependencies; then
        log_message "ERROR" "FAILED TO INSTALL REQUIRED DEPENDENCIES. ABORTING."
        return 1
    fi
    
    if ! check_internet_connection; then
        log_message "ERROR" "NO INTERNET CONNECTION AVAILABLE. CANNOT APPLY OPTIMIZATIONS."
        return 1
    fi
    if [[ -z "$PRIMARY_INTERFACE" ]]; then
        log_message "ERROR" "COULD NOT DETECT PRIMARY NETWORK INTERFACE."
        return 1
    fi

    log_message "INFO" "APPLYING OPTIMIZATIONS TO INTERFACE $PRIMARY_INTERFACE..."
    if ! fix_etc_hosts; then log_message "ERROR" "FAILED TO OPTIMIZE HOSTS FILE."; return 1; fi
    
    if ! apply_dns_persistent "${TARGET_DNS[0]}" "${TARGET_DNS[1]}"; then 
        log_message "ERROR" "FAILED TO OPTIMIZE DNS SETTINGS."; 
        return 1; 
    fi

    if ! gather_system_info; then log_message "ERROR" "FAILED TO GATHER SYSTEM INFORMATION."; return 1; fi
    if ! optimize_network "$PRIMARY_INTERFACE"; then log_message "ERROR" "FAILED TO APPLY NETWORK OPTIMIZATIONS."; return 1; fi
    if ! find_best_mtu "$PRIMARY_INTERFACE"; then log_message "ERROR" "FAILED TO OPTIMIZE MTU."; return 1; fi
    
    log_message "SUCCESS" "ALL OPTIMIZATIONS COMPLETED SUCCESSFULLY."
    log_message "INFO" "A SYSTEM REBOOT IS RECOMMENDED FOR CHANGES TO TAKE FULL EFFECT."
    
    local choice
    while true; do
        read -p "آیا مایل به ریبوت سیستم هستید؟ (y/n): " -n 1 -r choice
        echo
        case "$choice" in
            [Yy]*)
                log_message "INFO" "REBOOTING SYSTEM NOW..."
                systemctl reboot
                break
                ;;
            [Nn]*)
                break
                ;;
            *)
                printf "\n%b" "${C_RED}لطفاً با y یا n پاسخ دهید.${C_RESET}\n"
                ;;
        esac
    done
    return 0
}

show_as_bbr_menu() {
    while true; do
        clear
        echo -e "${B_CYAN}--- منوی بهینه سازی بستر شبکه ---${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "اعمال بهینه سازی هوشمند (پیشنهادی)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "بازگردانی به تنظیمات پیش‌فرض"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "بازگشت به منوی اصلی"
        echo -e "${B_BLUE}-----------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید (1-3): ${C_RESET}"
        read -e -r choice

        case "$choice" in
            1)
                intelligent_optimize
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            2)
                restore_defaults
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            3)
                log_message "INFO" "RETURNING TO THE MAIN MENU."
                return
                ;;
            *)
                printf "\n%sگزینه نامعتبر است. لطفاً عددی بین 1 تا 3 وارد کنید.%s\n" "$C_RED" "$C_RESET"
                sleep 2
                ;;
        esac
    done
}

run_as_bbr_optimization() {
    init_environment
    show_as_bbr_menu
}
manage_dns() {
    clear
    if ! command -v fping &>/dev/null; then
        log_message "WARN" "FPING TOOL NOT FOUND. ATTEMPTING TO INSTALL AUTOMATICALLY..."
        if ! install_dependencies; then
            log_message "ERROR" "AUTOMATIC INSTALLATION OF 'FPING' FAILED."
            read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
            return
        fi
        log_message "SUCCESS" "'FPING' TOOL INSTALLED SUCCESSFULLY. CONTINUING..."
        sleep 2
    fi

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
    
    find_and_set_best_dns() {
        local -n dns_list=$1
        local list_name="$2"
        echo -e "\n${B_CYAN}در حال تست پینگ از لیست DNS های ${list_name} با ابزار FPING...${C_RESET}"
        
        local fping_results
        fping_results=$(fping -C 3 -q -B1 -i10 "${dns_list[@]}" 2>&1)
        
        local reachable_dns=()
        local all_results=()

        while IFS= read -r line; do
            if [[ $line && ! "$line" == *"-"* ]]; then
                local ip avg_ping
                ip=$(echo "$line" | awk '{print $1}')
                avg_ping=$(echo "$line" | awk '{s=0; for(i=3;i<=NF;i++) s+=$i; print s/(NF-2)}' | bc -l)
                
                all_results+=("پینگ ${C_YELLOW}${ip}${C_RESET}: ${G}$(printf "%.2f" $avg_ping) ms${N}")
                reachable_dns+=("$(printf "%.2f" $avg_ping) $ip")
            fi
        done <<< "$fping_results"

        echo
        for (( i=0; i<${#all_results[@]}; i+=2 )); do
            printf "%-35b %s\n" "${all_results[i]}" "${all_results[i+1]}"
        done
        echo

        if [ ${#reachable_dns[@]} -eq 0 ]; then
            log_message "ERROR" "NONE OF THE DNS SERVERS RESPONDED. PLEASE CHECK YOUR INTERNET CONNECTION."
            return
        fi

        mapfile -t sorted_dns < <(printf '%s\n' "${reachable_dns[@]}" | sort -n)
        mapfile -t best_ips < <(printf '%s\n' "${sorted_dns[@]}" | awk '{print $2}')

        if [ "${#best_ips[@]}" -lt 2 ]; then
            log_message "WARN" "ONLY ONE ACCESSIBLE DNS WAS FOUND. SETTING BOTH DNS TO IT."
        fi

        local best_dns_1="${best_ips[0]}"
        local best_dns_2="${best_ips[1]:-${best_ips[0]}}"
        apply_dns_persistent "$best_dns_1" "$best_dns_2"
    }

    while true; do
        clear
        echo -e "${B_CYAN}--- مدیریت و یافتن بهترین DNS ---${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "یافتن و تنظیم بهترین DNS ایران"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "یافتن و تنظیم بهترین DNS جهانی"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "مشاهده DNS فعال سیستم"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "4" "بازگشت به منوی بهینه سازی"
        echo -e "${B_BLUE}-----------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"
        read -e -r choice

        case $choice in
            1) find_and_set_best_dns IRAN_DNS_LIST "ایران"; break ;;
            2) find_and_set_best_dns GLOBAL_DNS_LIST "جهانی"; break ;;
            3) clear; echo -e "${B_CYAN}--- وضعیت DNS فعال سیستم ---${C_RESET}"; show_current_dns_smart; break ;;
            4) return ;;
            *) echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}"; sleep 1 ;;
        esac
    done
    read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
}

manage_ipv6() {
    clear
    local sysctl_conf="/etc/sysctl.conf"
    echo -e "${B_CYAN}--- فعال/غیرفعال کردن IPV6 ---${C_RESET}\n"
    printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "غیرفعال کردن IPV6"
    printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "فعال کردن IPV6 (حذف تنظیمات)"
    printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "بازگشت به منوی امنیت"
    echo -e "${B_BLUE}-----------------------------------${C_RESET}"
    printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"
    read -e -r choice

    case $choice in
        1)
            printf "%b" "${C_YELLOW}**هشدار:** این کار ممکن است اتصال شما را دچار اختلال کند. آیا مطمئن هستید؟ (Y/N): ${C_RESET}"
            read -e -r confirm
            if [[ "$confirm" =~ ^[yY]$ ]]; then
                create_backup "$sysctl_conf"
                touch "$sysctl_conf"
                sed -i '/net.ipv6.conf.all.disable_ipv6/d' "$sysctl_conf"
                sed -i '/net.ipv6.conf.default.disable_ipv6/d' "$sysctl_conf"
                sed -i '/net.ipv6.conf.lo.disable_ipv6/d' "$sysctl_conf"
                echo "net.ipv6.conf.all.disable_ipv6 = 1" >> "$sysctl_conf"
                echo "net.ipv6.conf.default.disable_ipv6 = 1" >> "$sysctl_conf"
                echo "net.ipv6.conf.lo.disable_ipv6 = 1" >> "$sysctl_conf"
                sysctl -p
                log_message "SUCCESS" "IPV6 DISABLED SUCCESSFULLY."
            else
                log_message "INFO" "IPV6 DISABLE OPERATION CANCELED."
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
                log_message "SUCCESS" "IPV6 DISABLE SETTINGS REMOVED."
            else
                log_message "WARN" "SYSCTL.CONF FILE NOT FOUND."
            fi
            ;;
        3) return ;;
        *) echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}" ;;
    esac
    read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
}
manage_ssh_root() {
  clear
  local sshd_config="/etc/ssh/sshd_config"
  local ssh_service_name="ssh"
  systemctl status sshd >/dev/null 2>&1 && ssh_service_name="sshd"
  
  echo -e "${B_CYAN}--- مدیریت ورود کاربر ROOT ---${C_RESET}\n"
  printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "فعال کردن ورود ROOT با رمز عبور"
  printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "غیرفعال کردن ورود ROOT با رمز عبور"
  printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "بازگشت به منوی امنیت"
  echo -e "${B_BLUE}-----------------------------------${C_RESET}"
  printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"
  read -e -r choice

  case $choice in
    1)
      echo -e "\n${C_YELLOW}**هشدار:** فعال کردن ورود ROOT با رمز عبور، یک ریسک امنیتی است.${C_RESET}"
      printf "%b" "${B_MAGENTA}آیا برای ادامه مطمئن هستید؟ (Y/N) ${C_RESET}"
      read -e -r confirm
      if [[ "$confirm" =~ ^[yY]$ ]]; then
          echo -e "\nابتدا باید برای کاربر ROOT یک رمز عبور تنظیم کنید."
          passwd root
          create_backup "$sshd_config"
          if grep -q "^#*PermitRootLogin" "$sshd_config"; then
            sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' "$sshd_config"
          else
            echo "PermitRootLogin yes" >> "$sshd_config"
          fi
          systemctl restart "$ssh_service_name"
          check_service_status "$ssh_service_name"
      else
          log_message "INFO" "ENABLE ROOT LOGIN OPERATION CANCELED."
      fi
      ;;
    2)
      create_backup "$sshd_config"
      if grep -q "^#*PermitRootLogin" "$sshd_config"; then
        sed -i 's/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/' "$sshd_config"
      else
        echo "PermitRootLogin prohibit-password" >> "$sshd_config"
      fi
      systemctl restart "$ssh_service_name"
      check_service_status "$ssh_service_name"
      ;;
    3) return ;;
    *) echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}" ;;
  esac
  read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
}

manage_reboot_cron() {
    clear
    echo -e "${B_CYAN}--- مدیریت ریبوت خودکار سرور ---${C_RESET}\n"
    printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "افزودن CRON JOB برای ریبوت هر 3 ساعت"
    printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "افزودن CRON JOB برای ریبوت هر 7 ساعت"
    printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "افزودن CRON JOB برای ریبوت هر 12 ساعت"
    printf "  ${C_YELLOW}%2d)${C_RED}   %s\n"   "4" "حذف تمام CRON JOB های ریبوت خودکار"
    printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "5" "بازگشت به منوی امنیت"
    echo -e "${B_BLUE}-----------------------------------${C_RESET}"
    printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"
    read -e -r choice
    
    case $choice in
        1)
            (crontab -l 2>/dev/null | grep -v "/sbin/shutdown -r now"; echo "0 */3 * * * /sbin/shutdown -r now") | crontab -
            log_message "SUCCESS" "AUTOMATIC REBOOT SET FOR EVERY 3 HOURS."
            ;;
        2)
            (crontab -l 2>/dev/null | grep -v "/sbin/shutdown -r now"; echo "0 */7 * * * /sbin/shutdown -r now") | crontab -
            log_message "SUCCESS" "AUTOMATIC REBOOT SET FOR EVERY 7 HOURS."
            ;;
        3)
            (crontab -l 2>/dev/null | grep -v "/sbin/shutdown -r now"; echo "0 */12 * * * /sbin/shutdown -r now") | crontab -
            log_message "SUCCESS" "AUTOMATIC REBOOT SET FOR EVERY 12 HOURS."
            ;;
        4)
            crontab -l | grep -v "/sbin/shutdown -r now" | crontab -
            log_message "SUCCESS" "ALL AUTOMATIC REBOOT CRON JOBS HAVE BEEN REMOVED."
            ;;
        5) return ;;
        *) echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}" ;;
    esac
    read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
}
change_server_password() {
    clear
    echo -e "${B_CYAN}--- تغییر رمز عبور سرور ---${C_RESET}\n"
    echo -e "${C_YELLOW}این اسکریپت از ابزار امن 'passwd' خود سیستم برای تغییر رمز عبور شما استفاده می‌کند.${C_RESET}"
    echo -e "${C_WHITE}لطفاً دستورالعمل‌های روی صفحه را برای تغییر رمز دنبال کنید.${C_RESET}"
    echo -e "${B_BLUE}-----------------------------------${C_RESET}"
    passwd
    log_message "SUCCESS" "PASSWORD CHANGE PROCESS EXECUTED BY USER."
    read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
}
# ###########################################################################
# --- TCP OPTIMIZERS AND PANEL MANAGEMENT ---
# ###########################################################################

remove_tcp_optimizers() {
    log_message "INFO" "REMOVING TCP OPTIMIZER CONFIGS..."
    rm -f /etc/sysctl.d/99-custom-optimizer.conf
    sysctl --system &>/dev/null
    log_message "SUCCESS" "TCP OPTIMIZER CONFIG REMOVED."
}

apply_bbr_plus() {
    remove_tcp_optimizers
    log_message "INFO" "APPLYING BBR PLUS OPTIMIZATION PROFILE..."
    cat > /etc/sysctl.d/99-custom-optimizer.conf << EOF
# BBR PLUS PROFILE BY IRNET
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_keepalive_time=1800
net.ipv4.tcp_keepalive_intvl=30
net.ipv4.tcp_keepalive_probes=5
net.ipv4.tcp_max_syn_backlog=10240
net.ipv4.tcp_max_tw_buckets=2000000
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_notsent_lowat=16384
EOF
    sysctl -p /etc/sysctl.d/99-custom-optimizer.conf &>/dev/null
    log_message "SUCCESS" "BBR PLUS PROFILE APPLIED SUCCESSFULLY."
}

apply_bbr_v2() {
    remove_tcp_optimizers
    log_message "INFO" "APPLYING BBRV2 OPTIMIZATION PROFILE..."
    cat > /etc/sysctl.d/99-custom-optimizer.conf << EOF
# BBRV2 PROFILE BY IRNET
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_ecn=1
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_fin_timeout=10
net.ipv4.tcp_keepalive_intvl=20
net.ipv4.tcp_keepalive_probes=5
net.ipv4.tcp_keepalive_time=300
net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.tcp_max_tw_buckets=2000000
net.ipv4.tcp_notsent_lowat=16384
net.ipv4.tcp_retries2=10
net.ipv4.tcp_sack=1
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_timestamps=1
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_window_scaling=1
EOF
    sysctl -p /etc/sysctl.d/99-custom-optimizer.conf &>/dev/null
    log_message "SUCCESS" "BBRV2 PROFILE APPLIED SUCCESSFULLY."
}


apply_hybla_plus() {
    if ! modprobe tcp_hybla; then
        log_message "ERROR" "TCP HYBLA MODULE NOT AVAILABLE IN THIS KERNEL."
        return
    fi
    remove_tcp_optimizers
    log_message "INFO" "APPLYING HYBLA PLUS OPTIMIZATION PROFILE..."
    cat > /etc/sysctl.d/99-custom-optimizer.conf << EOF
# HYBLA PLUS PROFILE BY IRNET
net.core.default_qdisc=fq_codel
net.ipv4.tcp_congestion_control=hybla
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_keepalive_time=1800
net.ipv4.tcp_low_latency=1
EOF
    sysctl -p /etc/sysctl.d/99-custom-optimizer.conf &>/dev/null
    log_message "SUCCESS" "HYBLA PLUS PROFILE APPLIED SUCCESSFULLY."
}

apply_cubic_unstable() {
    remove_tcp_optimizers
    log_message "INFO" "APPLYING CUBIC PROFILE FOR UNSTABLE NETWORKS..."
    cat > /etc/sysctl.d/99-custom-optimizer.conf << EOF
# CUBIC FOR UNSTABLE NETWORKS PROFILE BY IRNET
net.core.default_qdisc=codel
net.ipv4.tcp_congestion_control=cubic
net.ipv4.ip_local_port_range = 32768 32818
EOF
    sysctl -p /etc/sysctl.d/99-custom-optimizer.conf &>/dev/null
    log_message "SUCCESS" "CUBIC (UNSTABLE NETWORK) PROFILE APPLIED SUCCESSFULLY."
}
manage_tcp_optimizers() {
    while true; do
        clear
        echo -e "${B_CYAN}--- مدیریت بهینه سازهای TCP ---${C_RESET}\n"
        local current_qdisc
        current_qdisc=$(sysctl -n net.core.default_qdisc)
        local current_tcp_algo
        current_tcp_algo=$(sysctl -n net.ipv4.tcp_congestion_control)
        echo -e "الگوریتم فعال: ${B_GREEN}${current_tcp_algo^^} ${C_RESET} | صف فعال: ${B_GREEN}${current_qdisc^^}${C_RESET}\n"

        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "نصب بهینه ساز BBR PLUS"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "نصب بهینه ساز BBRV2"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "نصب بهینه ساز HYBLA PLUS"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "4" "نصب بهینه ساز CUBIC (مخصوص شبکه ناپایدار)"
        printf "  ${C_YELLOW}%2d)${C_RED}   %s\n" "5" "حذف تمام بهینه سازها و بازگشت به پیشفرض کرنل"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "6" "بازگشت به منوی قبلی"
        echo -e "${B_BLUE}-----------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"
        read -e -r choice

        case $choice in
            1) apply_bbr_plus ;;
            2) apply_bbr_v2 ;;
            3) apply_hybla_plus ;;
            4) apply_cubic_unstable ;;
            5) remove_tcp_optimizers; log_message "INFO" "OPTIMIZER CONFIG REMOVED." ;;
            6) return ;;
            *) echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}"; sleep 1 ;;
        esac
        read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
    done
}
manage_txui_panel() {
    clear
    log_message "INFO" "--- TX-UI PANEL MANAGEMENT ---"

    echo -e "${B_CYAN}--- نصب / به‌روزرسانی پنل TX-UI ---${C_RESET}\n"
    echo -e "${C_WHITE}این اسکریپت آخرین نسخه پنل TX-UI را متناسب با معماری سیستم شما نصب می‌کند.${C_RESET}"
    echo -e "${C_YELLOW}اگر فایل نصب از قبل در مسیر /root موجود باشد، از همان استفاده خواهد شد.${C_RESET}"
    echo -e "${C_YELLOW}در غیر این صورت، آخرین نسخه به صورت خودکار از گیت‌هاب دانلود می‌شود.${C_RESET}\n"
    
    printf "%b" "${B_MAGENTA}آیا برای شروع نصب / به‌روزرسانی آماده‌اید؟ (Y/N): ${C_RESET}"
    read -e -r choice
    if [[ ! "$choice" =~ ^[yY]$ ]]; then
        log_message "INFO" "PANEL INSTALLATION CANCELED."
        return
    fi

    local ARCH
    ARCH=$(uname -m)
    local XUI_ARCH
    case "${ARCH}" in
      x86_64 | x64 | amd64) XUI_ARCH="amd64" ;;
      i*86 | x86) XUI_ARCH="386" ;;
      armv8* | armv8 | arm64 | aarch64) XUI_ARCH="arm64" ;;
      armv7* | armv7) XUI_ARCH="armv7" ;;
      armv6* | armv6) XUI_ARCH="armv6" ;;
      armv5* | armv5) XUI_ARCH="armv5" ;;
      s390x) XUI_ARCH='s390x' ;;
      *) XUI_ARCH="amd64" ;;
    esac
    log_message "INFO" "DETECTED ARCHITECTURE: ${XUI_ARCH}"

    local archive_name="x-ui-linux-${XUI_ARCH}.tar.gz"
    local archive_path="/root/${archive_name}"

    if [ ! -f "$archive_path" ]; then
        log_message "INFO" "PANEL INSTALLATION FILE NOT FOUND. DOWNLOADING LATEST VERSION..."
        local download_url="https://github.com/AghayeCoder/tx-ui/releases/latest/download/${archive_name}"
        
        log_message "INFO" "DOWNLOADING FROM: ${download_url}"
        if ! wget -O "$archive_path" "$download_url"; then
            log_message "ERROR" "DOWNLOAD FAILED. PLEASE CHECK YOUR INTERNET CONNECTION."
            rm -f "$archive_path"
            read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
            return
        fi
        log_message "SUCCESS" "LATEST PANEL VERSION DOWNLOADED SUCCESSFULLY."
    else
        log_message "INFO" "USING EXISTING INSTALLATION FILE AT ${archive_path}."
    fi

    log_message "INFO" "PREPARING FOR INSTALLATION..."
    systemctl stop x-ui &>/dev/null
    rm -rf /root/x-ui
    
    tar -zxvf "$archive_path" -C /root/
    if [ ! -d "/root/x-ui" ]; then
        log_message "ERROR" "COULD NOT FIND /root/x-ui DIRECTORY AFTER EXTRACTION. THE ARCHIVE MAY BE CORRUPT."
        read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
        return
    fi

    # IMPROVED: SAFE CD COMMAND
    cd /root/x-ui || { log_message "ERROR" "COULD NOT CHANGE TO /root/x-ui DIRECTORY. INSTALLATION FAILED."; return 1; }
    
    if [ ! -f "x-ui.sh" ]; then
        log_message "ERROR" "INSTALLATION SCRIPT 'x-ui.sh' NOT FOUND IN EXTRACTED FILES."
        return 1
    fi

    log_message "INFO" "EXECUTING THE PANEL'S OWN INSTALLATION SCRIPT..."
    chmod +x x-ui.sh
    ./x-ui.sh
    
    log_message "INFO" "INSTALLATION PROCESS BY THE PANEL SCRIPT HAS FINISHED."
    echo -e "${C_YELLOW}اگر پنل به درستی نصب شده باشد، منوی آن را مشاهده کردید.${C_RESET}"
    echo -e "${C_WHITE}اکنون می‌توانید برای مدیریت پنل از دستور 'x-ui' استفاده کنید.${C_RESET}"

    read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
}

# ###########################################################################
# --- 3X-UI, WHATSAPP FIX, AND OTHER UTILITIES ---
# ###########################################################################

manage_3xui_panel() {
    clear
    log_message "INFO" "--- 3X-UI PANEL MANAGEMENT ---"

    echo -e "${B_CYAN}--- نصب / به‌روزرسانی پنل 3X-UI ---${C_RESET}\n"
    echo -e "${C_WHITE}این اسکریپت پنل 3X-UI (اثر MHSanaei) را نصب یا به‌روزرسانی می‌کند.${C_RESET}"
    echo -e "${C_YELLOW}روش نصب هوشمند است:${C_RESET}"
    echo -e "${C_YELLOW}  - اگر فایل فشرده پنل در مسیر /root موجود باشد، نصب به صورت دستی (آفلاین) انجام می‌شود.${C_RESET}"
    echo -e "${C_YELLOW}  - در غیر این صورت، نصب به صورت خودکار (آنلاین) از گیت‌هاب انجام خواهد شد.${C_RESET}\n"

    printf "%b" "${B_MAGENTA}آیا برای شروع نصب / به‌روزرسانی آماده‌اید؟ (Y/N): ${C_RESET}"
    read -e -r choice
    if [[ ! "$choice" =~ ^[yY]$ ]]; then
        log_message "INFO" "3X-UI PANEL INSTALLATION CANCELED."
        return
    fi

    # DETECT ARCHITECTURE
    local ARCH
    ARCH=$(uname -m)
    local XUI_ARCH
    case "${ARCH}" in
      x86_64 | x64 | amd64) XUI_ARCH="amd64" ;;
      i*86 | x86) XUI_ARCH="386" ;;
      armv8* | armv8 | arm64 | aarch64) XUI_ARCH="arm64" ;;
      armv7* | armv7) XUI_ARCH="armv7" ;;
      armv6* | armv6) XUI_ARCH="armv6" ;;
      armv5* | armv5) XUI_ARCH="armv5" ;;
      s390x) XUI_ARCH='s390x' ;;
      *) XUI_ARCH="amd64" ;;
    esac
    
    local archive_name="x-ui-linux-${XUI_ARCH}.tar.gz"
    local archive_path="/root/${archive_name}"
    local install_success=false

    if [ -f "$archive_path" ]; then
        # --- MANUAL/OFFLINE INSTALLATION (IMPROVED) ---
        log_message "INFO" "DETECTED LOCAL INSTALLATION FILE: ${archive_path}"
        log_message "INFO" "PROCEEDING WITH ROBUST (OFFLINE) INSTALLATION..."
        
        log_message "INFO" "CLEANING UP PREVIOUS INSTALLATIONS..."
        systemctl stop x-ui &>/dev/null
        rm -rf /usr/local/x-ui /etc/systemd/system/x-ui.service /usr/bin/x-ui /root/x-ui
        
        log_message "INFO" "EXTRACTING PANEL FILES TO /root/..."
        if tar zxvf "$archive_path" -C /root/; then
            if [ ! -d "/root/x-ui" ]; then
                log_message "ERROR" "COULD NOT FIND /root/x-ui DIRECTORY AFTER EXTRACTION."
            else
                log_message "INFO" "ENTERING /root/x-ui AND RUNNING THE PANEL'S OWN INSTALLER..."
                # IMPROVED: SAFE CD COMMAND
                cd /root/x-ui || { log_message "ERROR" "COULD NOT CHANGE TO /root/x-ui DIRECTORY. OFFLINE INSTALLATION FAILED."; return 1; }
                
                if ./x-ui.sh install; then
                    log_message "SUCCESS" "3X-UI PANEL INSTALLED SUCCESSFULLY FROM LOCAL FILE."
                    install_success=true
                else
                    log_message "ERROR" "THE PANEL'S OWN INSTALLER SCRIPT FAILED."
                fi
                cd /root/ # RETURN TO A KNOWN DIRECTORY
            fi
        else
            log_message "ERROR" "FAILED TO EXTRACT THE ARCHIVE."
        fi

    else
        # --- AUTOMATIC/ONLINE INSTALLATION ---
        log_message "INFO" "LOCAL INSTALLATION FILE NOT FOUND."
        log_message "INFO" "PROCEEDING WITH AUTOMATIC (ONLINE) INSTALLATION..."
        if ! check_internet_connection; then
            log_message "ERROR" "NO INTERNET CONNECTION. CANNOT PROCEED WITH ONLINE INSTALLATION."
        else
            if bash <(curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh); then
                 log_message "SUCCESS" "3X-UI ONLINE INSTALLATION SCRIPT EXECUTED."
                 install_success=true
            else
                 log_message "ERROR" "ONLINE INSTALLATION SCRIPT FAILED."
            fi
        fi
    fi

    if [[ "$install_success" == true ]]; then
        check_service_status "x-ui"
        echo -e "\n${B_GREEN}پنل با موفقیت نصب شد. منوی پنل برای تایید اجرا می‌شود...${C_RESET}"
        echo -e "${C_YELLOW}پس از اتمام کار با پنل، از منوی آن خارج شوید تا به اسکریپت اصلی بازگردید.${C_RESET}"
        sleep 2
        x-ui
    else
        log_message "ERROR" "3X-UI PANEL INSTALLATION FAILED. PLEASE CHECK THE LOGS."
    fi

    read -n 1 -s -r -p $'\n'"${R}برای بازگشت به منوی اصلی، یک کلید را فشار دهید...${N}"
}


fix_whatsapp_time() {
    clear
    log_message "INFO" "SETTING SERVER TIMEZONE TO FIX WHATSAPP DATE ISSUE..."
    timedatectl set-timezone Asia/Tehran
    log_message "SUCCESS" "TIMEZONE CHANGED TO ASIA/TEHRAN."
    echo -e "${GREEN}منطقه زمانی سرور با موفقیت به ASIA/TEHRAN تنظیم شد.${NC}"
    read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
}
# ###########################################################################
# --- NEW: ADVANCED WARP SCANNER ---
# ###########################################################################
manage_advanced_warp_scanner() {
    local SCANNER_DIR="/usr/local/bin"
    local SCANNER_BIN="${SCANNER_DIR}/warp-scanner"
    local SCANNER_XRAY="${SCANNER_DIR}/xray" # THE SCANNER MIGHT PLACE AN XRAY CORE HERE
    local SCANNER_REPO="bia-pain-bache/BPB-Warp-Scanner"

    _install_warp_scanner() {
        log_message "INFO" "STARTING WARP SCANNER INSTALLATION/UPDATE..."
        
        if ! command -v curl &>/dev/null || ! command -v wget &>/dev/null; then
            log_message "ERROR" "CURL AND WGET ARE REQUIRED. PLEASE INSTALL THEM."
            return 1
        fi

        local ARCH
        ARCH=$(uname -m)
        case "${ARCH}" in
          "x86_64" | "amd64") ARCH="amd64" ;;
          "aarch64" | "arm64") ARCH="arm64" ;;
          *)
            log_message "ERROR" "UNSUPPORTED ARCHITECTURE: ${ARCH}. ONLY AMD64 AND ARM64 ARE SUPPORTED BY THIS SCANNER."
            return 1
            ;;
        esac

        local DOWNLOAD_URL="https://github.com/${SCANNER_REPO}/releases/download/v1.1.1/BPB-Warp-Scanner-linux-${ARCH}.tar.gz"
        local TEMP_FILE="/tmp/warp-scanner.tar.gz"
        
        log_message "INFO" "DOWNLOADING STABLE SCANNER VERSION FROM ${DOWNLOAD_URL}"
        
        if ! curl -L --fail --connect-timeout 20 -o "$TEMP_FILE" "$DOWNLOAD_URL"; then
            log_message "WARN" "CURL FAILED. TRYING WGET AS A FALLBACK..."
            rm -f "$TEMP_FILE"
            if ! wget --timeout=20 -O "$TEMP_FILE" "$DOWNLOAD_URL"; then
                log_message "ERROR" "DOWNLOAD FAILED WITH BOTH CURL AND WGET. PLEASE CHECK YOUR SERVER'S NETWORK."
                rm -f "$TEMP_FILE"
                return 1
            fi
        fi

        if [ ! -s "$TEMP_FILE" ]; then
            log_message "ERROR" "DOWNLOADED FILE IS EMPTY. ABORTING."
            rm -f "$TEMP_FILE"
            return 1
        fi

        log_message "SUCCESS" "DOWNLOAD COMPLETED. EXTRACTING..."
        
        mkdir -p "/tmp/warp-scanner-extracted"
        if ! tar -zxvf "$TEMP_FILE" -C "/tmp/warp-scanner-extracted"; then
            log_message "ERROR" "FAILED TO EXTRACT THE .TAR.GZ ARCHIVE."
            rm -rf "$TEMP_FILE" "/tmp/warp-scanner-extracted"
            return 1
        fi
        
        local extracted_bin="/tmp/warp-scanner-extracted/BPB-Warp-Scanner"
        if [ ! -f "$extracted_bin" ]; then
             log_message "ERROR" "SCANNER BINARY NOT FOUND IN THE ARCHIVE."
             rm -rf "$TEMP_FILE" "/tmp/warp-scanner-extracted"
             return 1
        fi

        mv "$extracted_bin" "$SCANNER_BIN"
        chmod +x "$SCANNER_BIN"
        
        log_message "SUCCESS" "WARP SCANNER INSTALLED/UPDATED SUCCESSFULLY."
        rm -rf "$TEMP_FILE" "/tmp/warp-scanner-extracted"
        return 0
    }

    _uninstall_warp_scanner() {
        printf "\n%b" "${C_RED}** هشدار ** این عملیات اسکنر و هسته XRAY آن را حذف می‌کند. آیا مطمئن هستید؟ (y/n): ${C_RESET}"
        read -e -r confirm
        if [[ ! "$confirm" =~ ^[yY]$ ]]; then
            log_message "INFO" "UNINSTALLATION CANCELED."
            return
        fi
        log_message "INFO" "UNINSTALLING WARP SCANNER AND ITS COMPONENTS..."
        rm -f "$SCANNER_BIN" "$SCANNER_XRAY"
        rm -f /root/result.csv /root/warp-v4.txt /root/warp-v6.txt &>/dev/null
        log_message "SUCCESS" "WARP SCANNER UNINSTALLED."
    }

    while true; do
        clear
        echo -e "${B_CYAN}--- اسکنر پیشرفته WARP ---${C_RESET}\n"
        if [ -f "$SCANNER_BIN" ]; then
            echo -e "وضعیت: ${G}نصب شده${N}"
        else
            echo -e "وضعیت: ${R}نصب نشده${N}"
        fi
        echo ""
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "نصب / به‌روزرسانی اسکنر"
        printf "  ${C_YELLOW}%2d)${B_GREEN} %s\n" "2" "اجرای اسکنر"
        printf "  ${C_YELLOW}%2d)${C_RED}   %s\n" "3" "حذف اسکنر"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "4" "بازگشت به منوی امنیت"
        echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"
        read -e -r choice

        case $choice in
            1) 
                _install_warp_scanner
                ;;
            2)
                if [ -f "$SCANNER_BIN" ]; then
                    clear
                    log_message "INFO" "EXECUTING WARP SCANNER..."
                    echo -e "${B_YELLOW}در حال اجرای اسکنر... برای بازگشت، از منوی خود اسکنر خارج شوید.${N}\n"
                    (
                        trap '' INT
                        "$SCANNER_BIN"
                    )
                else
                    log_message "WARN" "SCANNER IS NOT INSTALLED. PLEASE INSTALL IT FIRST."
                fi
                ;;
            3)
                _uninstall_warp_scanner
                ;;
            4) return ;;
            *) echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}"; sleep 1 ;;
        esac
        read -n 1 -s -r -p $'\n'"${R}برای ادامه یک کلید را فشار دهید...${N}"
    done
}
# ###########################################################################
# --- FINAL SECURITY TOOLS & NETWORK UTILITIES ---
# ###########################################################################

manage_firewall() {
    _resolve_firewall_conflicts() {
        if systemctl is-active --quiet "firewalld.service" &>/dev/null; then
            log_message "WARN" "CONFLICTING SERVICE 'FIREWALLD' DETECTED. DISABLING AUTOMATICALLY..."
            systemctl stop firewalld.service &>/dev/null
            systemctl disable firewalld.service &>/dev/null
            systemctl mask firewalld.service &>/dev/null
            log_message "SUCCESS" "FIREWALLD SERVICE DISABLED AND MASKED SUCCESSFULLY."
            echo -e "${GREEN}برای جلوگیری از مشکلات، سرویس متناقض firewalld به صورت خودکار حذف شد.${N}"
            sleep 2
        fi
        local conflict_service=""
        if systemctl list-units --full -all | grep -q 'netfilter-persistent.service'; then
            conflict_service="netfilter-persistent"
        elif systemctl list-units --full -all | grep -q 'iptables-persistent.service'; then
            conflict_service="iptables-persistent"
        fi
        if [ -n "$conflict_service" ]; then
            if systemctl is-active --quiet "${conflict_service}.service" || systemctl is-enabled --quiet "${conflict_service}.service"; then
                log_message "WARN" "CONFLICTING SERVICE '${conflict_service}' DETECTED. DISABLING AUTOMATICALLY..."
                systemctl stop "${conflict_service}.service" &>/dev/null
                systemctl disable "${conflict_service}.service" &>/dev/null
                systemctl mask "${conflict_service}.service" &>/dev/null
                rm -f /etc/iptables/rules.v4 /etc/iptables/rules.v6 &>/dev/null
                log_message "SUCCESS" "SERVICE ${conflict_service} DISABLED AND MASKED SUCCESSFULLY."
                echo -e "${GREEN}برای جلوگیری از مشکلات، سرویس متناقض ${conflict_service} به صورت خودکار حذف شد.${N}"
                sleep 2
            fi
        fi
        return 0
    }
    
    _manage_ping_submenu() {
        local UFW_RULES_FILE_V4="/etc/ufw/before.rules"
        local UFW_RULES_FILE_V6="/etc/ufw/before6.rules"
        local ICMP_V4_PARAMS=("-p" "icmp" "--icmp-type" "echo-request")
        local ICMP_V6_PARAMS=("-p" "icmpv6" "--icmpv6-type" "echo-request")
        local V4_ACCEPT_RULE="-A ufw-before-input ${ICMP_V4_PARAMS[*]} -j ACCEPT"
        local V4_DROP_RULE="-A ufw-before-input ${ICMP_V4_PARAMS[*]} -j DROP"
        local V6_ACCEPT_RULE="-A ufw6-before-input ${ICMP_V6_PARAMS[*]} -j ACCEPT"
        local V6_DROP_RULE="-A ufw6-before-input ${ICMP_V6_PARAMS[*]} -j DROP"

        while true; do
            clear
            echo -e "${B_CYAN}--- مدیریت پینگ سرور (ICMP) ---${C_RESET}\n"
            local ping_status_val
            ping_status_val=$(check_ping_status)
            local ping_status_display
            if [[ "$ping_status_val" == "BLOCKED" ]]; then
                ping_status_display="${R}غیرفعال (BLOCKED)${N}"
            else
                ping_status_display="${G}فعال (ALLOWED)${N}"
            fi
            echo -e "وضعیت لحظه‌ای پینگ: ${ping_status_display}\n"
            printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "فعال کردن پینگ"
            printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "غیرفعال کردن پینگ"
            printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "بازگشت به منوی فایروال"
            echo -e "${B_BLUE}-------------------------------------------------------------${C_RESET}"
            printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"
            read -e -r choice

            case $choice in
                1) # ENABLE PING
                    log_message "INFO" "ENABLING PING..."
                    create_backup "$UFW_RULES_FILE_V4"
                    touch "$UFW_RULES_FILE_V6" && create_backup "$UFW_RULES_FILE_V6"
                    sed -i "\|$V4_DROP_RULE|d" "$UFW_RULES_FILE_V4"
                    sed -i "\|$V6_DROP_RULE|d" "$UFW_RULES_FILE_V6"
                    grep -qF -- "$V4_ACCEPT_RULE" "$UFW_RULES_FILE_V4" || sed -i '/^# End required lines/a '"$V4_ACCEPT_RULE" "$UFW_RULES_FILE_V4"
                    grep -qF -- "$V6_ACCEPT_RULE" "$UFW_RULES_FILE_V6" || sed -i '/^COMMIT/i '"$V6_ACCEPT_RULE" "$UFW_RULES_FILE_V6"
                    while iptables -D ufw-before-input "${ICMP_V4_PARAMS[@]}" -j DROP &>/dev/null; do :; done
                    while ip6tables -D ufw6-before-input "${ICMP_V6_PARAMS[@]}" -j DROP &>/dev/null; do :; done
                    iptables -C ufw-before-input "${ICMP_V4_PARAMS[@]}" -j ACCEPT &>/dev/null || iptables -I ufw-before-input 1 "${ICMP_V4_PARAMS[@]}" -j ACCEPT
                    ip6tables -C ufw6-before-input "${ICMP_V6_PARAMS[@]}" -j ACCEPT &>/dev/null || ip6tables -I ufw6-before-input 1 "${ICMP_V6_PARAMS[@]}" -j ACCEPT
                    log_message "SUCCESS" "PING HAS BEEN ENABLED."
                    ;;
                2) # DISABLE PING
                    log_message "INFO" "DISABLING PING..."
                    create_backup "$UFW_RULES_FILE_V4"
                    touch "$UFW_RULES_FILE_V6" && create_backup "$UFW_RULES_FILE_V6"
                    sed -i "\|$V4_ACCEPT_RULE|d" "$UFW_RULES_FILE_V4"
                    sed -i "\|$V6_ACCEPT_RULE|d" "$UFW_RULES_FILE_V6"
                    grep -qF -- "$V4_DROP_RULE" "$UFW_RULES_FILE_V4" || sed -i '/^# End required lines/a '"$V4_DROP_RULE" "$UFW_RULES_FILE_V4"
                    grep -qF -- "$V6_DROP_RULE" "$UFW_RULES_FILE_V6" || sed -i '/^COMMIT/i '"$V6_DROP_RULE" "$UFW_RULES_FILE_V6"
                    while iptables -D ufw-before-input "${ICMP_V4_PARAMS[@]}" -j ACCEPT &>/dev/null; do :; done
                    while ip6tables -D ufw6-before-input "${ICMP_V6_PARAMS[@]}" -j ACCEPT &>/dev/null; do :; done
                    iptables -C ufw-before-input "${ICMP_V4_PARAMS[@]}" -j DROP &>/dev/null || iptables -I ufw-before-input 1 "${ICMP_V4_PARAMS[@]}" -j DROP
                    ip6tables -C ufw6-before-input "${ICMP_V6_PARAMS[@]}" -j DROP &>/dev/null || ip6tables -I ufw6-before-input 1 "${ICMP_V6_PARAMS[@]}" -j DROP
                    log_message "SUCCESS" "PING HAS BEEN DISABLED."
                    ;;
                3) return ;;
                *) echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}"; sleep 1 ;;
            esac
        done
    }

    if ! command -v ufw &> /dev/null; then
        log_message "WARN" "UFW IS NOT INSTALLED. ATTEMPTING TO INSTALL AUTOMATICALLY..."
        if ! install_dependencies; then
            log_message "ERROR" "AUTOMATIC INSTALLATION OF UFW FAILED. PLEASE INSTALL IT MANUALLY."
            read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
            return
        fi
        sleep 1
    fi
    
    _resolve_firewall_conflicts
    
    while true; do
        clear
        echo -e "${B_CYAN}--- مدیریت فایروال (UFW) ---${C_RESET}\n"
        local UFW_STATUS
        if ufw status | grep -q "Status: active"; then
            UFW_STATUS="${G}فعال (ACTIVE)${N}"
        else
            UFW_STATUS="${R}غیرفعال (INACTIVE)${N}"
        fi
        echo -e "  ${C_WHITE}وضعیت فعلی فایروال:${C_RESET} ${UFW_STATUS}\n"
        echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "فعال کردن فایروال (ENABLE)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "غیرفعال کردن فایروال (DISABLE)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "مشاهده وضعیت و قوانین (STATUS)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "4" "باز کردن یک پورت (ALLOW)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "5" "حذف یک قانون بر اساس شماره (DELETE)"
        printf "  ${C_YELLOW}%2d)${B_GREEN} %s\n" "6" "افزودن خودکار پورت‌های باز (AUTO-ADD)"
        printf "  ${C_YELLOW}%2d)${B_YELLOW} %s\n" "7" "مدیریت پینگ سرور (ICMP)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "8" "بازگشت"
        echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"; read -e -r choice

        case $choice in
            1)
                log_message "INFO" "ENABLING FIREWALL..."
                local ssh_port
                ssh_port=$(ss -lntp | grep sshd | awk '{print $4}' | sed 's/.*://' | head -n 1)
                if [[ -n "$ssh_port" ]]; then
                    echo -e "${Y}پورت SSH شما (${ssh_port}) شناسایی شد و به صورت خودکار باز شد.${N}"
                    ufw allow "$ssh_port/tcp" >/dev/null 2>&1
                else
                    log_message "WARN" "COULD NOT DETECT SSH PORT! MAKE SURE TO ALLOW IT MANUALLY."
                fi
                ufw default deny incoming >/dev/null 2>&1
                ufw default allow outgoing >/dev/null 2>&1
                echo "y" | ufw enable
                systemctl enable ufw.service >/dev/null 2>&1
                log_message "SUCCESS" "UFW FIREWALL ENABLED AND SECURED WITH DEFAULT RULES."
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            2)
                log_message "INFO" "DISABLING FIREWALL..."
                ufw disable
                log_message "SUCCESS" "UFW FIREWALL DISABLED."
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            3)
                clear
                echo -e "${B_CYAN}--- وضعیت و قوانین فعلی فایروال ---${C_RESET}\n"
                ufw status verbose
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            4) 
                printf "%b" "${B_MAGENTA}لطفاً شماره پورت را وارد کنید (مثال: 443 یا 8000:9000): ${C_RESET}"
                read -e -r port_to_allow
                if [[ -n "$port_to_allow" ]]; then
                    ufw allow "$port_to_allow"
                    log_message "SUCCESS" "REQUEST TO ADD RULE FOR '${port_to_allow}' SENT TO THE FIREWALL."
                else
                    log_message "WARN" "INVALID INPUT."
                fi
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            5) 
                clear
                echo -e "${B_CYAN}--- قوانین فعلی برای حذف (بر اساس شماره) ---${C_RESET}\n"
                ufw status numbered
                printf "\n%b" "${B_MAGENTA}شماره قانون (RULE NUMBER) که می‌خواهید حذف کنید را وارد نمایید: ${C_RESET}"
                read -e -r rule_to_delete
                if [[ "$rule_to_delete" =~ ^[0-9]+$ ]]; then
                    yes | ufw delete "$rule_to_delete"
                    log_message "SUCCESS" "REQUEST TO DELETE RULE NUMBER ${rule_to_delete} SENT."
                else
                    log_message "WARN" "INVALID RULE NUMBER."
                fi
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            6) 
                clear
                echo -e "${B_CYAN}--- افزودن خودکار پورت های در حال استفاده ---${C_RESET}\n"
                local ssh_port
                ssh_port=$(ss -lntp | grep sshd | awk '{print $4}' | sed 's/.*://' | head -n 1)
                mapfile -t listening_ports < <(ss -lntu | grep 'LISTEN' | awk '{print $5}' | sed 's/.*://' | sort -un)
                mapfile -t all_ports_to_allow < <(printf "%s\n" "${listening_ports[@]}" "$ssh_port" | sort -un)
                if [ ${#all_ports_to_allow[@]} -eq 0 ]; then
                    log_message "INFO" "NO ACTIVE LISTENING PORTS FOUND TO ADD."
                else
                    echo -e "${C_WHITE}پورت‌های زیر شناسایی و قوانین آنها به فایروال اضافه شد:${N}"
                    for port in "${all_ports_to_allow[@]}"; do
                        if [[ -n "$port" ]]; then
                           ufw allow "$port" > /dev/null
                           if [[ "$port" == "$ssh_port" ]]; then
                                echo "  - PORT ${port} (SSH) ${G}ADDED${N}"
                           else
                                echo "  - PORT ${port} ${G}ADDED${N}"
                           fi
                        fi
                    done
                    log_message "SUCCESS" "ALL ACTIVE LISTENING PORTS HAVE BEEN ALLOWED IN THE FIREWALL."
                    ufw reload >/dev/null
                fi
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            7)
                _manage_ping_submenu
                ;;
            8)
                return
                ;;
            *)
                echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}"; sleep 1
                ;;
        esac
    done
}
manage_abuse_defender() {
    if ! ufw status | grep -q "Status: active"; then
        log_message "WARN" "UFW (FIREWALL) IS NOT ACTIVE. PLEASE ENABLE IT FIRST FROM THE FIREWALL MENU."
        echo -e "\n${C_RED}خطا: فایروال UFW فعال نیست. لطفاً ابتدا از منوی 'مدیریت فایروال' آن را فعال کنید.${N}"
        read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
        return
    fi
    
    local ABUSE_IPS=(
        "185.105.237.0/24" "172.93.52.0/24" "5.2.72.0/24" "5.2.78.0/24" "5.2.82.0/24"
        "5.2.83.0/24" "5.2.86.0/24" "5.2.87.0/24" "46.224.0.0/16" "79.175.128.0/17"
        "81.12.0.0/17" "85.133.128.0/18" "89.198.0.0/16" "91.98.0.0/16" "94.182.0.0/15"
        "185.5.96.0/22" "185.13.36.0/22" "185.88.152.0/22" "188.94.152.0/21" "213.108.224.0/20"
        "217.218.0.0/15"
    )
    local COMMENT_TAG="IRNET-ABUSE-DEFENDER"

    while true; do
        clear
        echo -e "${B_CYAN}--- مدیریت فایروال ABUSE (مبتنی بر UFW) ---${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "مسدودسازی رنج آی‌پی‌های ABUSE"
        printf "  ${C_YELLOW}%2d)${C_GREEN} %s\n" "2" "افزودن آی‌پی به لیست سفید (WHITELIST)"
        printf "  ${C_YELLOW}%2d)${C_RED}   %s\n" "3" "مسدودسازی دستی یک آی‌پی"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "4" "مشاهده قوانین فایروال (UFW)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "5" "پاک کردن تمام قوانین ABUSE (رفع مسدودی)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "6" "بازگشت به منوی امنیت"
        echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"
        read -e -r choice

        case $choice in
            1) # BLOCK ABUSE IP-RANGES
                log_message "INFO" "BLOCKING ABUSE IP RANGES VIA UFW..."
                local add_count=0
                for ip in "${ABUSE_IPS[@]}"; do
                    if ! ufw status | grep -qw "$ip"; then
                        ufw deny from "$ip" to any comment "$COMMENT_TAG" >/dev/null
                        ((add_count++))
                    fi
                done
                log_message "SUCCESS" "$add_count NEW UFW RULES ADDED. ABUSE IPS BLOCKED."
                echo -e "\n${G}عملیات مسدودسازی با موفقیت انجام شد. $add_count قانون جدید به UFW اضافه شد.${N}"
                ufw reload >/dev/null
                ;;
            2) # WHITELIST AN IP/IP-RANGES MANUALLY
                printf "\n%b" "${B_MAGENTA}آی‌پی یا رنج مورد نظر برای افزودن به لیست سفید را وارد کنید: ${C_RESET}"
                read -e -r ip_to_whitelist
                if [[ -n "$ip_to_whitelist" ]]; then
                    ufw allow from "$ip_to_whitelist" to any comment "${COMMENT_TAG}-WHITELIST"
                    log_message "SUCCESS" "IP $ip_to_whitelist WHITELISTED IN UFW."
                    echo -e "\n${G}آی‌پی $ip_to_whitelist به لیست سفید (WHITELIST) فایروال اضافه شد.${N}"
                    ufw reload >/dev/null
                else
                    log_message "WARN" "NO IP PROVIDED."
                fi
                ;;
            3) # BLOCK AN IP/IP-RANGES MANUALLY
                printf "\n%b" "${B_MAGENTA}آی‌پی یا رنج مورد نظر برای مسدودسازی دستی را وارد کنید: ${C_RESET}"
                read -e -r ip_to_block
                if [[ -n "$ip_to_block" ]]; then
                    ufw deny from "$ip_to_block" to any comment "${COMMENT_TAG}-MANUAL"
                    log_message "SUCCESS" "IP $ip_to_block BLOCKED IN UFW."
                    echo -e "\n${G}آی‌پی $ip_to_block به صورت دستی در فایروال مسدود شد.${N}"
                    ufw reload >/dev/null
                else
                    log_message "WARN" "NO IP PROVIDED."
                fi
                ;;
            4) # VIEW RULES
                clear
                echo -e "${B_CYAN}--- لیست قوانین فعلی فایروال (UFW) ---${C_RESET}\n"
                ufw status numbered
                echo -e "\n${C_YELLOW}قوانین اضافه شده توسط این اسکریپت دارای کامنت '${COMMENT_TAG}' هستند.${N}"
                ;;
            5) # CLEAR ALL RULES (UNBLOCK ABUSE IPS)
                log_message "INFO" "REMOVING ALL ABUSE DEFENDER RULES FROM UFW..."
                local rules_to_delete
                mapfile -t rules_to_delete < <(ufw status numbered | grep "$COMMENT_TAG" | awk -F'[][]' '{print $2}' | sort -rn)
                
                if [ ${#rules_to_delete[@]} -eq 0 ]; then
                    log_message "INFO" "NO ABUSE DEFENDER RULES FOUND TO DELETE."
                    echo -e "\n${Y}هیچ قانونی برای حذف یافت نشد.${N}"
                else
                    echo -e "${C_YELLOW}در حال حذف ${#rules_to_delete[@]} قانون...${N}"
                    for rule_num in "${rules_to_delete[@]}"; do
                        yes | ufw delete "$rule_num" >/dev/null
                    done
                    log_message "SUCCESS" "${#rules_to_delete[@]} ABUSE RULES REMOVED FROM UFW."
                    echo -e "\n${G}تمام قوانین مسدودسازی مربوط به لیست ABUSE با موفقیت حذف شدند.${N}"
                    ufw reload >/dev/null
                fi
                ;;
            6) # EXIT
                return
                ;;
            *)
                echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}"; sleep 1
                continue
                ;;
        esac
        read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
    done
}
manage_xui_assistant() {
    local ASSISTANT_DIR="/root/xui-assistant"
    local EXECUTABLE_NAME="menu.sh"
    local SYMLINK_PATH="/usr/local/bin/x-ui-assistant"

    _install_xui_assistant() {
        log_message "INFO" "STARTING X-UI ASSISTANT INSTALLATION..."

        local deps=("git" "python3" "python3-pip")
        local missing_deps=()
        for dep in "${deps[@]}"; do
            if ! command -v "$dep" &>/dev/null; then
                missing_deps+=("$dep")
            fi
        done

        if [[ ${#missing_deps[@]} -gt 0 ]]; then
            log_message "WARN" "INSTALLING MISSING DEPENDENCIES FOR ASSISTANT: ${missing_deps[*]}"
            apt-get update -qq
            if ! DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${missing_deps[@]}"; then
                log_message "ERROR" "FAILED TO INSTALL DEPENDENCIES. CANNOT PROCEED."
                return 1
            fi
        fi

        local GIT_REPO_URL="https://github.com/dev-ir/xui-assistant.git"
        log_message "INFO" "CLONING REPOSITORY FROM: $GIT_REPO_URL"
        rm -rf "$ASSISTANT_DIR"
        if ! git clone "$GIT_REPO_URL" "$ASSISTANT_DIR"; then
            log_message "ERROR" "GIT CLONE FAILED. PLEASE CHECK YOUR CONNECTION AND GIT INSTALLATION."
            return 1
        fi

        log_message "INFO" "INSTALLING PYTHON REQUIREMENTS..."
        if ! python3 -m pip install requests prettytable pycryptodome; then
            log_message "ERROR" "FAILED TO INSTALL PYTHON REQUIREMENTS."
            return 1
        fi

        log_message "INFO" "CREATING SYSTEM-WIDE COMMAND..."
        local executable_script_path="$ASSISTANT_DIR/$EXECUTABLE_NAME"
        if [ -f "$executable_script_path" ]; then
            chmod +x "$executable_script_path"
            ln -sf "$executable_script_path" "$SYMLINK_PATH"
            log_message "SUCCESS" "X-UI ASSISTANT INSTALLED SUCCESSFULLY."
            echo -e "\n${G}دستیار با موفقیت نصب شد. برای اجرا از گزینه ۴ در همین منو یا دستور 'x-ui-assistant' در ترمینال استفاده کنید.${N}"
        else
            log_message "ERROR" "MAIN SCRIPT FILE '$EXECUTABLE_NAME' NOT FOUND AFTER CLONING."
            return 1
        fi
        return 0
    }

    _uninstall_xui_assistant() {
        printf "\n%b" "${C_RED}** هشدار ** این عملیات دستیار X-UI را به طور کامل حذف می‌کند. آیا مطمئن هستید؟ (y/n): ${C_RESET}"
        read -e -r confirm
        if [[ ! "$confirm" =~ ^[yY]$ ]]; then
            log_message "INFO" "UNINSTALLATION CANCELED BY USER."
            echo -e "\nعملیات حذف لغو شد."
            return
        fi
        
        log_message "INFO" "UNINSTALLING X-UI ASSISTANT..."
        rm -f "$SYMLINK_PATH"
        rm -rf "$ASSISTANT_DIR"
        log_message "SUCCESS" "X-UI ASSISTANT HAS BEEN UNINSTALLED."
        echo -e "\n${G}دستیار X-UI با موفقیت حذف شد.${N}"
    }

    while true; do
        clear
        echo -e "${B_CYAN}--- مدیریت دستیار پنل X-UI (چند ادمین) ---${C_RESET}\n"
        
        if [ -f "$SYMLINK_PATH" ]; then
            echo -e "وضعیت: ${G}نصب شده${N}"
        else
            echo -e "وضعیت: ${R}نصب نشده${N}"
        fi

        echo ""
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "نصب دستیار"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "به‌روزرسانی دستیار (نصب مجدد)"
        printf "  ${C_YELLOW}%2d)${C_RED}   %s\n" "3" "حذف دستیار"
        printf "  ${C_YELLOW}%2d)${B_GREEN} %s\n" "4" "اجرای منوی مدیریت دستیار"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "5" "بازگشت"
        echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"
        read -e -r choice

        case $choice in
            1|2)
                _install_xui_assistant
                ;;
            3)
                if [ -f "$SYMLINK_PATH" ]; then
                    _uninstall_xui_assistant
                else
                    log_message "INFO" "ASSISTANT IS NOT INSTALLED. NOTHING TO UNINSTALL."
                    echo -e "\n${Y}دستیار از قبل نصب نشده است.${N}"
                fi
                ;;
            4)
                if [ -f "$SYMLINK_PATH" ]; then
                    clear
                    (
                        trap '' INT
                        "$SYMLINK_PATH"
                    )
                else
                    log_message "INFO" "ASSISTANT IS NOT INSTALLED. CANNOT RUN."
                    echo -e "\n${Y}دستیار نصب نیست. لطفاً ابتدا با استفاده از گزینه ۱ آن را نصب کنید.${N}"
                fi
                ;;
            5)
                return
                ;;
            *)
                echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}"; sleep 1
                continue
                ;;
        esac
        read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
    done
}

manage_tc_script() {
  clear
  echo -e "${B_CYAN}--- بهینه سازی سرعت (TC) ---${C_RESET}\n"
  printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "نصب و تست اسکریپت بهینه‌سازی TC"
  printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "حذف اسکریپت بهینه‌سازی TC"
  printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "بازگشت به منوی بهینه سازی"
  echo -e "${B_BLUE}-----------------------------------${C_RESET}"
  printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"
  read -e -r choice
  
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
    echo "$(date): CAKE OPTIMIZATION COMPLETE" >> /var/log/tc_smart.log
    echo 'CAKE OPTIMIZATION COMPLETE'
elif tc qdisc add dev $INTERFACE root fq_codel limit 10240 flows 1024 target 5ms interval 100ms 2>/dev/null; then
    echo "$(date): FQ_CODEL OPTIMIZATION COMPLETE" >> /var/log/tc_smart.log
    echo 'FQ_CODEL OPTIMIZATION COMPLETE'
elif tc qdisc add dev $INTERFACE parent 1: classid 1:1 htb rate 1000mbit ceil 1000mbit 2>/dev/null && \
     tc class add dev $INTERFACE parent 1:1 classid 1:11 htb rate 1000mbit ceil 1000mbit 2>/dev/null && \
     tc qdisc add dev $INTERFACE parent 1:11 netem delay 1ms loss 0.005% duplicate 0.05% reorder 0.5% 2>/dev/null; then
    echo "$(date): HTB+NETEM OPTIMIZATION COMPLETE" >> /var/log/tc_smart.log
    echo 'HTB+NETEM OPTIMIZATION COMPLETE'
else
    tc qdisc add dev $INTERFACE root netem delay 1ms loss 0.005% duplicate 0.05% reorder 0.5% 2>/dev/null
    echo "$(date): FALLBACK NETEM OPTIMIZATION COMPLETE" >> /var/log/tc_smart.log
    echo 'FALLBACK NETEM OPTIMIZATION COMPLETE'
fi
tc qdisc show dev $INTERFACE | grep -E 'cake|fq_codel|htb|netem'
echo -e "\033[38;5;208mIRNET\033[0m"
EOF
      chmod +x "$SCRIPT_PATH"
      (crontab -l 2>/dev/null | grep -v "$SCRIPT_PATH"; echo "@reboot sleep 30 && \"$SCRIPT_PATH\"") | crontab -
      log_message "SUCCESS" "TC OPTIMIZATION SCRIPT INSTALLED SUCCESSFULLY."
      echo -e "\n${C_YELLOW}--- اجرای خودکار تست برای تایید نصب ---${C_RESET}"
      bash "$SCRIPT_PATH" && echo "تست موفق بود." && tail -5 /var/log/tc_smart.log
      ;;
    2)
      rm -f "$SCRIPT_PATH"
      (crontab -l 2>/dev/null | grep -v "$SCRIPT_PATH" | crontab -)
      log_message "SUCCESS" "TC OPTIMIZATION SCRIPT AND ITS CRON JOB REMOVED."
      ;;
    3) return ;;
    *) echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}" ;;
  esac
  read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
}

manage_custom_sysctl() {
    local conf_file="/etc/sysctl.d/98-custom-optimizer.conf"
    while true; do
        clear
        echo -e "${B_CYAN}--- بهینه ساز SYSCTL اختصاصی ---${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "اعمال تنظیمات اختصاصی"
        printf "  ${C_YELLOW}%2d)${C_RED}   %s\n" "2" "حذف تنظیمات اختصاصی"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "بازگشت"
        echo -e "${B_BLUE}-----------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"
        read -e -r choice
        case $choice in
            1)
                log_message "INFO" "APPLYING CUSTOM SYSCTL SETTINGS..."
                create_backup "$conf_file"
                tee "$conf_file" > /dev/null <<'EOF'
# CUSTOM SYSCTL SETTINGS BY IRNET
net.core.rmem_max=134217728
net.core.wmem_max=134217728
net.core.rmem_default=16777216
net.core.wmem_default=16777216
net.core.netdev_max_backlog=30000
net.core.somaxconn=32768
net.ipv4.tcp_rmem=8192 131072 134217728
net.ipv4.tcp_wmem=8192 131072 134217728
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_fin_timeout=10
net.ipv4.tcp_keepalive_time=600
net.ipv4.tcp_keepalive_intvl=30
net.ipv4.tcp_keepalive_probes=3
net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.tcp_max_tw_buckets=2000000
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_window_scaling=1
net.ipv4.tcp_timestamps=1
net.ipv4.tcp_sack=1
net.ipv4.tcp_ecn=2
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_no_metrics_save=1
net.ipv4.tcp_mtu_probing=2
net.ipv4.ip_forward=1
net.ipv4.ip_default_ttl=64
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.all.send_redirects=0
net.netfilter.nf_conntrack_max=1048576
vm.swappiness=10
fs.file-max=2097152
fs.nr_open=2097152
net.core.default_qdisc=fq_codel
EOF
                sysctl -p "$conf_file"
                log_message "SUCCESS" "CUSTOM SYSCTL SETTINGS APPLIED SUCCESSFULLY."
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            2)
                if [ -f "$conf_file" ]; then
                    rm -f "$conf_file"
                    sysctl --system &>/dev/null
                    log_message "SUCCESS" "CUSTOM SYSCTL SETTINGS FILE REMOVED."
                else
                    log_message "INFO" "CUSTOM SETTINGS FILE NOT FOUND."
                fi
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            3) return ;;
            *) echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}"; sleep 1 ;;
        esac
    done
}
manage_tc_qleen_mtu() {
    if [[ -z "$PRIMARY_INTERFACE" ]]; then
        log_message "ERROR" "PRIMARY NETWORK INTERFACE NOT FOUND."
        read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
        return
    fi
    
    local TC_CONFIG_FILE="$CONFIG_DIR/tc.conf"
    local TC_SERVICE_FILE="/etc/systemd/system/irnet-tc-persistent.service"

    while true; do
        clear
        echo -e "${B_CYAN}--- بهینه ساز QLEEN & MTU اختصاصی ---${C_RESET}"
        echo -e "کارت شبکه شناسایی شده: ${B_YELLOW}${PRIMARY_INTERFACE}${N}\n"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "اعمال پروفایل CAKE (TXQUEUELEN 500, MTU 1380)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "اعمال پروفایل FQ_CODEL (TXQUEUELEN 1500, MTU 1380)"
        printf "  ${C_YELLOW}%2d)${C_RED}   %s\n" "3" "حذف تنظیمات TC و بازگشت به پیشفرض"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "4" "بازگشت"
        echo -e "${B_BLUE}-----------------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"
        read -e -r choice
        
        case $choice in
            1|2)
                local profile_name qdisc txq mtu
                if [ "$choice" -eq 1 ]; then
                    profile_name="CAKE"
                    qdisc="cake"
                    txq="500"
                    mtu="1380"
                else
                    profile_name="FQ_CODEL"
                    qdisc="fq_codel"
                    txq="1500"
                    mtu="1380"
                fi

                log_message "INFO" "APPLYING $profile_name PROFILE TO $PRIMARY_INTERFACE..."
                tc qdisc del dev "$PRIMARY_INTERFACE" root 2>/dev/null
                tc qdisc add dev "$PRIMARY_INTERFACE" root "$qdisc"
                ip link set dev "$PRIMARY_INTERFACE" txqueuelen "$txq"
                ip link set dev "$PRIMARY_INTERFACE" mtu "$mtu"
                log_message "SUCCESS" "$profile_name PROFILE APPLIED SUCCESSFULLY."

                log_message "INFO" "MAKING TC PROFILE PERSISTENT..."
                echo "TC_PROFILE=${profile_name}" > "$TC_CONFIG_FILE"
                echo "INTERFACE=${PRIMARY_INTERFACE}" >> "$TC_CONFIG_FILE"
                
                cat > "$TC_SERVICE_FILE" << EOF
[Unit]
Description=Persistent TC Profile by IRNET Script ($profile_name)
After=network.target
Wants=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c "source \"$TC_CONFIG_FILE\" && tc qdisc del dev \\\$INTERFACE root 2>/dev/null; if [ \\\"\\\$TC_PROFILE\\\" = \\\"CAKE\\\" ]; then tc qdisc add dev \\\$INTERFACE root cake; ip link set dev \\\$INTERFACE txqueuelen 500; ip link set dev \\\$INTERFACE mtu 1380; elif [ \\\"\\\$TC_PROFILE\\\" = \\\"FQ_CODEL\\\" ]; then tc qdisc add dev \\\$INTERFACE root fq_codel; ip link set dev \\\$INTERFACE txqueuelen 1500; ip link set dev \\\$INTERFACE mtu 1380; fi"

[Install]
WantedBy=multi-user.target
EOF
                systemctl daemon-reload
                systemctl enable --now irnet-tc-persistent.service
                check_service_status "irnet-tc-persistent.service"

                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            3)
                log_message "INFO" "REMOVING TC QDISC FROM $PRIMARY_INTERFACE..."
                tc qdisc del dev "$PRIMARY_INTERFACE" root 2>/dev/null
                
                log_message "INFO" "REMOVING PERSISTENT TC SERVICE..."
                systemctl disable --now irnet-tc-persistent.service &>/dev/null
                rm -f "$TC_SERVICE_FILE"
                rm -f "$TC_CONFIG_FILE"
                systemctl daemon-reload

                log_message "SUCCESS" "TC SETTINGS AND ITS PERSISTENT SERVICE REMOVED."
                read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
                ;;
            4) return ;;
            *) echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}"; sleep 1 ;;
        esac
    done
}

run_packet_loss_test() {
    clear
    echo -e "${B_CYAN}--- تست پکت لاست، پینگ و مسیر شبکه (MTR) ---${C_RESET}\n"
    if ! command -v mtr &> /dev/null || ! command -v jq &> /dev/null; then
        log_message "ERROR" "MTR AND JQ TOOLS ARE REQUIRED FOR THIS TEST. PLEASE INSTALL THEM."
        read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
        return
    fi

    local target_ip
    echo -e "${B_MAGENTA}لطفاً آدرس IP سرور مقصد را وارد کنید:${C_RESET}"
    read -e -r target_ip

    if ! is_valid_ip "$target_ip"; then
        log_message "ERROR" "THE IP ADDRESS ENTERED IS NOT VALID."; sleep 2
        return
    fi
    clear
    echo -e "${B_CYAN}--- تست پکت لاست، پینگ و مسیر شبکه (MTR) ---${C_RESET}\n"
    echo -e "\n${C_YELLOW}در حال اجرای تست MTR برای مقصد ${target_ip}... (این عملیات حدود 1 دقیقه طول می‌کشد)${C_RESET}"
    echo -e "${C_CYAN}برای لغو تست و بازگشت به منو، کلیدهای CTRL+C را فشار دهید.${C_RESET}\n"
    
    local MTR_JSON
    (
        trap '' INT
        MTR_JSON=$(mtr -j -c 50 --no-dns "$target_ip")
    )

    if ! echo "$MTR_JSON" | jq . > /dev/null 2>&1; then
        log_message "ERROR" "PARSING FAILED. MTR DID NOT PRODUCE VALID OUTPUT OR WAS CANCELED."
        read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
        return
    fi

    echo -e "${B_BLUE}-----------------------------------------------------------------------------------------${C_RESET}"
    printf "%-4s%-3s%-22s %-8s %-5s %-7s %-7s %-7s %-7s %-7s\n" " " "" "HOST" "LOSS%" "SNT" "LAST" "AVG" "BEST" "WRST" "STDEV"
    
    echo "$MTR_JSON" | jq -c '.report.hubs[]' | while IFS= read -r line; do
        local count host loss snt last avg best wrst stdev
        count=$(echo "$line" | jq -r '.count')
        host=$(echo "$line" | jq -r '.host')
        loss=$(echo "$line" | jq -r '."Loss%"')
        snt=$(echo "$line" | jq -r '.Snt')
        last=$(echo "$line" | jq -r '.Last')
        avg=$(echo "$line" | jq -r '.Avg')
        best=$(echo "$line" | jq -r '.Best')
        wrst=$(echo "$line" | jq -r '.Wrst')
        stdev=$(echo "$line" | jq -r '.StDev')
        printf " %-3s|-- %-22s %-7.1f%% %-5.0f %-7.1f %-7.1f %-7.1f %-7.1f %-7.1f\n" "$count." "$host" "$loss" "$snt" "$last" "$avg" "$best" "$wrst" "$stdev"
    done
    echo -e "${B_BLUE}-----------------------------------------------------------------------------------------${C_RESET}"
    log_message "SUCCESS" "MTR TEST COMPLETED."
    
    echo -e "${B_CYAN}--- تحلیل خودکار نتیجه ---${N}\n"

    local first_hop_loss final_loss final_avg_ping
    first_hop_loss=$(echo "$MTR_JSON" | jq -r '.report.hubs[0]."Loss%"')
    final_loss=$(echo "$MTR_JSON" | jq -r '.report.hubs[-1]."Loss%"')
    final_avg_ping=$(echo "$MTR_JSON" | jq -r '.report.hubs[-1].Avg')

    echo -e "${C_WHITE}▪️ پکت لاست در مبدأ (گام اول):${N} ${Y}${first_hop_loss:-0}%${N}"
    echo -e "${C_WHITE}▪️ پکت لاست تا مقصد نهایی:${N} ${Y}${final_loss:-0}%${N}"
    echo -e "${C_WHITE}▪️ میانگین پینگ تا مقصد نهایی:${N} ${Y}${final_avg_ping:-0} ms${N}\n"

    if (( $(echo "$first_hop_loss > 10" | bc -l) )); then
        echo -e " ${R}❌ نتیجه: ارتباط بسیار ضعیف است.${N}"
        echo -e "   دلیل: پکت لاست شدید در مبدأ (${first_hop_loss}%) نشان‌دهنده مشکل جدی در شبکه سرور ایران است."
        echo -e "   این سرور به هیچ وجه برای تونل زدن مناسب نیست."
    elif (( $(echo "$final_loss > 5" | bc -l) )); then
        echo -e " ${R}❌ نتیجه: ارتباط بسیار ضعیف است.${N}"
        echo -e "   دلیل: پکت لاست بالا در مقصد (${final_loss}%) کیفیت هر نوع تونلی را به شدت مختل می‌کند."
    elif (( $(echo "$final_loss > 0" | bc -l) )); then
        echo -e " ${Y}⚠️ نتیجه: ارتباط ضعیف است.${N}"
        echo -e "   دلیل: وجود پکت لاست در مقصد (${final_loss}%) می‌تواند باعث افت کیفیت و قطعی‌های موقت شود."
        echo -e "   این ارتباط برای کارهای حساس مانند بازی یا تماس تصویری توصیه نمی‌شود."
    elif (( $(echo "$final_avg_ping > 200" | bc -l) )); then
        echo -e " ${B}🟡 نتیجه: ارتباط قابل قبول اما با تاخیر (LATENCY) بسیار بالا است.${N}"
        echo -e "   پکت لاست 0% است که عالیست، اما پینگ بالا (${final_avg_ping}ms) ممکن است باعث کندی شود."
    else
        echo -e " ${G}✅ نتیجه: ارتباط خوب و پایدار است.${N}"
        echo -e "   پکت لاست 0% و پینگ مناسب است. این سرور برای تونل زدن کیفیت خوبی دارد."
    fi

    read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
}
advanced_mirror_test() {
    clear
    log_message "INFO" "--- ADVANCED APT REPOSITORY ANALYSIS ---"
    
    test_mirror_speed() {
        local url="$1/ls-lR.gz"
        local speed_bytes_per_sec
        speed_bytes_per_sec=$(curl -s -o /dev/null -w '%{speed_download}' --max-time 3 "$url" 2>/dev/null | cut -d'.' -f1)

        if [[ -z "$speed_bytes_per_sec" || "$speed_bytes_per_sec" -lt 10240 ]]; then
            echo "0"
        else
            echo $((speed_bytes_per_sec / 1024))
        fi
    }

    apply_selected_mirror() {
        local mirror_url="$1"
        local mirror_name="$2"
        log_message "INFO" "APPLYING REPOSITORY: $mirror_name ($mirror_url)..."
        if ! command -v lsb_release &> /dev/null; then
            log_message "ERROR" "LSB-RELEASE PACKAGE IS NOT INSTALLED. CANNOT UPDATE SOURCES."; return 1
        fi
        
        local codename ubuntu_version
        codename=$(lsb_release -cs)
        ubuntu_version=$(lsb_release -sr)
        
        if [[ -f /etc/apt/sources.list.d/ubuntu.sources ]] && (echo "$ubuntu_version" | grep -q -E "^(22\.04|22\.10|23\.|24\.)"); then
            log_message "INFO" "MODERN OS DETECTED (UBUNTU $ubuntu_version). USING DEB822 FORMAT."
            local sources_file="/etc/apt/sources.list.d/ubuntu.sources"
            create_backup "$sources_file"
            tee "$sources_file" > /dev/null <<EOF
# GENERATED BY LINUX OPTIMIZER SCRIPT | MIRROR: ${mirror_name}
Types: deb
URIs: ${mirror_url}
Suites: ${codename} ${codename}-updates ${codename}-backports
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

Types: deb
URIs: ${mirror_url}
Suites: ${codename}-security
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
EOF
        else
            log_message "INFO" "LEGACY OS DETECTED (UBUNTU $ubuntu_version). USING SOURCES.LIST FORMAT."
            local sources_file="/etc/apt/sources.list"
            create_backup "$sources_file"
            tee "$sources_file" > /dev/null <<EOF
# GENERATED BY LINUX OPTIMIZER SCRIPT | MIRROR: ${mirror_name}
deb ${mirror_url} ${codename} main restricted universe multiverse
deb ${mirror_url} ${codename}-updates main restricted universe multiverse
deb ${mirror_url} ${codename}-backports main restricted universe multiverse
deb ${mirror_url} ${codename}-security main restricted universe multiverse
EOF
        fi
        
        log_message "INFO" "UPDATING PACKAGE LISTS..."
        if apt-get update -o Acquire::AllowInsecureRepositories=true -o Acquire::AllowDowngradeToInsecureRepositories=true; then
            log_message "SUCCESS" "✅ REPOSITORY SUCCESSFULLY CHANGED TO $mirror_name AND PACKAGE LISTS UPDATED."
        else
            log_message "ERROR" "❌ FAILED TO UPDATE PACKAGE LISTS. PLEASE CHECK THE ISSUE MANUALLY."
        fi
    }

    choose_custom_mirror_from_list() {
        printf "\n%b" "${B_MAGENTA}شماره رتبه مخزن مورد نظر خود را برای اعمال وارد کنید: ${C_RESET}"
        read -e -r rank_choice
        if [[ ! "$rank_choice" =~ ^[0-9]+$ ]] || [ "$rank_choice" -lt 1 ] || [ "$rank_choice" -gt "${#MIRROR_LIST_CACHE[@]}" ]; then
            log_message "ERROR" "INVALID SELECTION. PLEASE ENTER A NUMBER FROM THE LIST ABOVE."
            return
        fi
        local selected_mirror_info="${MIRROR_LIST_CACHE[$((rank_choice - 1))]}"
        local selected_mirror_url
        selected_mirror_url=$(echo "$selected_mirror_info" | cut -d'|' -f2)
        local selected_mirror_name
        selected_mirror_name=$(echo "$selected_mirror_info" | cut -d'|' -f3)
        apply_selected_mirror "$selected_mirror_url" "$selected_mirror_name"
    }

    local mirrors=(
        "https://mirrors.pardisco.co/ubuntu/" "http://mirror.aminidc.com/ubuntu/" "http://mirror.faraso.org/ubuntu/"
        "https://ir.ubuntu.sindad.cloud/ubuntu/" "https://ubuntu-mirror.kimiahost.com/" "https://archive.ubuntu.petiak.ir/ubuntu/"
        "https://ubuntu.hostiran.ir/ubuntuarchive/" "https://ubuntu.bardia.tech/" "https://mirror.iranserver.com/ubuntu/"
        "https://ir.archive.ubuntu.com/ubuntu/" "https://mirror.0-1.cloud/ubuntu/" "http://linuxmirrors.ir/pub/ubuntu/"
        "http://repo.iut.ac.ir/repo/Ubuntu/" "https://ubuntu.shatel.ir/ubuntu/" "http://ubuntu.byteiran.com/ubuntu/"
        "https://mirror.rasanegar.com/ubuntu/" "http://mirrors.sharif.ir/ubuntu/" "http://mirror.ut.ac.ir/ubuntu/"
        "http://archive.ubuntu.com/ubuntu/"
    )
    mirrors=($(printf "%s\n" "${mirrors[@]}" | sort -u))

    echo -e "${Y}فاز ۱: تست سرعت ${#mirrors[@]} مخزن...${N}"
    local temp_speed_file="/tmp/mirror_speeds_$$"
    
    (
        trap '' INT
        for mirror in "${mirrors[@]}"; do
            (
                local speed name
                speed=$(test_mirror_speed "$mirror")
                if [[ "$speed" != "0" ]]; then
                    name=$(echo "$mirror" | sed -E 's/https?:\/\///' | sed -E 's/(\.com|\.ir|\.co|\.tech|\.org|\.net|\.ac\.ir|\.cloud).*//' | sed -E 's/(mirrors?|archive|ubuntu|repo)\.//g' | awk '{print toupper(substr($0,1,1))substr($0,2)}')
                    echo "$speed|$mirror|$name" >> "$temp_speed_file"
                    echo -n -e "${G}.${N}"
                else
                    echo -n -e "${R}x${N}"
                fi
            ) &
        done
        wait
    )
    echo -e "\n\n${G}فاز ۱ تکمیل شد.${N}"

    if [ ! -s "$temp_speed_file" ]; then
        log_message "ERROR" "[X] NO ACTIVE REPOSITORIES FOUND. PLEASE CHECK YOUR INTERNET CONNECTION."; return 1
    fi

    mapfile -t MIRROR_LIST_CACHE < <(sort -t'|' -k1 -nr "$temp_speed_file")
    rm -f "$temp_speed_file"

    echo -e "\n${Y}--- نتایج آنالیز مخازن (مرتب شده بر اساس سرعت) ---${N}"
    printf "%-4s %-35s %-15s\n" "رتبه" "نام مخزن" "سرعت (MBPS)"
    printf "%.0s-" {1..60}; echo

    local rank=1
    for result in "${MIRROR_LIST_CACHE[@]}"; do
        local speed name mbps
        speed=$(echo "$result" | cut -d'|' -f1)
        name=$(echo "$result" | cut -d'|' -f3)
        mbps=$(awk -v speed="$speed" 'BEGIN { printf "%.2f", speed * 8 / 1024 }')
        printf "%-4s %-35s ${G}%-15s${N}\n" "$rank." "${name^^}" "$mbps"
        rank=$((rank + 1))
    done
    printf "%.0s-" {1..60}; echo

    local best_mirror_info best_mirror_url best_mirror_name
    best_mirror_info="${MIRROR_LIST_CACHE[0]}"
    best_mirror_url=$(echo "$best_mirror_info" | cut -d'|' -f2)
    best_mirror_name=$(echo "$best_mirror_info" | cut -d'|' -f3)

    echo -e "\n${B_CYAN}--- گزینه‌ها ---${C_RESET}"
    printf "  ${C_YELLOW}%2d)${C_WHITE} %s (%s)\n" "1" "اعمال سریع‌ترین مخزن" "${best_mirror_name^^}"
    printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "انتخاب دستی یک مخزن از لیست"
    printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "بازگشت"
    echo -e "${B_BLUE}-----------------------------------------------------${C_RESET}"
    printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"
    read -e -r mirror_choice
    
    case $mirror_choice in
        1) apply_selected_mirror "$best_mirror_url" "$best_mirror_name" ;;
        2) choose_custom_mirror_from_list ;;
        3) return ;;
        *) echo -e "${R}گزینه نامعتبر است!${N}" ;;
    esac
    read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
}

port_scanner_menu() {
    while true; do
        clear
        echo -e "${B_CYAN}--- اسکنر پورت (NMAP) ---${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "اسکن سریع (1000 پورت رایج)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "اسکن کامل (تمام پورت‌ها - بسیار کند)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "بازگشت به منوی امنیت"
        echo -e "${B_BLUE}---------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"
        read -e -r choice

        case $choice in
            1|2)
                if ! command -v nmap &> /dev/null; then
                    log_message "ERROR" "NMAP IS NOT INSTALLED. ATTEMPTING TO INSTALL AUTOMATICALLY..."
                    install_dependencies
                fi
                printf "%b" "${B_MAGENTA}آدرس IP هدف را وارد کنید: ${C_RESET}"
                read -e -r target_ip
                if ! is_valid_ip "$target_ip"; then 
                    log_message "ERROR" "THE IP ADDRESS ENTERED IS NOT VALID."
                else
                    echo -e "\n${C_YELLOW}لطفا صبر کنید، اسکن در حال انجام است...${C_RESET}"
                    echo -e "${C_CYAN}برای لغو اسکن و بازگشت به منو، کلیدهای CTRL+C را فشار دهید.${C_RESET}\n"
                    (
                        trap '' INT
                        if [ "$choice" -eq 1 ]; then
                            log_message "INFO" "RUNNING A FAST SCAN FOR COMMON PORTS ON $target_ip..."
                            nmap --top-ports 1000 --open "$target_ip"
                        else
                            log_message "INFO" "RUNNING A FULL SCAN FOR ALL OPEN PORTS ON $target_ip (THIS MAY TAKE A VERY LONG TIME)..."
                            nmap -p- --open "$target_ip"
                        fi
                    )
                    log_message "SUCCESS" "NMAP SCAN COMPLETED OR CANCELED."
                fi
                ;;
            3) return ;;
            *) echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}" ;;
        esac
        read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
    done
}
show_current_dns_smart() {
    echo -e "${B_YELLOW}دی ان اس های فعلی سیستم:${C_RESET}"
    local dns_servers
    if command -v resolvectl &>/dev/null && systemctl is-active --quiet systemd-resolved; then
        dns_servers=$(resolvectl status | grep "DNS Servers" | grep -v '127.0.0.53' | awk '{for(i=3; i<=NF; i++) print $i}' | tr '\n' ' ' | xargs)
    fi
    if [[ -z "$dns_servers" ]]; then
        dns_servers=$(grep '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' | grep -v '127.0.0.53' | tr '\n' ' ' | xargs)
    fi
    
    if [ -z "$dns_servers" ]; then
        echo "  (یافت نشد)"
    else
        echo "$dns_servers" | tr ' ' '\n' | awk '{print "  • " $1}'
    fi
    echo
}

manage_sanction_dns() {
    clear
    echo -e "${B_CYAN}--- دی ان اس رفع تحریم داخلی ---${C_RESET}\n"

    local -a providers=("SHECAN" "RADAR" "ELECTRO" "BEGZAR" "DNS PRO" "403" "GOOGLE" "CLOUDFLARE" "RESET TO DEFAULT")
    local -A dns_servers=(
        ["SHECAN"]="178.22.122.100 185.51.200.2"
        ["RADAR"]="10.202.10.10 10.202.10.11"
        ["ELECTRO"]="78.157.42.100 78.157.42.101"
        ["BEGZAR"]="185.55.226.26 185.55.225.25"
        ["DNS PRO"]="87.107.110.109 87.107.110.110"
        ["403"]="10.202.10.202 10.202.10.102"
        ["GOOGLE"]="8.8.8.8 8.8.4.4"
        ["CLOUDFLARE"]="1.1.1.1 1.0.0.1"
        ["RESET TO DEFAULT"]=""
    )

    show_current_dns_smart
    
    echo -e "${B_CYAN}سرویس دهندگان DNS موجود:${C_RESET}"
    for i in "${!providers[@]}"; do
        local name="${providers[$i]}"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %-17s ${C_CYAN}%s${C_RESET}\n" $((i + 1)) "$name" "${dns_servers[$name]}"
    done
    printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "0" "بازگشت به منوی قبلی"
    echo -e "${B_BLUE}-----------------------------------${C_RESET}"
    
    printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"
    read -e -r choice

    if [[ ! "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -gt "${#providers[@]}" ]; then
        log_message "ERROR" "INVALID SELECTION."; sleep 2; return
    fi
    [ "$choice" -eq 0 ] && return

    local provider="${providers[$((choice - 1))]}"
    local dns_list="${dns_servers[$provider]}"
    local dns1 dns2
    read -r dns1 dns2 <<< "$dns_list"
    apply_dns_persistent "$dns1" "$dns2"
    
    log_message "INFO" "OPERATION COMPLETED. CHECKING NEW DNS SETTINGS..."
    sleep 2; clear; show_current_dns_smart
    read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
}

manage_ip_health_check() {
    while true; do
        clear
        echo -e "${B_CYAN}--- تشخیص سالم بودن آی پی ---${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "تست اول (IP.CHECK.PLACE)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "تست دوم (BENCH.OPENODE.XYZ)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "تست سوم (GIT.IO/JRW8R)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "4" "بازگشت به منوی امنیت"
        echo -e "${B_BLUE}-----------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"
        read -e -r choice

        case $choice in
            1) (trap '' INT; clear; log_message "INFO" "RUNNING TEST 1..."; bash <(curl -Ls IP.Check.Place) -l en -4); break ;;
            2) (trap '' INT; clear; log_message "INFO" "RUNNING TEST 2..."; bash <(curl -L -s https://bench.openode.xyz/multi_check.sh)); break ;;
            3) (trap '' INT; clear; log_message "INFO" "RUNNING TEST 3..."; bash <(curl -L -s https://git.io/JRw8R) -E en -M 4); break ;;
            4) return ;;
            *) echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}"; sleep 1 ;;
        esac
    done
    read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
}

manage_ssh_port() {
    clear
    local sshd_config="/etc/ssh/sshd_config"
    local ssh_service_name="ssh"
    systemctl status sshd >/dev/null 2>&1 && ssh_service_name="sshd"

    echo -e "${B_CYAN}--- تغییر پورت SSH ---${C_RESET}\n"
    
    local current_port
    current_port=$(grep -i "^#*port" "$sshd_config" | tail -n 1 | awk '{print $2}')
    echo -e "${C_WHITE}پورت SSH فعلی: ${C_GREEN}${current_port:-22}${C_RESET}"
    
    printf "%b" "${B_MAGENTA}پورت جدید SSH را وارد کنید (یا برای لغو ENTER بزنید): ${C_RESET}"
    read -e -r new_port

    if [ -z "$new_port" ]; then log_message "INFO" "PORT CHANGE OPERATION CANCELED."
    elif ! [[ "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -lt 1 ] || [ "$new_port" -gt 65535 ]; then
        log_message "ERROR" "INVALID PORT NUMBER. MUST BE BETWEEN 1 AND 65535."
    else
        log_message "INFO" "CHANGING PORT TO ${new_port}..."
        create_backup "$sshd_config"
        sed -i -E 's/^[ ]*#?[ ]*Port[ ].*/#&/' "$sshd_config"
        echo "Port ${new_port}" >> "$sshd_config"
        log_message "SUCCESS" "PORT CHANGED IN SSH CONFIG FILE."
        
        if command -v ufw &> /dev/null && ufw status | grep -q "Status: active"; then
            log_message "INFO" "UFW FIREWALL IS ACTIVE. ADDING RULE FOR PORT ${new_port}..."
            ufw allow "${new_port}/tcp"
        fi
        systemctl restart "$ssh_service_name"
        check_service_status "$ssh_service_name"
        echo -e "\n${B_YELLOW}**مهم:** لطفاً اتصال SSH خود را با پورت جدید (${new_port}) تست کنید.${C_RESET}"
    fi
    
    read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
}

manage_xray_auto_restart() {
    clear
    echo -e "${B_CYAN}--- ریستارت خودکار سرویس XRAY ---${C_RESET}\n"
    local xray_service=""
    local possible_services=("xray.service" "x-ui.service" "tx-ui.service")
    for service in "${possible_services[@]}"; do
        if systemctl list-units --full -all | grep -q "${service}"; then
            xray_service=$service
            log_message "INFO" "ACTIVE XRAY SERVICE FOUND: ${xray_service}"
            break
        fi
    done

    if [ -z "$xray_service" ]; then
        log_message "ERROR" "NO KNOWN XRAY OR PANEL SERVICE WAS FOUND ON YOUR SERVER."
        read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
        return
    fi
    
    echo -e "${C_WHITE}سرویس فعال شناسایی شده: ${B_GREEN}${xray_service}${C_RESET}\n"
    printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "افزودن CRON JOB برای ریستارت هر 15 دقیقه"
    printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "افزودن CRON JOB برای ریستارت هر 30 دقیقه"
    printf "  ${C_YELLOW}%2d)${C_RED}   %s\n" "3" "حذف CRON JOB ریستارت خودکار XRAY"
    printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "4" "بازگشت"
    echo -e "${B_BLUE}-----------------------------------${C_RESET}"
    printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"
    read -e -r choice

    case $choice in
        1)
            (crontab -l 2>/dev/null | grep -v "systemctl restart ${xray_service}"; echo "*/15 * * * * systemctl restart ${xray_service}") | crontab -
            log_message "SUCCESS" "AUTOMATIC RESTART FOR ${xray_service} SET TO EVERY 15 MINUTES."
            ;;
        2)
            (crontab -l 2>/dev/null | grep -v "systemctl restart ${xray_service}"; echo "*/30 * * * * systemctl restart ${xray_service}") | crontab -
            log_message "SUCCESS" "AUTOMATIC RESTART FOR ${xray_service} SET TO EVERY 30 MINUTES."
            ;;
        3)
            (crontab -l 2>/dev/null | grep -v "systemctl restart ${xray_service}" | crontab -)
            log_message "SUCCESS" "AUTOMATIC RESTART FOR ${xray_service} REMOVED."
            ;;
        4) return ;;
        *) echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}" ;;
    esac
    read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
}

scan_arvan_ranges() {
    clear
    log_message "INFO" "--- SCANNING ARVAN CLOUD IP RANGES (PING TEST) ---"
    if ! command -v fping &>/dev/null; then
        log_message "ERROR" "FPING TOOL IS REQUIRED FOR THIS SCAN. ATTEMPTING TO INSTALL..."
        if ! install_dependencies; then
            read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"; return
        fi
    fi

    local arvan_ranges=(
        "185.143.232.0/22" "188.229.116.16/29" "94.101.182.0/27" "2.144.3.128/28"
        "89.45.48.64/28" "37.32.16.0/27" "37.32.17.0/27" "37.32.18.0/27"
        "37.32.19.0/27" "185.215.232.0/22"
    )

    echo -e "${B_YELLOW}این عملیات ممکن است زمان‌بر باشد.${N}"
    echo -e "اسکن پینگ به صورت بخش به بخش انجام خواهد شد.\n"

    for range in "${arvan_ranges[@]}"; do
        echo -e "${B_CYAN}--- آماده‌سازی برای اسکن پینگ رنج: ${range} ---${N}"
        local choice
        while true; do
            read -p "آیا اسکن این رنج را شروع می‌کنید؟ (y/n): " -n 1 -r choice
            echo
            case "$choice" in
                [Yy]*)
                    (
                        trap '' INT
                        log_message "INFO" "PINGING ARVAN RANGE: ${range}"
                        echo -e "\n${C_YELLOW}در حال انجام تست پینگ... (فقط آی‌پی‌های فعال نمایش داده می‌شوند)${N}"
                        echo -e "${C_CYAN}برای لغو اسکن این رنج و رفتن به رنج بعدی، CTRL+C را فشار دهید.${N}\n"
                        fping -a -g "${range}" 2>/dev/null
                    )
                    log_message "SUCCESS" "PING SCAN FOR ${range} COMPLETED OR CANCELED."
                    break
                    ;;
                [Nn]*)
                    log_message "INFO" "SKIPPING SCAN FOR RANGE: ${range}"
                    echo -e "${C_RED}از اسکن این رنج صرف نظر شد.${N}"
                    read -p "آیا می‌خواهید به طور کامل از اسکنر خارج شوید؟ (y/n): " -n 1 -r exit_choice
                    echo
                    if [[ "$exit_choice" =~ ^[yY]$ ]]; then
                        return
                    fi
                    break
                    ;;
                *)
                    printf "\n%b" "${C_RED}لطفاً با y یا n پاسخ دهید.${C_RESET}\n"
                    ;;
            esac
        done
        echo -e "${B_BLUE}-------------------------------------------------${N}"
    done
    log_message "SUCCESS" "SCAN OF ALL ARVAN RANGES COMPLETED."
    read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
}

scan_warp_endpoints() {
    clear
    log_message "INFO" "--- SCANNING WARP ENDPOINTS ---"
    if ! command -v ncat &>/dev/null; then
        log_message "WARN" "NCAT TOOL (PART OF NMAP) NOT FOUND. ATTEMPTING TO INSTALL..."
        if ! install_dependencies; then
            read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"; return
        fi
    fi
    
    local endpoints=(
        "162.159.192.19:1701" "188.114.98.61:955" "188.114.96.137:988" "188.114.99.66:4198"
        "188.114.99.212:1074" "188.114.98.224:4500" "188.114.98.224:878" "188.114.98.224:1387"
        "188.114.98.224:3476" "188.114.98.224:500" "188.114.98.224:2371" "188.114.98.224:1070"
        "188.114.98.224:854" "188.114.98.224:864" "188.114.98.224:939" "188.114.98.224:2408"
        "188.114.98.224:908" "162.159.192.121:2371" "188.114.96.145:1074" "188.114.98.0:878"
        "188.114.98.228:878" "188.114.99.0:878" "188.114.98.224:1074" "162.159.195.238:7156"
        "188.114.98.224:894" "188.114.96.191:3854" "188.114.99.53:890" "188.114.96.157:890"
        "188.114.96.6:890" "188.114.99.137:968" "188.114.96.239:1387"
        "[2606:4700:d1::58a8:0f84:d37f:90e7]:7559" "[2606:4700:d1::1665:bab6:7ff1:a710]:878"
        "[2606:4700:d0::6932:d526:67b7:77ce]:890" "[2606:4700:d1::9eae:b:2754:6ad9]:1018"
    )

    echo -e "${B_YELLOW}در حال اسکن ${#endpoints[@]} اندپوینت... این عملیات ممکن است کمی طول بکشد.${N}\n"
    
    printf "%-45s | %-12s | %-10s | %-10s\n" "ENDPOINT" "PING (MS)" "TCP" "UDP"
    printf "%.0s-" {1..85}; echo

    for endpoint in "${endpoints[@]}"; do
        local ip port ping_cmd ping_avg tcp_status udp_status
        
        if [[ $endpoint =~ ^\[(.+)\]:(.+) ]]; then
            ip="${BASH_REMATCH[1]}"
            port="${BASH_REMATCH[2]}"
            ping_cmd="ping6"
        else
            ip=$(echo "$endpoint" | cut -d: -f1)
            port=$(echo "$endpoint" | cut -d: -f2)
            ping_cmd="ping"
        fi

        ping_avg=$($ping_cmd -c 2 -W 1 "$ip" 2>/dev/null | tail -1 | awk -F '/' '{print $5}' | cut -d. -f1)
        [[ -z "$ping_avg" ]] && ping_avg="${R}FAIL${N}" || ping_avg="${G}${ping_avg}${N}"

        if ncat -z -w 1 "$ip" "$port" &>/dev/null; then
            tcp_status="${G}OPEN${N}"
        else
            tcp_status="${R}CLOSED${N}"
        fi

        if ncat -u -z -w 1 "$ip" "$port" &>/dev/null; then
            udp_status="${G}OPEN${N}"
        else
            udp_status="${R}CLOSED${N}"
        fi
        
        printf "%-45s | %-20b | %-18b | %-18b\n" "$endpoint" "$ping_avg" "$tcp_status" "$udp_status"
    done
    
    log_message "SUCCESS" "WARP ENDPOINT SCAN COMPLETED."
    read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
}
# --- SCRIPT MAIN MENUS (UPDATED) ---

manage_advanced_tools() {
    while true; do
        clear
        stty sane
        echo -e "${B_CYAN}--- ابزارهای پیشرفته و وب ---${C_RESET}\n"
        echo -e "${C_WHITE}این منو شامل ابزارهای پیشرفته مانند DOCKER، وب سرور CADDY و ابزارهای مرتبط با SSL و GEO-IP است.${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${B_GREEN} %s\n" "1" "نصب و مدیریت DOCKER"
        printf "  ${C_YELLOW}%2d)${B_GREEN} %s\n" "2" "مدیریت وب سرور CADDY (با SSL خودکار)"
        printf "  ${C_YELLOW}%2d)${B_GREEN} %s\n" "3" "مدیریت گواهی SSL با CERTBOT"
        printf "  ${C_YELLOW}%2d)${B_GREEN} %s\n" "4" "مسدودسازی بر اساس موقعیت جغرافیایی (GEO-IP)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "5" "بازگشت به منوی اصلی"
        echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"; read -e -r choice

        case $choice in
            1) manage_docker ;;
            2) manage_caddy ;;
            3) manage_certbot ;;
            4) manage_geoip_blocking ;;
            5) return ;;
            *) echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}"; sleep 1 ;;
        esac
    done
}

manage_network_optimization() {
    while true; do
        clear
        stty sane
        echo -e "${B_CYAN}--- بهینه سازی شبکه و اتصال ---${C_RESET}\n"
        echo -e "${C_WHITE}در این بخش می‌توانید تنظیمات شبکه، DNS، الگوریتم‌های TCP و مخازن نرم‌افزاری را بهینه سازی کنید.${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "مدیریت بهینه سازهای TCP (BBR, HYBLA, CUBIC)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "بهینه ساز SYSCTL اختصاصی"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "بهینه ساز QLEEN & MTU اختصاصی (ماندگار)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "4" "رفع مشکل تاریخ واتس‌اپ"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "5" "بهینه سازی سرعت (TC)"
        printf "  ${C_YELLOW}%2d)${B_YELLOW} %s\n" "6" "بهینه سازی بستر شبکه (پیشرفته و ماندگار)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "7" "مدیریت و یافتن بهترین DNS"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "8" "یافتن سریعترین مخزن APT (پیشرفته)"
        printf "  ${C_YELLOW}%2d)${B_WHITE} %s\n" "9" "تست پکت لاست بین سرور (MTR)"
        printf "  ${C_YELLOW}%2d)${B_GREEN} %s\n" "10" "دی ان اس رفع تحریم داخلی"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "11" "بازگشت به منوی اصلی"
        echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"; read -e -r choice

        case $choice in
            1) manage_tcp_optimizers ;; 2) manage_custom_sysctl ;; 3) manage_tc_qleen_mtu ;;
            4) fix_whatsapp_time ;; 5) manage_tc_script ;; 6) run_as_bbr_optimization ;; 
            7) manage_dns ;; 8) advanced_mirror_test ;; 9) run_packet_loss_test ;; 
            10) manage_sanction_dns ;; 11) return ;;
            *) echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}"; sleep 1 ;;
        esac
    done
}

manage_security() {
    while true; do
        clear
        stty sane
        echo -e "${B_CYAN}--- امنیت و دسترسی ---${C_RESET}\n"
        echo -e "${C_WHITE}مجموعه ابزارهای امنیتی برای مدیریت فایروال، دسترسی‌ها، اسکنرها و محافظت از سرور شما.${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "مدیریت فایروال و پینگ (UFW)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "مدیریت ورود کاربر ROOT"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "تغییر پورت SSH"
        printf "  ${C_YELLOW}%2d)${B_GREEN} %s\n" "4" "تغییر پسوورد سرور"
        printf "  ${C_YELLOW}%2d)${B_YELLOW} %s\n" "5" "جلوگیری از ابیوز (ABUSE DEFENDER)"
        printf "  ${C_YELLOW}%2d)${B_GREEN} %s\n" "6" "دستیار پنل X-UI (چند ادمین)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "7" "ریستارت خودکار XRAY"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "8" "مدیریت ریبوت خودکار سرور"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "9" "فعال/غیرفعال کردن IPV6"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "10" "اسکنر پورت"
        printf "  ${C_YELLOW}%2d)${B_GREEN} %s\n" "11" "اسکنرهای بدافزار"
        printf "  ${C_YELLOW}%2d)${B_GREEN} %s\n" "12" "ممیزی امنیتی با LYNIS"
        printf "  ${C_YELLOW}%2d)${B_GREEN} %s\n" "13" "اسکن رنج وارپ پیشرفته"
        printf "  ${C_YELLOW}%2d)${B_YELLOW} %s\n" "14" "اسکن رنج آروان کلود"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "15" "تشخیص سالم بودن آی پی"
        printf "  ${C_YELLOW}%2d)${B_YELLOW} %s\n" "16" "اسکن اندپوینت های WARP"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "17" "بازگشت به منوی اصلی"
        echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"; read -e -r choice

        case $choice in
            1) manage_firewall ;; 2) manage_ssh_root ;; 3) manage_ssh_port ;; 4) change_server_password ;;
            5) manage_abuse_defender ;; 6) manage_xui_assistant ;; 7) manage_xray_auto_restart ;; 
            8) manage_reboot_cron ;; 9) manage_ipv6 ;; 10) port_scanner_menu ;;
            11) manage_malware_scanners ;; 12) manage_lynis_audit ;;
            13) manage_advanced_warp_scanner ;; 14) scan_arvan_ranges ;; 15) manage_ip_health_check ;; 
            16) scan_warp_endpoints ;; 17) return ;;
            *) echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}"; sleep 1 ;;
        esac
    done
}

manage_monitoring_diagnostics() {
    while true; do
        clear
        stty sane
        echo -e "${B_CYAN}--- ابزارهای مانیتورینگ و عیب یابی ---${C_RESET}\n"
        echo -e "${C_WHITE}ابزارهایی برای مشاهده زنده منابع سیستم، ترافیک شبکه و تحلیل فضای دیسک.${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "مانیتورینگ پیشرفته منابع (BTOP/HTOP)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "تحلیلگر فضای دیسک (NCDU)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "مشاهده زنده ترافیک شبکه (IFTOP)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "4" "بازگشت به منوی اصلی"
        echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"; read -e -r choice

        case $choice in
            1) manage_system_monitors ;;
            2) manage_disk_analyzer ;;
            3) manage_network_traffic ;;
            4) return ;;
            *) echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}"; sleep 1 ;;
        esac
    done
}

manage_system_tools() {
    while true; do
        clear
        stty sane
        echo -e "${B_CYAN}--- ابزارهای سیستمی و مدیریتی ---${C_RESET}\n"
        echo -e "${C_WHITE}شامل ابزارهای مدیریتی سیستم مانند مدیریت SWAP و پاکسازی دیسک.${C_RESET}\n"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "1" "مدیریت حافظه SWAP"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "2" "پاکسازی سیستم (آزاد کردن فضا)"
        printf "  ${C_YELLOW}%2d)${C_WHITE} %s\n" "3" "بازگشت به منوی اصلی"
        echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"
        printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"; read -e -r choice

        case $choice in
            1) manage_swap ;;
            2) manage_system_cleanup ;;
            3) return ;;
            *) echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}"; sleep 1 ;;
        esac
    done
}

update_and_install_packages() {
    clear
    log_message "INFO" "--- INTERACTIVE UPDATE AND INSTALLATION PROCESS ---"
    
    echo -e "${B_CYAN}--- آپدیت و نصب بسته‌های لازم (با تایید مرحله به مرحله) ---${C_RESET}\n"

    # --- STEP 1: APT UPDATE ---
    local choice
    printf "%b" "${C_YELLOW}مرحله ۱: آیا مایل به به‌روزرسانی لیست بسته‌های سیستم عامل (APT UPDATE) هستید؟ (y/n): ${C_RESET}"
    read -e -r choice
    if [[ "$choice" =~ ^[yY]$ ]]; then
        log_message "INFO" "UPDATING PACKAGE LISTS..."
        if ! apt-get update -qq; then
            log_message "ERROR" "FAILED TO UPDATE PACKAGE LISTS."
        else
            log_message "SUCCESS" "PACKAGE LISTS UPDATED SUCCESSFULLY."
        fi
    else
        log_message "INFO" "SKIPPED: PACKAGE LIST UPDATE."
    fi
    echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"

    # --- STEP 2: APT UPGRADE ---
    printf "%b" "${C_YELLOW}مرحله ۲: آیا مایل به ارتقاء بسته‌های نصب شده (APT UPGRADE) هستید؟ (ممکن است زمان‌بر باشد) (y/n): ${C_RESET}"
    read -e -r choice
    if [[ "$choice" =~ ^[yY]$ ]]; then
        log_message "INFO" "UPGRADING SYSTEM PACKAGES..."
        if ! DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"; then
            log_message "WARN" "UPGRADE FAILED FOR SOME PACKAGES. SCRIPT WILL CONTINUE."
        else
            log_message "SUCCESS" "SYSTEM PACKAGES UPGRADED."
        fi
    else
        log_message "INFO" "SKIPPED: SYSTEM UPGRADE."
    fi
    echo -e "${B_BLUE}----------------------------------------------------${C_RESET}"

    # --- STEP 3: GROUPED DEPENDENCIES INSTALLATION ---
    echo -e "${B_CYAN}مرحله ۳: نصب پیش‌نیازها به صورت گروهی${C_RESET}"
    
    _install_group_if_confirmed() {
        local group_title="$1"
        shift
        local deps_to_check=("$@")
        local missing_deps=()

        for dep in "${deps_to_check[@]}"; do
            local cmd_name="$dep"
            [[ "$dep" == "dnsutils" ]] && cmd_name="dig"
            [[ "$dep" == "net-tools" ]] && cmd_name="ifconfig"
            [[ "$dep" == "mtr-tiny" ]] && cmd_name="mtr"
            [[ "$dep" == "netcat-openbsd" ]] && cmd_name="nc"
            [[ "$dep" == "uuid-runtime" ]] && cmd_name="uuidgen"
            [[ "$dep" == "iptables-persistent" ]] && cmd_name="netfilter-persistent"
            [[ "$dep" == "xtables-addons-common" ]] && cmd_name="xtables-addons-info"

            if ! command -v "$cmd_name" &>/dev/null; then
                 if [[ "$dep" == "netcat-openbsd" ]] && (command -v "ncat" >/dev/null || command -v "netcat" >/dev/null); then
                    continue
                fi
                missing_deps+=("$dep")
            fi
        done

        if [ ${#missing_deps[@]} -gt 0 ]; then
            echo -e "\n${C_WHITE}گروه '${group_title}' نیاز به نصب بسته‌های زیر دارد:${N} ${C_CYAN}${missing_deps[*]}${N}"
            printf "%b" "${C_YELLOW}آیا این بسته‌ها نصب شوند؟ (y/n): ${C_RESET}"
            read -e -r install_choice
            if [[ "$install_choice" =~ ^[yY]$ ]]; then
                log_message "INFO" "INSTALLING GROUP: ${group_title}"
                if ! DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "${missing_deps[@]}"; then
                    log_message "ERROR" "FAILED TO INSTALL SOME DEPENDENCIES IN GROUP: ${group_title}"
                else
                    log_message "SUCCESS" "GROUP '${group_title}' INSTALLED SUCCESSFULLY."
                fi
            else
                log_message "INFO" "SKIPPED GROUP: ${group_title}"
            fi
        else
            echo -e "\n${G}بسته‌های گروه '${group_title}' از قبل نصب هستند.${N}"
        fi
    }

    local core_deps=("curl" "wget" "net-tools" "dnsutils" "bc" "lsb-release" "uuid-runtime" "unzip" "git" "gnupg")
    local socat_dep=("socat")
    local security_deps=("fail2ban" "chkrootkit" "rkhunter" "lynis" "iptables-persistent" "xtables-addons-common" "geoip-database")
    local monitoring_deps=("htop" "btop" "ncdu" "iftop")
    local web_deps=("certbot")
    local advanced_deps=("mtr-tiny" "iperf3" "jq" "netcat-openbsd" "nmap" "fping" "python3" "python3-pip")

    _install_group_if_confirmed "ابزارهای اصلی و ضروری" "${core_deps[@]}"
    _install_group_if_confirmed "ابزار Socat (برای ارتباطات شبکه)" "${socat_dep[@]}"
    _install_group_if_confirmed "ابزارهای امنیتی و اسکنرها" "${security_deps[@]}"
    _install_group_if_confirmed "ابزارهای مانیتورینگ" "${monitoring_deps[@]}"
    _install_group_if_confirmed "ابزارهای وب و SSL" "${web_deps[@]}"
    _install_group_if_confirmed "ابزارهای پیشرفته شبکه" "${advanced_deps[@]}"

    echo -e "\n${B_GREEN}✅ فرآیند بررسی و نصب پیش‌نیازها به پایان رسید.${N}"
    read -n 1 -s -r -p $'\n'"${R}PRESS ANY KEY TO CONTINUE...${N}"
}


# --- SCRIPT MAIN LOOP ---
main() {
    init_environment
    clear
    progress_bar "درحال بارگذاری اسکریپت..." 2

    while true; do
      stty sane 
      clear; show_banner; show_enhanced_system_status
      printf "   ${C_YELLOW}%2d) ${B_CYAN}%s\n" "1" "بهینه سازی شبکه و اتصال"
      printf "   ${C_YELLOW}%2d) ${B_CYAN}%s\n" "2" "امنیت و دسترسی"
      printf "   ${C_YELLOW}%2d) ${B_CYAN}%s\n" "3" "ابزارهای مانیتورینگ و عیب یابی"
      printf "   ${C_YELLOW}%2d) ${B_CYAN}%s\n" "4" "ابزارهای سیستمی و مدیریتی"
      printf "   ${C_YELLOW}%2d) ${B_CYAN}%s\n" "5" "ابزارهای پیشرفته و وب"
      printf "   ${C_YELLOW}%2d) ${C_WHITE}%s\n" "6" "آپدیت و نصب پکیج های لازم"
      printf "   ${C_YELLOW}%2d)${B_GREEN} %s\n" "7" "نصب / به‌روزرسانی پنل TX-UI"
      printf "   ${C_YELLOW}%2d)${B_GREEN} %s\n" "8" "نصب / به‌روزرسانی پنل 3X-UI"
      printf "\n   ${C_YELLOW}%2d) ${C_RED}%s\n" "9" "خروج (EXIT)"
      echo -e "${B_BLUE}------------------------------------------------------------${C_RESET}"
      printf "%b" "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}"
      read -e -r main_choice

      case $main_choice in
        1) manage_network_optimization ;;
        2) manage_security ;;
        3) manage_monitoring_diagnostics ;;
        4) manage_system_tools ;;
        5) manage_advanced_tools ;;
        6) update_and_install_packages ;;
        7) manage_txui_panel ;;
        8) manage_3xui_panel ;;
        9) clear; log_message "INFO" "EXITING SCRIPT."; echo -e "\n${B_CYAN}خدا نگهدار!${C_RESET}\n"; stty sane; exit 0 ;;
        *) echo -e "\n${C_RED}گزینه نامعتبر است!${C_RESET}"; read -n 1 -s -r -p "" ;;
      esac
    done
}

main "$@"
# ###########################################################################
# --- END OF SCRIPT ---
# ###########################################################################
