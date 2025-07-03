#!/bin/bash

# Check for root user
if [ "$(id -u)" -ne 0 ]; then
  echo "این اسکریپت باید با دسترسی ریشه (root) اجرا شود."
  echo "لطفاً از دستور 'sudo bash menu.sh' استفاده کنید."
  exit 1
fi

# --- New Color Palette ---
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


# --- Header and Banner ---
show_banner() {
    echo -e "${B_BLUE}╔══════════════════════════════════════════════════════════════╗${C_RESET}"
    echo -e "${B_BLUE}║        ${B_CYAN}مدیریت جامع بهینه سازی لینوکس اوبونتو${B_BLUE}         ║${C_RESET}"
    echo -e "${B_BLUE}╠══════════════════════════════════════════════════════════════╣${C_RESET}"
    echo -e "${B_BLUE}║ ${C_WHITE}CREATED BY: AMIR ALI KARBALAEE${B_BLUE}   |   ${C_WHITE}TELEGRAM: T.ME/CY3ER${B_BLUE}      ║${C_RESET}"
    echo -e "${B_BLUE}║ ${C_WHITE}COLLABORATOR: FREAK${B_BLUE}              |   ${C_WHITE}TELEGRAM: T.ME/FREAK_4L${B_BLUE}   ║${C_RESET}"
    echo -e "${B_BLUE}╚══════════════════════════════════════════════════════════════╝${C_RESET}"
    echo ""
}

# --- HELPER FUNCTIONS ---
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
    # This regex handles both IPv4 and IPv6 (basic validation)
    if [[ "$ip" =~ ^([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}$ || "$ip" =~ ^(([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])) || "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 0 # Valid
    else
        return 1 # Invalid
    fi
}


# --- INDIVIDUAL TOOL FUNCTIONS ---

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
        read -p "$(echo -e "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}")" choice
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
    read -p "$(echo -e "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}")" choice
    case $choice in
        1)
            read -p "$(echo -e "${C_YELLOW}**هشدار:** این کار ممکن است اتصال شما را دچار اختلال کند. آیا مطمئن هستید؟ (y/n): ${C_RESET}")" confirm
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
  read -p "$(echo -e "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}")" choice
  case $choice in
    1)
      read -p "$(echo -e "${C_YELLOW}**هشدار:** فعال کردن ورود روت ریسک امنیتی دارد. آیا مطمئن هستید؟ (y/n): ${C_RESET}")" confirm
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
  read -p "$(echo -e "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}")" choice
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
  read -p "$(echo -e "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}")" choice
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
  read -p "$(echo -e "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}")" choice
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
    read -p "$(echo -e "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}")" choice
    case $choice in
        1)
            echo -e "\n${C_YELLOW}در حال نصب hping3 و nmap...${C_RESET}"
            apt-get update
            apt-get install -y hping3 nmap
            echo -e "\n${C_GREEN}ابزارها با موفقیت نصب شدند.${C_RESET}"
            ;;
        2)
            read -p "$(echo -e "${B_MAGENTA}آدرس IP هدف را وارد کنید: ${C_RESET}")" target_ip
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
            read -p "$(echo -e "${B_MAGENTA}آدرس IP هدف را وارد کنید: ${C_RESET}")" target_ip
            if ! is_valid_ip "$target_ip"; then
                echo -e "\n${C_RED}خطا: آدرس IP وارد شده معتبر نیست.${C_RESET}"
            elif ! command -v hping3 &> /dev/null; then
                echo -e "\n${C_RED}خطا: hping3 نصب نیست. لطفاً ابتدا از گزینه ۱ آن را نصب کنید.${C_RESET}"
            else
                echo -e "\n${B_YELLOW}**هشدار:** این نوع اسکن بسیار زمان‌بر است و ممکن است ساعت‌ها طول بکشد.${C_RESET}"
                read -p "$(echo -e "${B_MAGENTA}آیا برای شروع اسکن با hping3 مطمئن هستید؟ (y/n): ${C_RESET}")" confirm
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
        read -p "$(echo -e "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}")" choice
        case $choice in
            1)
                clear
                echo -e "${B_CYAN}--- وضعیت کامل فایروال و قوانین ---${C_RESET}"
                ufw status verbose
                read -n 1 -s -r -p $'\nبرای ادامه کلیدی را فشار دهید...'
                ;;
            2)
                read -p "$(echo -e "${B_MAGENTA}پورت مورد نظر را وارد کنید: ${C_RESET}")" port
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
                read -p "$(echo -e "${B_MAGENTA}شماره قانونی که می‌خواهید حذف شود را وارد کنید: ${C_RESET}")" rule_num
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
        read -p "$(echo -e "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}")" choice

        case $choice in
            1)
                local xui_archive="/root/x-ui-linux-amd64.tar.gz"
                if [ ! -f "$xui_archive" ]; then
                    echo -e "\n${C_RED}خطا: فایل ${xui_archive} یافت نشد!${C_RESET}"
                    echo -e "${C_YELLOW}لطفاً ابتدا با استفاده از گزینه (2) راهنما، فایل را دانلود و در پوشه روت قرار دهید.${C_RESET}"
                else
                    echo -e "\n${C_YELLOW}فایل یافت شد. در حال شروع مراحل نصب...${C_RESET}"
                    cd /root/
                    echo "--> در حال پاکسازی نصب‌های قبلی..."
                    rm -rf x-ui/ /usr/local/x-ui/ /usr/bin/x-ui
                    echo "--> در حال استخراج فایل فشرده..."
                    tar zxvf x-ui-linux-amd64.tar.gz
                    echo "--> در حال تنظیم دسترسی‌ها..."
                    chmod +x x-ui/x-ui x-ui/bin/xray-linux-* x-ui/x-ui.sh
                    echo "--> در حال کپی کردن فایل‌های اجرایی..."
                    cp x-ui/x-ui.sh /usr/bin/x-ui
                    cp -f x-ui/x-ui.service /etc/systemd/system/
                    echo "--> در حال انتقال پوشه پنل..."
                    mv x-ui/ /usr/local/
                    echo "--> در حال فعال‌سازی سرویس..."
                    systemctl daemon-reload
                    systemctl enable x-ui
                    systemctl restart x-ui
                    echo -e "\n${C_GREEN}✅ نصب پنل TX-UI با موفقیت به پایان رسید.${C_RESET}"
                    echo -e "${C_YELLOW}--- وضعیت پنل ---${C_RESET}"
                    sleep 2
                    x-ui
                    echo -e "${B_BLUE}-----------------------------------${C_RESET}"
                fi
                break
                ;;
            2)
                clear
                echo -e "${B_CYAN}--- راهنمای نصب آفلاین TX-UI ---${C_RESET}\n"
                echo -e "${C_WHITE}کاربر گرامی لطفا فایل زیر را از گیت هاب سازنده دانلود کرده و در پوشه روت سرور قرار بدهید تا اسکریپت بتواند به درستی نصب را"
                echo -e "انجام بدهد و بعد از نصب با زدن آدرس آی پی خود به همراه پورت ${C_YELLOW}2053${C_RESET}${C_WHITE} و نام کاربری ${C_YELLOW}admin${C_RESET}${C_WHITE} و پسوورد ${C_YELLOW}admin${C_RESET}${C_WHITE} به پنل خود ورود کنید."
                echo -e "و دقت داشته باشید که حتما یک پچ برای مسیر انتخاب کنید و رمز عبور دیفالت را نیز تغییر بدهید تا پنل شما شناسایی و هک نشود."
                echo -e "\n${C_YELLOW}نام فایلی که باید دانلود کنید :${C_RESET} ${C_GREEN}x-ui-linux-amd64.tar.gz${C_RESET}"
                echo -e "\n${C_YELLOW}آدرس گیت هاب پروژه :${C_RESET}"
                echo -e "${C_CYAN}https://github.com/AghayeCoder/tx-ui/releases${C_RESET}"
                echo -e "\n${C_WHITE}باتشکر${C_RESET}"
                echo -e "${B_BLUE}-----------------------------------${C_RESET}"
                break
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
    read -n 1 -s -r -p "برای ادامه، کلیدی را فشار دهید..."
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
        read -p "$(echo -e "${B_YELLOW}--> برای اسکن رنج [${C_CYAN}${range}${B_YELLOW}] کلید Enter را بزنید (s=رد کردن, q=خروج): ${C_RESET}")" choice
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
        # Correctly parse both IPv4 and IPv6 endpoints
        if [[ $endpoint == \[* ]]; then
            # IPv6
            ip_host=$(echo "$endpoint" | cut -d']' -f1 | tr -d '[')
            port=$(echo "$endpoint" | cut -d']' -f2 | tr -d ':')
        else
            # IPv4
            ip_host=$(echo "$endpoint" | cut -d: -f1)
            port=$(echo "$endpoint" | cut -d: -f2)
        fi
        
        echo -ne "    ${C_YELLOW}تست اندپوینت: ${ip_host}:${port}   \r${C_RESET}"

        # 1. Check UDP port first
        if nc -u -z -w 1 "$ip_host" "$port" &> /dev/null; then
            # 2. If port is open, then get the ICMP ping time
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
        read -p "$(echo -e "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}")" choice
        case $choice in
            1)
                clear
                echo -e "${C_YELLOW}در حال اجرای تست اول...${C_RESET}"
                bash <(curl -Ls IP.Check.Place) -l en -4
                break
                ;;
            2)
                clear
                echo -e "${C_YELLOW}در حال اجرای تست دوم...${C_RESET}"
                bash <(curl -L -s https://bench.openode.xyz/multi_check.sh)
                break
                ;;
            3)
                clear
                echo -e "${C_YELLOW}در حال اجرای تست سوم...${C_RESET}"
                bash <(curl -L -s https://git.io/JRw8R) -E en -M 4
                break
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
    read -n 1 -s -r -p "برای ادامه، کلیدی را فشار دهید..."
}


# --- NEW MAIN MENUS ---

manage_network_optimization() {
    while true; do
        clear
        echo -e "${B_CYAN}--- بهینه سازی شبکه و اتصال ---${C_RESET}\n"
        echo -e "${C_YELLOW}1) ${C_WHITE}بهینه سازی سرعت (TC)"
        echo -e "${C_YELLOW}2) ${C_WHITE}بهینه سازی هسته (SYSCTL)"
        echo -e "${C_YELLOW}3) ${C_WHITE}مدیریت و یافتن بهترین DNS"
        echo -e "${C_YELLOW}4) ${C_WHITE}یافتن سریعترین مخزن APT"
        echo -e "${C_YELLOW}5) ${C_WHITE}تست پینگ سرورهای DNS"
        echo -e "${C_YELLOW}6) ${C_WHITE}پینگ خارج به داخل"
        echo -e "${C_YELLOW}7) ${C_WHITE}پینگ داخل به خارج"
        echo -e "${C_YELLOW}8) ${C_WHITE}بازگشت به منوی اصلی"
        echo -e "${B_BLUE}-----------------------------------${C_RESET}"
        read -p "$(echo -e "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}")" choice
        case $choice in
            1) manage_tc_script ;;
            2) manage_sysctl ;;
            3) manage_dns ;;
            4) manage_mirror_test ;;
            5) ping_test_ips ;;
            6) ping_iran_hosts ;;
            7) ping_external_hosts ;;
            8) return ;;
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
        read -p "$(echo -e "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}")" choice
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

# --- SCRIPT MAIN LOOP ---
while true; do
  clear
  show_banner
  echo -e "   ${C_YELLOW}1) ${B_CYAN}بهینه سازی شبکه و اتصال"
  echo -e "   ${C_YELLOW}2) ${B_CYAN}امنیت و دسترسی"
  echo -e "   ${C_YELLOW}3) ${C_WHITE}آپدیت و نصب پکیج های لازم"
  echo -e "   ${C_YELLOW}4) ${B_GREEN}نصب آفلاین پنل TX-UI"
  echo ""
  echo -e "   ${C_YELLOW}5) ${C_RED}خروج"
  echo -e "${B_BLUE}------------------------------------------------------------${C_RESET}"
  read -p "$(echo -e "${B_MAGENTA}لطفاً یک گزینه را انتخاب کنید: ${C_RESET}")" main_choice

  case $main_choice in
    1) manage_network_optimization ;;
    2) manage_security ;;
    3) install_core_packages ;;
    4) manage_xui_offline_install ;;
    5)
      clear
      echo -e "\n${B_CYAN}خدا نگهدار!${C_RESET}\n"
      exit 0
      ;;
    *)
      echo -e "\n${C_RED}گزینه نامعتبر است! لطفاً عددی بین 1 تا 5 وارد کنید.${C_RESET}"
      read -n 1 -s -r -p "برای ادامه، کلیدی را فشار دهید..."
      ;;
  esac
done
