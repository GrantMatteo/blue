#!/bin/sh
ncolors=$(tput -T tmux-256color colors)
#if [ "$ncolors" -ge 8 ]; then
 #   ORAG='\033[0;33m'
  #  GREEN='\033[0;32m'
   # YELLOW='\033[1;33m'
    #BLUE='\033[0;36m'
    #NC='\033[0m' # No Color
#else
    ORAG=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
#fi

printf "${GREEN}
      ##################################
      #                                #
      #         INVENTORY TIME         #
      #                                #
      ##################################
      ${NC}\n"

printf "${GREEN}#############Installing potential dependencies############${NC}\n"
IS_RHEL=false
IS_DEBIAN=false
IS_OTHER=false
if command -v yum 2>/dev/null ; then
    #yum install iproute sed -y
    IS_RHEL=true
elif  command -v apt-get >/dev/null ; then
    #apt-get -qq update
    #apt-get -qq install net-tools iproute2 sed -y
    IS_DEBIAN=true
else
    printf "Unknown package manager, install netstat/ip/ifconfig/sed manually if necessary\n"
fi

printf "\n${GREEN}#############HOST INFORMATION############${NC}\n"

HOST=$(hostname)
OS=$(cat /etc/os-release  | grep PRETTY_NAME | sed 's/PRETTY_NAME=//' | sed 's/"//g')
INTERFACES=$(ip a | grep -P '\d{0,}: ' | awk -F ' ' '{print $2}' | sed 's/://' 2>/dev/null)
IP=""
USERS=$(cat /etc/passwd | grep -vE '(false|nologin|sync)$')
SUDOERS=$(cat /etc/sudoers /etc/sudoers.d/* | grep -vE '#|Defaults|^\s*$')
SUIDS=$(find /bin /sbin /usr -perm -u=g+s -type f -exec ls {} -la \; | grep -Ev '(sudo|chsh|chfn|su|umount|newgrp|pppd|polkit-agent-helper-1|dbus-daemon-launch-helper|snap-confine|auth_pam_tool|ssh-keysign|Xorg.wrap|fusermount3|vmware-user-suid-wrapper|pkexec|mount|gpasswd|pkexec|passwd|ping|exim4|cockpit-wsintance|cockpit-session)$')
WORLDWRITEABLES=$(find /usr /bin/ /sbin /var/www -perm -o=w -type f -exec ls {} -la \; 2>/dev/null)
if [ $IS_RHEL = true ]; then
    SUDOGROUP=$(cat /etc/group | grep wheel | sed 's/x:.*:/\ /')
else
    SUDOGROUP=$(cat /etc/group | grep sudo | sed 's/x:.*:/\ /')
fi

for i in $INTERFACES
do
    IPENTRY=''
    IPADDRESSESOFINTERFACES=$( ip addr show "$i" 2>/dev/null | grep inet | sed 's/\s*inet/inet/' | sed 's/\/[0-9]*//' | grep -v inet6 | awk -F ' ' '{print $2}' 2>/dev/null)
    for j in $IPADDRESSESOFINTERFACES
    do
        IPENTRY=$(printf "$IPENTRY $j\n")
    done
    SPACE='\n'
    IP=$(printf "$IP$SPACE$i: ${YELLOW}$IPENTRY${NC}" )
done

NMCLI=$(nmcli -t --fields NAME con show --active | sed 's/\ /delimiter/g')
DNS=''
for i in $NMCLI
do
    parsed=$(echo $i | sed 's/delimiter/\ /g')
    DNSENTRY=$(nmcli --fields ip4.dns con show "$parsed" 2>/dev/null | sed 's/dns:\s*/dns: /' | sed 's/.*://' | awk '{print $1}' )
    if echo "$DNSENTRY" | grep -qi '\-\-'  || echo "$DNSENTRY" | grep -qiE '^$' ; then
        continue
    fi
    DNS=$(printf "$DNS\n$parsed: ${YELLOW}$DNSENTRY${NC}")
done

printf "${BLUE}[+] Hostname:${NC} $HOST\n"
printf "${BLUE}[+] OS:${NC} $OS\n"
echo "${BLUE}[+] IP Addresses and interfaces${NC}"
echo "$IP"
printf "\n${BLUE}[+] DNS Servers${NC}"
echo "$DNS"
printf "\n${BLUE}[+] Users${NC}\n"
echo "${YELLOW}$USERS${NC}"
printf "\n${BLUE}[+] /etc/sudoers and /etc/sudoers.d/*${NC}\n"
echo "${YELLOW}$SUDOERS${NC}"
printf "\n${BLUE}[+] Sudo group${NC}\n"
echo "${YELLOW}$SUDOGROUP${NC}"
printf "\n${BLUE}[+] Funny SUIDs${NC}\n"
echo "${YELLOW}$SUIDS${NC}"
printf "\n${BLUE}[+] World Writeable Files${NC}\n"
echo "${YELLOW}$WORLDWRITEABLES${NC}"
printf "\n${GREEN}#############SERVICE INFORMATION############${NC}"
SERVICES=$(systemctl --type=service  | grep active | awk '{print $1}')
APACHE2=false
NGINX=false
checkService()
{
    serviceName=$1
    serviceToCheckExists=$2
    if echo "$serviceName" | grep -qi "$serviceToCheckExists"; then
        printf "\n${BLUE}[+] $serviceToCheckExists is on this machine${NC} "
        if netstat -tulpn | grep -qi "$serviceToCheckExists"; then
            printf "\nActive on port(s) ${YELLOW}$(netstat -tulpn | grep -i $serviceToCheckExists | awk 'BEGIN {ORS=" and "} {print $1, $4}' | sed 's/\(.*\)and /\1\n/')${NC}"
        fi
    fi
}

if checkService "$SERVICES"  'ssh' | grep -qi "is on this machine"; then checkService "$SERVICES"  'ssh' ; SSH=true ;fi
if checkService "$SERVICES"  'docker' | grep -qi "is on this machine"; then
    checkService "$SERVICES"  'docker'
    echo "\n[!] Current Active Containers"
    echo "${ORAG}$(docker ps)${NC}"
fi

if checkService "$SERVICES"  'cockpit' | grep -qi "is on this machine"; then
    checkService "$SERVICES"  'cockpit'
    echo "${ORAG}[!] WE PROBABLY SHOULD KILL COCKPIT${NC}"
fi

if checkService "$SERVICES"  'apache2' | grep -qi "is on this machine"; then
    checkService "$SERVICES"  'apache2'
    APACHE2VHOSTS=$(cat /etc/apache2/sites-enabled/* | grep -E 'VirtualHost|DocumentRoot')
    printf "\n[!] Configuration Details\n"
    echo "${ORAG}$APACHE2VHOSTS${NC}"
    APACHE2=true
fi

if checkService "$SERVICES"  'ftp' | grep -qi "is on this machine"; then
    checkService "$SERVICES"  'ftp'
    FTPCONF=$(cat /etc/*ftp* | grep -v '#' | grep -E 'anonymous_enable|guest_enable|no_anon_password|write_enable')
    printf "\n[!] Configuration Details\n"
    echo "${ORAG}$FTPCONF${NC}"
fi


if checkService "$SERVICES"  'nginx' | grep -qi "is on this machine"; then
    checkService "$SERVICES"  'nginx'
    NGINXCONFIG=$(cat /etc/nginx/sites-enabled/default | grep -v '#'  | sed '/^\s*$/d' )
    printf "\n[!] Configuration Details\n"
    echo "${ORAG}$NGINXCONFIG${NC}"
    NGINX=true
fi

sql_test()
{
        printf "\n[!] SQL DETAILS\n"
        CONFINFO=$(grep -RE '(^user|^bind-address)' /etc/mysql/ --include="*sql*.cnf"  | sed 's/:user\s*/ ===> user /' | sed 's/bind-address\s*/ ===> bind-address /')
        echo "${ORAG}$CONFINFO${NC}"
        if mysql -uroot -e 'bruh' 2>&1 >/dev/null |   grep -q 'bruh'; then
                echo Can login as root, with root and no password
        elif mysql -uroot -proot -e 'bruh' 2>&1 >/dev/null |   grep -q 'bruh'; then
                echo Can login with root:root
        elif mysql -uroot -ppassword -e 'bruh' 2>&1 >/dev/null |   grep -q 'bruh'; then
                echo Can login with root:password
        elif mysql -uroot -p$DEFAULT_PASS -e 'bruh' 2>&1 >/dev/null |   grep -q 'bruh'; then
                echo Can login with root:$DEFAULT_PASS
        else
                echo Cannot login with weak creds or deafult credentials
        fi
}
if checkService "$SERVICES"  'mysql' | grep -qi "is on this machine"; then checkService "$SERVICES"  'mysql' ; sql_test; MYSQL=true; fi
if checkService "$SERVICES"  'mariadb' | grep -qi "is on this machine"; then checkService "$SERVICES"  'mariadb' ; sql_test ; MARIADB=true; fi
if checkService "$SERVICES"  'postgresql' | grep -qi "is on this machine"; then
    checkService "$SERVICES" 'postgresql'
    PSQLHBA=$(grep -REv '(#|^\s*$|replication)' /etc/postgresql/ --include="pg_hba.conf" -h )
    echo "[!] Authentication Details"
    POSTGRESQL=true
    echo "${ORAG}$PSQLHBA${NC}"
fi
if checkService "$SERVICES"  'python' | grep -qi "is on this machine"; then checkService "$SERVICES"  'python' ; PYTHON=true; fi
if checkService "$SERVICES"  'dropbear' | grep -qi "is on this machine"; then checkService "$SERVICES"  'dropbear' ; DROPBEAR=true; fi
if checkService "$SERVICES"  'php' | grep -qi "is on this machine"; then checkService "$SERVICES"  'php' ; PHP=true; fi
if checkService "$SERVICES"  'vsftpd' | grep -qi "is on this machine"; then checkService "$SERVICES"  'vsftpd' ; VSFTPD=true; fi
if checkService "$SERVICES"  'pure-ftpd' | grep -qi "is on this machine"; then checkService "$SERVICES"  'pure-ftpd' ; PUREFTPD=true; fi
if checkService "$SERVICES"  'proftpd' | grep -qi "is on this machine"; then checkService "$SERVICES"  'proftpd' ; PROFTPD=true; fi
if checkService "$SERVICES"  'httpd' | grep -qi "is on this machine"; then checkService "$SERVICES"  'httpd' ; HTTPD=true; fi
if checkService "$SERVICES"  'xinetd' | grep -qi "is on this machine"; then checkService "$SERVICES"  'xinetd' ; XINETD=true; fi
if checkService "$SERVICES"  'inetd' | grep -qi "is on this machine"; then checkService "$SERVICES"  'inetd' ; INETD=true; fi
if checkService "$SERVICES"  'tftpd' | grep -qi "is on this machine"; then checkService "$SERVICES"  'tftpd' ; TFTPD=true; fi
if checkService "$SERVICES"  'atftpd' | grep -qi "is on this machine"; then checkService "$SERVICES"  'atftpd' ; ATFTPD=true; fi
if checkService "$SERVICES"  'smbd' | grep -qi "is on this machine"; then checkService "$SERVICES"  'smbd' ; SMBD=true; fi
if checkService "$SERVICES"  'nmbd' | grep -qi "is on this machine"; then checkService "$SERVICES"  'nmbd' ; NMBD=true; fi
if checkService "$SERVICES"  'snmpd' | grep -qi "is on this machine"; then checkService "$SERVICES"  'snmpd' ; SNMPD=true; fi
if checkService "$SERVICES"  'ypbind' | grep -qi "is on this machine"; then checkService "$SERVICES"  'ypbind' ; YPBIND=true; fi
if checkService "$SERVICES"  'rshd' | grep -qi "is on this machine"; then checkService "$SERVICES"  'rshd' ; RSHD=true; fi
if checkService "$SERVICES"  'rexecd' | grep -qi "is on this machine"; then checkService "$SERVICES"  'rexecd' ; REXECD=true; fi
if checkService "$SERVICES"  'rlogin' | grep -qi "is on this machine"; then checkService "$SERVICES"  'rlogin' ; RLOGIN=true; fi
if checkService "$SERVICES"  'telnet' | grep -qi "is on this machine"; then checkService "$SERVICES"  'telnet' ; TELNET=true; fi
if checkService "$SERVICES"  'squid' | grep -qi "is on this machine"; then checkService "$SERVICES"  'squid' ; SQUID=true; fi
