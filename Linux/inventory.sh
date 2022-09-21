#!/bin/sh

ncolors=$(tput colors)
if [ $ncolors -gt 8 ]; then
    ORAG='\033[0;33m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;36m'
    NC='\033[0m' # No Color
else
    ORAG=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

echo "${GREEN}
      ##################################
      #                                #
      #         INVENTORY TIME         #
      #                                #
      ##################################
      ${NC}"

echo "${GREEN}#############Installing potential dependencies############${NC}"
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
    echo "Unknown package manager, install netstat/ip/ifconfig/sed manually if necessary"
fi

echo "\n${GREEN}#############HOST INFORMATION############${NC}"

HOST=$(hostname)
OS=$(cat /etc/os-release  | grep PRETTY_NAME | sed 's/PRETTY_NAME=//' | sed 's/"//g')
INTERFACES=$(ip a | grep -P '\d{0,}: ' | awk -F ' ' '{print $2}' | sed 's/://')
IP=""
USERS=$(cat /etc/passwd | grep -vE 'false|nologin|sync')
SUDOERS=$(cat /etc/sudoers /etc/sudoers.d/* | grep -vE '#|Defaults|^\s*$')
if [ $IS_RHEL = true ]; then
    SUDOGROUP=$(cat /etc/group | grep wheel | sed 's/x:.*:/\ /')
else
    SUDOGROUP=$(cat /etc/group | grep sudo | sed 's/x:.*:/\ /')
fi

for i in $INTERFACES
do
    IPENTRY=''
    #IPENTRY=$( ( ifconfig $i | grep inet | awk -F ' ' '{print $2;exit}' ) || echo "") 2>/dev/null
    IPADDRESSESOFINTERFACES=$( (ip addr show $i | grep inet | sed 's/\s*inet/inet/' | sed 's/\/\d*//' | grep -v inet6 | awk -F ' ' '{print $2}') 2>/dev/null)
    for j in $IPADDRESSESOFINTERFACES
    do
        IPENTRY=$(echo "$IPENTRY $j\n")
    done
    SPACE='\n'
    IP=$(echo "$IP$SPACE$i: ${YELLOW}$IPENTRY${NC}" )
done

NMCLI=$(nmcli -t --fields NAME con show --active)
#DNS=$(systemd-resolve --status | grep 'DNS Server')
DNS=''
for i in $NMCLI
do
    DNSENTRY=$(nmcli --fields ipv4.dns con show $i | sed 's/dns:\s*/dns: /')
    if echo "$DNSENTRY" | grep -qi '\-\-'; then
        continue
    fi
    DNS=$(echo "$DNS\n$i: ${YELLOW}$DNSENTRY${NC}")
done

echo "${BLUE}Hostname:${NC} $HOST\n"
echo "${BLUE}OS:${NC} $OS\n"
echo "${BLUE}IP Addresses and interfaces${NC}"
echo "$IP"
echo "\n${BLUE}DNS Servers${NC}"
echo "$DNS"
echo "\n${BLUE}Users${NC}"
echo "${YELLOW}$USERS${NC}"
echo "\n${BLUE}/etc/sudoers${NC}"
echo "${YELLOW}$SUDOERS${NC}"
echo "\n${BLUE}Sudo group${NC}"
echo "${YELLOW}$SUDOGROUP${NC}"

echo "\n${GREEN}#############SERVICE INFORMATION############${NC}"
SERVICES=$(systemctl --type=service  | grep active | awk '{print $1}')
APACHE2=false
NGINX=false
checkService() 
{
    serviceName=$1
    serviceToCheckExists=$2
    if echo "$serviceName" | grep -qi "$serviceToCheckExists"; then
        echo "\n${BLUE}$serviceToCheckExists is on this machine${NC}"
        if netstat -tulpn | grep -qi "$serviceToCheckExists"; then
            echo "On port(s) ${YELLOW}$(netstat -tulpn | grep -i $serviceToCheckExists | awk 'BEGIN {ORS=" and "} {print $1, $4}' | sed 's/\(.*\)and /\1\n/')${NC}"
        fi
    fi
}

if checkService "$SERVICES"  'ssh' | grep -qi "is on this machine"; then checkService "$SERVICES"  'ssh' ; SSH=true ;fi
if checkService "$SERVICES"  'docker' | grep -qi "is on this machine"; then 
    checkService "$SERVICES"  'docker'
    echo "Current Active Containers"
    echo "${ORAG}$(docker ps)${NC}"
fi

if checkService "$SERVICES"  'cockpit' | grep -qi "is on this machine"; then 
    checkService "$SERVICES"  'cockpit' 
    echo "${ORAG}WE PROBABLY SHOULD KILL COCKPIT${NC}"
fi

if checkService "$SERVICES"  'apache2' | grep -qi "is on this machine"; then 
    checkService "$SERVICES"  'apache2'
    APACHE2VHOSTS=$(cat /etc/apache2/sites-enabled/* | grep -E 'VirtualHost|DocumentRoot')
    echo "Configuration Details"
    echo "${ORAG}$APACHE2VHOSTS${NC}"
    APACHE2=true
fi

if checkService "$SERVICES"  'ftp' | grep -qi "is on this machine"; then 
    checkService "$SERVICES"  'ftp'
    FTPCONF=$(cat /etc/*ftp* | grep -v '#' | grep -E 'anonymous_enable|guest_enable|no_anon_password|write_enable')
    echo "Configuration Details"
    echo "${ORAG}$FTPCONF${NC}"
fi


if checkService "$SERVICES"  'nginx' | grep -qi "is on this machine"; then 
    checkService "$SERVICES"  'nginx' 
    NGINXCONFIG=$(cat /etc/nginx/sites-enabled/default | grep -v '#'  | sed '/^\s*$/d' )
    echo "Configuration Details"
    echo "${ORAG}$NGINXCONFIG${NC}"
    NGINX=true
fi

if checkService "$SERVICES"  'mysql' | grep -qi "is on this machine"; then checkService "$SERVICES"  'mysql' ; MYSQL=true; fi
if checkService "$SERVICES"  'mariadb' | grep -qi "is on this machine"; then checkService "$SERVICES"  'mariadb' ; MARIADB=true; fi
if checkService "$SERVICES"  'python' | grep -qi "is on this machine"; then checkService "$SERVICES"  'python' ; PYTHON=true; fi
if checkService "$SERVICES"  'dropbear' | grep -qi "is on this machine"; then checkService "$SERVICES"  'dropbear' ; DROPBEAR=true; fi