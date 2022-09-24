#!/bin/bash

YUM_CMD=$(which yum)
APT_GET_CMD=$(which apt-get)

if [[ ! -z $YUM_CMD ]]; then
    yum install rsyslog -y 
elif [[ ! -z $APT_GET_CMD ]]; then
    echo "Updating and Upgrading Packages"
    apt update && apt upgrade -y
    echo "Installing rsyslog"
    apt install rsyslog -y 
else
    echo "Installation Failed"
    exit 1;
fi

read -p "IP to forward to: " IP

cat << EOF > /etc/rsyslog.conf
\$ModLoad imfile 
\$InputFileName /var/log/auth.log 
\$InputFileStateFile auth_log 
\$InputFileTag auth_log 
\$InputFileSeverity info
\$InputFileFacility local1
\$InputRunFileMonitor

\$InputFileName /var/log/apache2/access.log
\$InputFileStateFile access_log
\$InputFileTag access_log
\$InputFileSeverity info
\$InputFileFacility local3
\$InputFileRunMonitor

*.* @$IP:514
EOF