#!/bin/bash

YUM_CMD=$(which yum)
APT_GET_CMD=$(which apt-get)

read "IP: " IP

if [[ ! -z $YUM_CMD ]]; then
    yum install rsyslog audit curl -y 
elif [[ ! -z $APT_GET_CMD ]]; then
    apt-get update
    apt-get install rsyslog auditd curl -y 
else
    echo "Installation Failed"
    exit 1;
fi

curl https://raw.githubusercontent.com/Neo23x0/auditd/master/audit.rules > /etc/audit/audit.rules
cat /etc/audit/audit.rules > /etc/audit/rules.d/audit.rules

SERVICE=$(which systemctl)

if [[ ! -z systemctl ]]; then
    systemctl restart rsyslog
    systemctl restart auditd
else 
    service rsyslog restart
    service auditd restart
fi

grep -Prl 'general_log_file' /etc/ | xargs echo Enable SQL logging at

cat << EOF > /etc/rsyslog.conf

# Ubuntu Auth 
\$ModLoad imfile 
\$InputFileName /var/log/auth.log 
\$InputFileStateFile auth_log 
\$InputFileTag auth_log 
\$InputFileSeverity info
\$InputFileFacility local1
\$InputRunFileMonitor

# CentOS Auth
\$InputFileName /var/log/secure
\$InputFileStateFile auth_log
\$InputFileTag auth_log
\$InputFileSeverity info
\$InputFileFacility local1
\$InputRunFileMonitor

# Ubuntu Apache2
\$InputFileName /var/log/apache2/access.log
\$InputFileStateFile access_log
\$InputFileTag access_log
\$InputFileSeverity info
\$InputFileFacility local2
\$InputRunFileMonitor

# RHEL Apache2
\$InputFileName /var/log/httpd/access_log
\$InputFileStateFile access_log
\$InputFileTag access_log
\$InputFileSeverity info
\$InputFileFacility local2
\$InputRunFileMonitor

# Nginx
\$InputFileName /var/log/nginx/access.log
\$InputFileStateFile access_log
\$InputFileTag access_log
\$InputFileSeverity info
\$InputFileFacility local2
\$InputRunFileMonitor

# Honeypot logging (thepot.sh)
\$InputFileName /var/log/honeypot
\$InputFileStateFile honeypot
\$InputFileTag honeypot
\$InputFileSeverity info
\$InputFileFacility local3
\$InputRunFileMonitor

# MySQL logging
\$InputFileName /var/log/mysql/mysql.log
\$InputFileStateFile database
\$InputFileTag database
\$InputFileSeverity info
\$InputFileFacility local4
\$InputRunFileMonitor

# AuditDeez
\$InputFileName /var/log/audit/audit.log
\$InputFileStateFile audit
\$InputFileTag audit
\$InputFileSeverity info
\$InputFileFacility local5
\$InputRunFileMonitor

*.* @$IP:514
EOF