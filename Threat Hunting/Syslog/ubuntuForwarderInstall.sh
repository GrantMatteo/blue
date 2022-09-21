#!/bin/bash

echo "Updating and Upgrading Packages"
apt update && apt upgrade -y

echo "Installing rsyslog"
apt install rsyslog -y 

read -p "IP to forward to: " IP

echo '$ModLoad imfile 
$InputFileName /var/log/auth.log 
$InputFileStateFile auth_log 
$InputFileTag auth_log 
$InputFileSeverity info
$InputFileFacility local1
$InputRunFileMonitor

$InputFileName /var/log/apache2/access.log
$InputFileStateFile access_log
$InputFileTag access_log
$InputFileSeverity info
$InputFileFacility local3
$InputFileRunMonitor

*.* @'$IP':514' > /etc/rsyslog.conf