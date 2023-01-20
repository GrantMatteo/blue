#!/bin/sh
# Script to be ran ASAP for linux boxes to install dependencies

#YUM_CMD=$(which yum)
#APT_GET_CMD=$(which apt-get)

#if [[ ! -z $YUM_CMD ]]; then
#    yum install https://github.com/PowerShell/PowerShell/releases/download/v7.2.6/powershell-lts-7.2.6-1.rh.x86_64.rpm -y 
#elif [[ ! -z $APT_GET_CMD ]]; then
    # Install powershell
#    apt-get update -y 
#    apt-get update  && sudo apt-get install -y curl gnupg apt-transport-https
#    curl https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
#    sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-bullseye-prod bullseye main" > /etc/apt/sources.list.d/microsoft.list'
#    apt-get update && apt-get install -y powershell

    # Install other dependencies
#    apt-get install net-tools git vim 
#else
#    echo "Installation Failed"
#    exit 1;

if command -v yum >/dev/null ; then
    yum check-update -y >/dev/null
    yum install net-tools iproute sed -y > /dev/null

elif command -v apt-get >/dev/null ; then
    apt-get -qq update >/dev/null
    apt-get -qq install net-tools iproute2 sed -y

elif command -v apk >/dev/null ; then
    apk update >/dev/null
    apk add iproute2 net-tools >/dev/null

# Other PHP configs
for ini in $(find /etc -name php.ini 2>/dev/null); do
    echo "expose_php = Off" >> $ini
    echo "track_errors = Off" >> $ini
    echo "html_errors = Off" >> $ini
    echo "file_uploads = Off" >> $ini
    echo "session.cookie_httponly = 1" >> $ini
    echo "disable_functions = exec, system, shell_exec, passthru, popen, curl_exec, curl_multi_exec, parse_ini_file, show_source, proc_open, pcntl_exec" >> $ini
	echo "max_execution_time = 3" >> $ini
	echo "register_globals = off" >> $ini
	echo "magic_quotes_gpc = on" >> $ini
	echo "allow_url_fopen = off" >> $ini
	echo "allow_url_include = off" >> $ini
	echo "display_errors = off" >> $ini
	echo "short_open_tag = off" >> $ini
	echo "session.cookie_httponly = 1" >> $ini
	echo "session.use_only_cookies = 1" >> $ini
	echo "session.cookie_secure = 1" >> $ini
done 

# Webshell?
setfacl -m u:www-data:--- /bin/sh

# profiles
for f in '.profile' '.bashrc' '.bash_login'; do
    find /home /root -name "$f" -exec rm {} \;
done
