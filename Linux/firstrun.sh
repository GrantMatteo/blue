# Script to be ran ASAP for linux boxes to install dependencies

YUM_CMD=$(which yum)
APT_GET_CMD=$(which apt-get)

if [[ ! -z $YUM_CMD ]]; then
    yum install https://github.com/PowerShell/PowerShell/releases/download/v7.2.6/powershell-lts-7.2.6-1.rh.x86_64.rpm -y 
elif [[ ! -z $APT_GET_CMD ]]; then
    apt-get update -y 
    apt update  && sudo apt install -y curl gnupg apt-transport-https
    curl https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
    sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-bullseye-prod bullseye main" > /etc/apt/sources.list.d/microsoft.list'
    apt update && apt install -y powershell
else
    echo "Installation Failed"
    exit 1;
fi