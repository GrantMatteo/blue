#!/bin/sh
echo "username,password" > $(hostname).csv
for user in $(cat /etc/passwd | grep -P "/bin/.*sh" | cut -f1 -d':'); do
        pass=$(cat /dev/urandom | tr -dc '[:alpha:]' | fold -w ${1:-20} | head -n 1)
        #echo $user:$pass | chpasswd
        echo "$user,$pass" >> $(hostname).csv
done
#rm $(hostname).csv
#rm $(basename "$0")