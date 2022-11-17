#!/bin/sh
echo "username,password" > $(hostname).csv
for user in $(cat /etc/passwd | grep -E "/bin/.*sh" | cut -f1 -d':'); do
        pass=$(cat /dev/urandom | tr -dc '[:alpha:][:digit:]' | fold -w ${1:-20} | head -n 1)
	if [ $user = "root" ]; then
                echo $user:$ROOTPASS | chpasswd
                echo "$user,$ROOTPASS" >> $(hostname).csv
	elif [ $user = $USER ]; then
		echo $USER:$PASS | chpasswd
		echo "$USER,$PASS" >> $(hostname).csv
	else
        	echo $user:$pass | chpasswd
		echo "$user,$pass" >> $(hostname).csv
        fi
done
cat $(hostname).csv
rm $(hostname).csv
