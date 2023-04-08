#!/bin/bash

apt-get update -y && apt-get install unzip nmap chromium golang -y 
wget -O /root/nuclei.zip https://github.com/projectdiscovery/nuclei/releases/download/v2.9.1/nuclei_2.9.1_linux_amd64.zip
unzip /root/nuclei.zip
mv nuclei /usr/bin/nuclei
nuclei -i $1 -me /root/initial
wget http://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
unzip aquatone_linux_amd64_1.7.0.zip
mv aquatone /usr/bin
nmap -T5 -oX /root/foraqua $1 
cat /root/foraqua.xml | aquatone