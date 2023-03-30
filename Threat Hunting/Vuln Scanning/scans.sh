#!/bin/bash

apt-get update -y && apt install nuclei unzip nmap chromium -y 
nuclei -i $1 -me /root/initial
wget http://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
apt-get install unzip
unzip aquatone_linux_amd64_1.7.0.zip
mv aquatone /usr/bin
nmap -T5 -oX /root/foraqua $1 
cat /root/foraqua.xml | aquatone