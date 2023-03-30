#!/bin/sh
cat /var/log/iptra*/*.log | awk -F ';' '{print $5}' | awk '{print $2}' | sort -r | uniq -c | sort -r
