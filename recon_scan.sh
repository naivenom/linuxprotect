#!/bin/bash
#Script for hardening Linux servers
#@naivenom

echo -e "\e[00;33m### SCAN ##############################################\e[00m"
sleep 1
	
if [ "$keyword" = "bash_ping" ]; then
	read -p 'Introduce Network (Ex:10.10.1): ' net
	for i in {1..254}; do ping -c 1 -W 1 $net.$i | grep 'from'; done
else 
	:
fi

if [ "$keyword" = "nmap_ping" ]; then
	read -p 'Introduce Network (Ex:10.10.1.0/24): ' net
	nmap -sn -PE $net
else 
	:
fi

if [ "$keyword" = "nmap_scan" ]; then
	read -p 'Introduce IP: ' ip
	nmap -v -Pn -T4 -A -p- $ip
else 
	:
fi