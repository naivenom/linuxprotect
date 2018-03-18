#!/bin/bash
#Script for hardening Linux servers
#@naivenom

echo -e "\e[00;33m### IPTABLES ##############################################\e[00m" 
echo -e "Using default policy to DROP"
#basic iptables status of firewall
if [ "$keyword" = "status" ]; then 
	iptables -L -n -v
else 
	:
fi

echo 1 >/proc/sys/net/ipv4/ip_forward

########################OUTGOING AND INCOMING REQUESTS TO THIS FIREWALL SERVER
#Loopback traffic ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

#DNS request through Internet
if [ "$keyword" = "dns_ext" ]; then
	read -p 'External interface: ' ext_int
	echo -e "Allow DNS request through Internet"
	iptables -A INPUT -i $ext_int -p udp --sport 53 -j ACCEPT
	iptables -A OUTPUT -o $ext_int -p udp --dport 53 -j ACCEPT
else 
	:
fi

#HTTP and HTTPS request through Internet
if [ "$keyword" = "http_ext" ]; then
	read -p 'External interface: ' ext_int
	echo -e "Allow HTTP and HTTPS request through Internet"
	iptables -A INPUT -i $ext_int -p tcp --sport 80 -j ACCEPT
	iptables -A OUTPUT -o $ext_int -p tcp --dport 80 -j ACCEPT
	iptables -A INPUT -i $ext_int -p tcp --sport 443 -j ACCEPT
	iptables -A OUTPUT -o $ext_int -p tcp --dport 443 -j ACCEPT
else 
	:
fi

#DHCP request
if [ "$keyword" = "dhcp_ext" ]; then
	read -p 'External interface: ' ext_int
	echo -e "Allow DHCP"
	iptables -A INPUT -i $ext_int -p udp --sport 67:68 -j ACCEPT
	iptables -A OUTPUT -o $ext_int -p udp --dport 67:68 -j ACCEPT
else 
	:
fi

#Allow or enable outgoing ping request
if [ "$keyword" = "icmp_ext" ]; then
	read -p 'External interface: ' ext_int
	echo -e "Allow or enable outgoing ping request"
	iptables -A INPUT -i $ext_int -p icmp -m state --state ESTABLISHED,RELATED -j ACCEPT
	iptables -A OUTPUT -o $ext_int -p icmp -j ACCEPT
else 
	:
fi

#SSH request
if [ "$keyword" = "ssh_ext" ]; then
	read -p 'External interface: ' ext_int
	echo -e "Allow SSH"
	iptables -A INPUT -i $ext_int -p tcp --sport 22 -j ACCEPT
	iptables -A OUTPUT -o $ext_int -p tcp --dport 22 -j ACCEPT
else 
	:
fi

#Allow SSH conexion to this Server
if [ "$keyword" = "ssh_server" ]; then
	echo -e "Allow SSH conexion to this Server"
	iptables -A INPUT -p tcp --sport 22 -j ACCEPT
	iptables -A OUTPUT -p tcp --dport 22 -j ACCEPT
else 
	:
fi

########################FORWARDING TO LAN NETWORK

#Allow ICMP
if [ "$keyword" = "icmp_lan" ]; then
	read -p 'External interface: ' ext_int
	read -p 'LAN interface: ' lan_int
	echo -e "Allow or enable outgoing ping request"
	iptables -t filter -A FORWARD -i $lan_int -o $ext_int -p icmp -j ACCEPT
	iptables -t filter -A FORWARD -i $ext_int -o $lan_int -p icmp -j ACCEPT
else 
	:
fi

#Allow HTTP and HTTPS traffic
if [ "$keyword" = "http_lan" ]; then
	read -p 'External interface: ' ext_int
	read -p 'LAN interface: ' lan_int
	echo -e "Allow HTTP and HTTPS traffic"
	iptables -A FORWARD -i $lan_int -o $ext_int -p tcp --dport 80 -j ACCEPT
	iptables -A FORWARD -i $ext_int -o $lan_int -p tcp --sport 80 -j ACCEPT
	iptables -A FORWARD -i $lan_int -o $ext_int -p tcp --dport 443 -j ACCEPT
	iptables -A FORWARD -i $ext_int -o $lan_int -p tcp --sport 443 -j ACCEPT
else 
	:
fi

#HTTP Server
if [ "$keyword" = "http_server" ]; then
	read -p 'External interface: ' ext_int
	read -p 'LAN interface: ' lan_int
	echo -e "HTTP Server"
	iptables -A FORWARD -i $ext_int -o $lan_int -p tcp --dport 80 -j ACCEPT
	iptables -A FORWARD -i $lan_int -o $ext_int -p tcp --sport 80 -j ACCEPT
else 
	:
fi

#DNS Requests
if [ "$keyword" = "dns_lan" ]; then
	read -p 'External interface: ' ext_int
	read -p 'LAN interface: ' lan_int
	echo -e "DNS Requests"
	iptables -A FORWARD -i $lan_int -o $ext_int -p tcp --dport 53 -j ACCEPT
	iptables -A FORWARD -i $ext_int -o $lan_int -p tcp --sport 53 -j ACCEPT
else 
	:
fi

#################################NAT
#DNAT to client of the LAN Network. HTTP 
if [ "$keyword" = "dnat_http" ]; then
	read -p 'External interface: ' ext_int
	read -p 'Client OR Server IP: ' ip
	echo -e "DNAT to client of the LAN Network --> HTTP Port 80"
	iptables -t nat -A PREROUTING -i $ext_int -p tcp --dport 80 -j DNAT --to-destination $ip
else 
	:
fi

#SNAT FOR OUTGOING PACKETS THROUGH INTERNET (EXTERNAL INTERFACE)
if [ "$keyword" = "snat_lan" ]; then
	read -p 'External interface: ' ext_int
	read -p 'LAN Network: ' net #192.168.1.0/24
	echo -e "SNAT for outgoing packets through internet"
	iptables -t nat -A POSTROUTING -s $net -o $ext_int -j MASQUERADE
else 
	:
fi

#List of rules applied to the filter table
if [ "$keyword" = "list_filter" ]; then 
	iptables -t filter -nvL --line-numbers
	echo -e "List of rules applied to the filter table"
else 
	:
fi

#List of rules applied for the table nat
if [ "$keyword" = "list_nat" ]; then 
	iptables -t nat -nvL --line-numbers
	echo -e "List of rules applied for the table nat"
else 
	:
fi

#Selective deleting by rule number
if [ "$keyword" = "delete_selective" ]; then
	read -p 'Introduce table: ' table
	read -p 'Introduce chain: ' cadena
	read -p 'Introduce number of rule: ' number
	iptables -t $table -D $cadena $number
	echo -e "Selective deleting by rule number"

else 
	:
fi

#Deleting (flushing) all the rules and delete chain
if [ "$keyword" = "restart_firewall" ]; then 
	iptables -F
	iptables -X
	echo -e "Deleting (flushing) all the rules and delete chain"

else 
	:
fi

if [ "$keyword" = "policy_default" ]; then
	read -p 'Introduce chain: ' chain
	iptables -P $chain DROP
	echo -e "Setting policy by default to DROP"

else 
	:
fi