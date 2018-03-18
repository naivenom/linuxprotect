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

########################AVOID SCAN
if [ "$keyword" = "avoid_scan" ]; then
	read -p 'External interface: ' ext_int
	read -p 'Introduce chain (INPUT|FORWARD): ' chain
	echo -e "Restrict certain types of scans or malformed packages"
	echo -e "I/O for this own server (INPUT/OUTPUT) OR traffic not directed at this server (FORWARD)"
	iptables -A $chain -i $ext_int -p tcp --tcp-flags ACK ACK -m state --state NEW -j REJECT
	iptables -A $chain -i $ext_int -p tcp --tcp-flags RST RST -m state --state NEW -j REJECT
	iptables -A $chain -i $ext_int -p tcp --tcp-flags PSH PSH -m state --state NEW -j REJECT
	iptables -A $chain -i $ext_int -p tcp --tcp-flags FIN FIN -m state --state INVALID -j REJECT
	iptables -A $chain -i $ext_int -p tcp --tcp-flags FIN,PSH,URG FIN,PSH,URG -j DROP
	iptables -A $chain -i $ext_int -p tcp --tcp-flags ALL ACK,RST,SYN,FIN -j DROP
	iptables -A $chain -i $ext_int -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
	iptables -A $chain -i $ext_int -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
	iptables -A $chain -i $ext_int -p tcp --tcp-flags ALL NONE -j DROP
	
else 
	:
fi

##########################AVOID TCP SYN INPUT CONNECTIONS (SYN FLOOD)

if [ "$keyword" = "avoid_syn" ]; then
	read -p 'External interface: ' ext_int
	read -p 'Introduce chain (INPUT|FORWARD): ' chain
	echo -e "Limit incoming TCP SYN connections"
	echo -e "I/O for this own server (INPUT/OUTPUT) OR traffic not directed at this server (FORWARD)"
	iptables -A $chain -i $ext_int -p tcp --syn -m recent --set
	iptables -A $chain -i $ext_int -p tcp --syn -m recent --update --seconds 5 --hitcount 20 -j DROP
	
	
else 
	:
fi

##########################AVOID PING PER SECOND AND IP ADDRESS (ICMP FLOOD)

if [ "$keyword" = "avoid_ping" ]; then
	read -p 'External interface: ' ext_int
	read -p 'Introduce chain (INPUT|FORWARD): ' chain
	echo -e "Avoid ping per second and IP ADDRESS"
	echo -e "I/O for this own server (INPUT/OUTPUT) OR traffic not directed at this server (FORWARD)"
	iptables -A $chain -i $ext_int -p icmp --icmp-type echo-request -m hashlimit --hashlimit-name ping --hashlimit-above 1/s --hashlimit-burst 2 --hashlimit-mode srcip -j REJECT
	
	
else 
	:
fi


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

#Allow ICMP
if [ "$keyword" = "icmp_ext" ]; then
	echo -e "Allow or enable ping request"
	iptables -A INPUT -p icmp -j ACCEPT
	iptables -A OUTPUT -p icmp -j ACCEPT
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

#SSH request TO DMZ
if [ "$keyword" = "ssh_dmz" ]; then
	read -p 'DMZ interface: ' dmz_int
	read -p 'External interface: ' ext_int
	read -p 'DMZ Network: ' net_dmz
	echo -e "Allow SSH request to DMZ"
	iptables -A INPUT -i $dmz_int -s $net_dmz -p tcp --sport 22 -j ACCEPT
	iptables -A OUTPUT -o $ext_int -d $net_dmz -p tcp --dport 22 -j ACCEPT
else 
	:
fi

#SSH Server
if [ "$keyword" = "ssh_server" ]; then
	read -p 'LAN interface: ' lan_int
	read -p 'External interface: ' ext_int
	echo -e "Allow SSH Server traffic"
	iptables -A INPUT -i $lan_int -p tcp --dport 22 -j ACCEPT
	iptables -A OUTPUT -o $lan_int -p tcp --sport 22 -j ACCEPT
	iptables -A INPUT -i $ext_int -s 8.8.8.8 -p tcp --dport 22 -j ACCEPT
	iptables -A OUTPUT -o $ext_int -d 8.8.8.8 -p tcp --sport 22 -j ACCEPT
	iptables -A INPUT -i $ext_int -s 8.8.4.4 -p tcp --dport 22 -j ACCEPT
	iptables -A OUTPUT -o $ext_int -d 8.8.4.4 -p tcp --sport 22 -j ACCEPT
else 
	:
fi

##############################FORWARDING TO DMZ NETWORK

#Allow source ICMP traffic from DMZ
if [ "$keyword" = "icmp_dmz" ]; then
	read -p 'DMZ interface: ' dmz_int
	read -p 'External interface: ' ext_int
	read -p 'DMZ Network: ' net_dmz
	echo -e "Allow source ICMP traffic from DMZ"
	iptables -A FORWARD -i $dmz_int -s $net_dmz -p icmp -j ACCEPT
	iptables -A FORWARD -o $dmz_int -d $net_dmz -p icmp --icmp-type destination-unreachable -j ACCEPT
	iptables -A FORWARD -o $dmz_int -d $net_dmz -p icmp --icmp-type time-exceeded -j ACCEPT
	iptables -A FORWARD -o $dmz_int -d $net_dmz -p icmp --icmp-type echo-reply -j ACCEPT
	iptables -A FORWARD -o $dmz_int -d $net_dmz -p icmp --icmp-type echo-request -j ACCEPT

else 
	:
fi

#Allow HTTP and HTTPS traffic
if [ "$keyword" = "http_dmz" ]; then
	read -p 'External interface: ' ext_int
	read -p 'DMZ interface: ' dmz_int
	echo -e "Allow HTTP and HTTPS traffic"
	iptables -A FORWARD -i $dmz_int -o $ext_int -p tcp --dport 80 -j ACCEPT
	iptables -A FORWARD -i $ext_int -o $dmz_int -p tcp --sport 80 -j ACCEPT
	iptables -A FORWARD -i $dmz_int -o $ext_int -p tcp --dport 443 -j ACCEPT
	iptables -A FORWARD -i $ext_int -o $dmz_int -p tcp --sport 443 -j ACCEPT
else 
	:
fi

#DNS Requests
if [ "$keyword" = "dns_dmz" ]; then
	read -p 'External interface: ' ext_int
	read -p 'DMZ interface: ' dmz_int
	echo -e "Allow DNS Requests"
	iptables -A FORWARD -i $dmz_int -o $ext_int -p tcp --dport 53 -j ACCEPT
	iptables -A FORWARD -i $ext_int -o $dmz_int -p tcp --sport 53 -j ACCEPT
else 
	:
fi

#Allow DMZ Web Server traffic. HTTP and HTTPS
if [ "$keyword" = "http_dmz_server" ]; then
	read -p 'DMZ interface: ' dmz_int
	read -p 'External interface: ' ext_int
	read -p 'DMZ Network: ' net_dmz
	echo -e "Allow DMZ Web Server traffic. HTTP and HTTPS"
	iptables -A FORWARD -d $net_dmz -i $ext_int -o $dmz_int -p tcp --dport 80 -j ACCEPT
	iptables -A FORWARD -s $net_dmz -i $dmz_int -o $ext_int -p tcp --sport 80 -j ACCEPT
	iptables -A FORWARD -d $net_dmz -i $ext_int -o $dmz_int -p tcp --dport 443 -j ACCEPT
	iptables -A FORWARD -s $net_dmz -i $dmz_int -o $ext_int -p tcp --sport 443 -j ACCEPT
else 
	:
fi

#Allow DMZ Mail Server traffic.
if [ "$keyword" = "mail_dmz_server" ]; then
	read -p 'DMZ interface: ' dmz_int
	read -p 'External interface: ' ext_int
	read -p 'DMZ Network: ' net_dmz
	echo -e "Allow Mail Web Server traffic"
	iptables -A FORWARD -d $net_dmz -i $ext_int -o $dmz_int -p tcp --dport 25 -j ACCEPT
	iptables -A FORWARD -s $net_dmz -i $dmz_int -o $ext_int -p tcp --sport 25 -j ACCEPT
	iptables -A FORWARD -d $net_dmz -i $ext_int -o $dmz_int -p tcp --dport 465 -j ACCEPT
	iptables -A FORWARD -s $net_dmz -i $dmz_int -o $ext_int -p tcp --sport 465 -j ACCEPT
	iptables -A FORWARD -d $net_dmz -i $ext_int -o $dmz_int -p tcp --dport 110 -j ACCEPT
	iptables -A FORWARD -s $net_dmz -i $dmz_int -o $ext_int -p tcp --sport 110 -j ACCEPT
	iptables -A FORWARD -d $net_dmz -i $ext_int -o $dmz_int -p tcp --dport 995 -j ACCEPT
	iptables -A FORWARD -s $net_dmz -i $dmz_int -o $ext_int -p tcp --sport 995 -j ACCEPT
	iptables -A FORWARD -d $net_dmz -i $ext_int -o $dmz_int -p tcp --dport 220 -j ACCEPT
	iptables -A FORWARD -s $net_dmz -i $dmz_int -o $ext_int -p tcp --sport 220 -j ACCEPT
	iptables -A FORWARD -d $net_dmz -i $ext_int -o $dmz_int -p tcp --dport 993 -j ACCEPT
	iptables -A FORWARD -s $net_dmz -i $dmz_int -o $ext_int -p tcp --sport 993 -j ACCEPT
else 
	:
fi

##############################FORWARDING TO LAN NETWORK
#Allow source ICMP traffic from LAN Network
if [ "$keyword" = "icmp_lan" ]; then
	read -p 'LAN interface: ' lan_int
	read -p 'LAN Network: ' net
	echo -e "Allow source ICMP traffic from LAN Network"
	iptables -A FORWARD -i $lan_int -s $net -p icmp -j ACCEPT
	iptables -A FORWARD -o $lan_int -d $net -p icmp --icmp-type destination-unreachable -j ACCEPT
	iptables -A FORWARD -o $lan_int -d $net -p icmp --icmp-type time-exceeded -j ACCEPT
	iptables -A FORWARD -o $lan_int -d $net -p icmp --icmp-type echo-reply -j ACCEPT
	iptables -A FORWARD -o $lan_int -d $net -p icmp --icmp-type echo-request -j ACCEPT

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

#Allow HTTP server in LAN Network
if [ "$keyword" = "http_server" ]; then
	read -p 'LAN interface: ' dmz_int
	read -p 'External interface: ' ext_int
	echo -e "Allow HTTP server in LAN Network"
	iptables -A FORWARD -i $ext_int -o $lan_int -p tcp --dport 80 -j ACCEPT
	iptables -A FORWARD -i $lan_int -o $ext_int -p tcp --sport 80 -j ACCEPT
else 
	:
fi

#DNS Requests
if [ "$keyword" = "dns_lan" ]; then
	read -p 'External interface: ' ext_int
	read -p 'LAN interface: ' lan_int
	echo -e " Allow DNS Requests"
	iptables -A FORWARD -i $lan_int -o $ext_int -p tcp --dport 53 -j ACCEPT
	iptables -A FORWARD -i $ext_int -o $lan_int -p tcp --sport 53 -j ACCEPT
else 
	:
fi

################################NAT
#OPEN PORTS
#DNAT to client of the DMZ Network. HTTP 
if [ "$keyword" = "dnat_http" ]; then
	read -p 'External interface: ' ext_int
	read -p 'Client OR Server IP: ' ip
	echo -e "DNAT to client of the DMZ Network --> HTTP Port 80"
	iptables -t nat -A PREROUTING -i $ext_int -p tcp --dport 80 -j DNAT --to-destination $ip
else 
	:
fi

#DNAT to client of the DMZ Network. HTTPS
if [ "$keyword" = "dnat_https" ]; then
	read -p 'External interface: ' ext_int
	read -p 'Client OR Server IP: ' ip
	echo -e "DNAT to client of the DMZ Network --> HTTPS Port 443"
	iptables -t nat -A PREROUTING -i $ext_int -p tcp --dport 443 -j DNAT --to-destination $ip
else 
	:
fi

#DNAT to client of the DMZ Network. SMTP
if [ "$keyword" = "dnat_smtp" ]; then
	read -p 'External interface: ' ext_int
	read -p 'Client OR Server IP: ' ip
	echo -e "DNAT to client of the DMZ Network --> SMTP Port 25"
	iptables -t nat -A PREROUTING -i $ext_int -p tcp --dport 25 -j DNAT --to-destination $ip
else 
	:
fi

#DNAT to client of the DMZ Network. SMTPS
if [ "$keyword" = "dnat_smtps" ]; then
	read -p 'External interface: ' ext_int
	read -p 'Client OR Server IP: ' ip
	echo -e "DNAT to client of the DMZ Network --> SMTPS Port 465"
	iptables -t nat -A PREROUTING -i $ext_int -p tcp --dport 465 -j DNAT --to-destination $ip
else 
	:
fi

#DNAT to client of the DMZ Network. POP3
if [ "$keyword" = "dnat_pop3" ]; then
	read -p 'External interface: ' ext_int
	read -p 'Client OR Server IP: ' ip
	echo -e "DNAT to client of the DMZ Network --> POP3 Port 110"
	iptables -t nat -A PREROUTING -i $ext_int -p tcp --dport 110 -j DNAT --to-destination $ip
else 
	:
fi

#DNAT to client of the DMZ Network. POP3 Securely
if [ "$keyword" = "dnat_pop3secure" ]; then
	read -p 'External interface: ' ext_int
	read -p 'Client OR Server IP: ' ip
	echo -e "DNAT to client of the DMZ Network --> POP3 Securely Port 995"
	iptables -t nat -A PREROUTING -i $ext_int -p tcp --dport 995 -j DNAT --to-destination $ip
else 
	:
fi

#DNAT to client of the DMZ Network. IMAP
if [ "$keyword" = "dnat_imap" ]; then
	read -p 'External interface: ' ext_int
	read -p 'Client OR Server IP: ' ip
	echo -e "DNAT to client of the DMZ Network --> IMAP Port 220"
	iptables -t nat -A PREROUTING -i $ext_int -p tcp --dport 220 -j DNAT --to-destination $ip
else 
	:
fi

#DNAT to client of the DMZ Network. IMAPS
if [ "$keyword" = "dnat_imaps" ]; then
	read -p 'External interface: ' ext_int
	read -p 'Client OR Server IP: ' ip
	echo -e "DNAT to client of the DMZ Network --> IMAPS Port 993"
	iptables -t nat -A PREROUTING -i $ext_int -p tcp --dport 993 -j DNAT --to-destination $ip
else 
	:
fi

#SNAT FOR OUTGOING PACKETS THROUGH INTERNET (EXTERNAL INTERFACE)
if [ "$keyword" = "snat_lan" ]; then
	read -p 'External interface: ' ext_int
	read -p 'LAN Network: ' net #192.168.1.0/24
	echo -e "SNAT for outgoing packets through internet and LAN NETWORK"
	iptables -t nat -A POSTROUTING -s $net -o $ext_int -j MASQUERADE
else 
	:
fi

#SNAT FOR OUTGOING PACKETS THROUGH INTERNET (EXTERNAL INTERFACE)
if [ "$keyword" = "snat_dmz" ]; then
	read -p 'External interface: ' ext_int
	read -p 'DMZ Network: ' net_dmz #192.168.1.0/24
	echo -e "SNAT for outgoing packets through internet and DMZ NETWORK"
	iptables -t nat -A POSTROUTING -s $net_dmz -o $ext_int -j MASQUERADE
else 
	:
fi

if [ "$keyword" = "list_filter" ]; then 
	iptables -t filter -nvL --line-numbers
	echo -e "List of rules applied to the filter table"
else 
	:
fi

if [ "$keyword" = "list_nat" ]; then 
	iptables -t nat -nvL --line-numbers
	echo -e "List of rules applied for the table nat"
else 
	:
fi

if [ "$keyword" = "delete_selective" ]; then
	read -p 'Introduce table: ' table
	read -p 'Introduce chain: ' cadena
	read -p 'Introduce number of rule: ' number
	iptables -t $table -D $cadena $number
	echo -e "Selective deleting by rule number"

else 
	:
fi

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

if [ "$keyword" = "disable_ipv6" ]; then
	read -p 'Introduce chain: ' chain
	ip6tables -P $chain DROP
	echo -e "Deactivation of the ipv6 protocol"

else 
	:
fi