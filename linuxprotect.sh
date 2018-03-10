#!/bin/bash
#Script for hardening Linux servers
v="version 0.1"
#@naivenom

#help function
usage () 
{ 
echo -e "\n\e[00;31m#########################################################\e[00m" 
echo -e "\e[00;31m#\e[00m" "\e[00;33mLinux Defend and Detect Attacks\e[00m" "\e[00;31m#\e[00m"
echo -e "\e[00;31m#########################################################\e[00m"
echo -e "\e[00;33m# www.fwhibbit.es && @naivenom \e[00m"
echo -e "\e[00;33m# $v\e[00m\n"
echo -e "\e[00;33m# Example: ./linuxprotect.sh -i -k ssh_server"

		echo "OPTIONS:"
		echo "-k	Enter keyword or option"
		echo "-e	Enter export location"
		echo "-t	Include thorough (lengthy) tests"
		echo "-r	Enter report name" 
		echo "-h	Displays this help text"
		echo "-i  	Displays IPTABLES Basic Execution Command for LAN Network"
		echo "-I  	Displays IPTABLES Advanced Execution Command for LAN Network with DMZ"
		echo -e "\n"
		echo "Running with no options = limited execution/no output file"
		
echo -e "\e[00;31m#########################################################\e[00m"		
}
header()
{
echo -e "\n\e[00;31m#########################################################\e[00m" 
echo -e "\e[00;31m#\e[00m" "\e[00;33mLinux Defend and Detect Attacks\e[00m" "\e[00;31m#\e[00m" 
echo -e "\e[00;31m#########################################################\e[00m" 
echo -e "\e[00;33m# www.fwhibbit.es\e[00m" 
echo -e "\e[00;33m# $version\e[00m\n" 

}

debug_info()
{
echo "Debug Info" 

if [ "$keyword" ]; then 
	echo "keyword = $keyword" 
else 
	:
fi

if [ "$report" ]; then 
	echo "report name = $report" 
else 
	:
fi

if [ "$export" ]; then 
	echo "export location = $export" 
else 
	:
fi

if [ "$thorough" ]; then 
	echo "thorough tests = enabled" 
else 
	echo "thorough tests = disabled" 
fi

if [ "$iptables_basic" ]; then 
	echo "iptables basic execution = enabled" 
else 
	echo "iptables basic execution = disabled" 
fi

if [ "$iptables_advanced" ]; then 
	echo "iptables advanced execution = enabled" 
else 
	echo "iptables advanced execution = disabled" 
fi

sleep 2

if [ "$export" ]; then
	mkdir $export 2>/dev/null
	format=$export/linuxprotect-export-`date +"%d-%m-%y"`
	mkdir $format 2>/dev/null
else 
	:
fi

who=`whoami` 2>/dev/null 
echo -e "\n" 

echo -e "\e[00;33mThe Tool was executed:"; date 
echo -e "\e[00m\n" 
}

iptables_basic()
{
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
	echo -e "Setting policy by default"

else 
	:
fi

}

iptables_advanced()
{
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
	echo -e "DNS Requests"
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
	echo -e "Setting policy by default"

else 
	:
fi

}

call_functions()
{
	header
	debug_info
	iptables_basic
	iptables_advanced
}

while getopts "h:k:r:e:t:i:I" option; do
 case "${option}" in
		k) keyword=${OPTARG};;
		r) report=${OPTARG}"-"`date +"%d-%m-%y"`;;
		e) export=${OPTARG};;
		t) thorough=1;;
		i) iptables_basic=1;;
		I) iptables_advanced=1;;
		h) usage; exit;;
		*) usage; exit;;
 esac
done



call_functions | tee -a $report 2> /dev/null
