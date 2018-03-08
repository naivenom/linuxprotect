#!/bin/bash
#Script para defender y monitorizar servidores Linux
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
echo -e "\e[00;33m# Example: ./linuxprotect.sh -i -k https_drop"

		echo "OPTIONS:"
		echo "-k	Enter keyword or option"
		echo "-e	Enter export location"
		echo "-t	Include thorough (lengthy) tests"
		echo "-r	Enter report name" 
		echo "-h	Displays this help text"
		echo "-i  	Displays IPTABLES Execution"
		echo -e "\n"
		echo "Running with no options = limited scans/no output file"
		
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

if [ "$iptables_exec" ]; then 
	echo "iptables execution = enabled" 
else 
	echo "iptables execution = disabled" 
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

echo -e "\e[00;33mTool ejecuta en:"; date 
echo -e "\e[00m\n" 
}

iptables_exec()
{
echo -e "\e[00;33m### IPTABLES ##############################################\e[00m" 

#basic iptables status of firewall

if [ "$keyword" = "status" ]; then 
	iptables -L -n -v
else 
	:
fi

if [ "$keyword" = "https_drop" ]; then 
	iptables -A OUTPUT -p tcp --dport 443 -j DROP
	iptables -A INPUT -p tcp --sport 443 -j DROP
	echo -e "Descartado todos los paquetes HTTPS desde este servidor a servidores remotos (peticion y respuesta)"
else 
	:
fi

if [ "$keyword" = "http_drop" ]; then 
	iptables -A OUTPUT -p tcp --dport 80 -j DROP
	iptables -A INPUT -p tcp --sport 80 -j DROP
	echo -e "Descartado todos los paquetes HTTP desde este servidor a servidores remotos (peticion y respuesta)"

else 
	:
fi

if [ "$keyword" = "http_forward" ]; then 
	read -p 'Paquetes que entran por la Interface: ' interface_entrada
	read -p 'Paquetes que salen por la Interface: ' interface_salida
	iptables -t filter -A FORWARD -i $interface_entrada -o $interface_salida -p tcp --dport 80 -j DROP
	iptables -t filter -A FORWARD -i $interface_entrada -o $interface_salida -p tcp --sport 80 -j DROP
	echo -e "Descartado trafico HTTP para aquellos servidores o maquinas que pasan por el server que ejecuta Iptables en este script (peticion y respuesta)"
else 
	:
fi

if [ "$keyword" = "ssh_forward" ]; then 
	read -p 'Paquetes que entran por la Interface: ' interface_entrada
	read -p 'Paquetes que salen por la Interface: ' interface_salida
	iptables -t filter -A FORWARD -i $interface_entrada -o $interface_salida -p tcp --dport 22 -j DROP
	iptables -t filter -A FORWARD -i $interface_entrada -o $interface_salida -p tcp --sport 22 -j DROP
	echo -e "Descartado trafico HTTP para aquellos servidores o maquinas que pasan por el server que ejecuta Iptables en este script (peticion y respuesta)"
else 
	:
fi

if [ "$keyword" = "nat_postrouting" ]; then 
	read -p 'Paquetes que salen por la Interface: ' interface_salida
	iptables -t nat -A POSTROUTING -o $interface_salida -j MASQUERADE
	echo -e "Realizado SNAT para enrutamiento de los paquetes por la interfaz de salida $interface_salida con IP publica"
else 
	:
fi

if [ "$keyword" = "restart_rules" ]; then 
	iptables -F
	iptables -X
	echo -e "Deleting (flushing) all the rules and delete chain"

else 
	:
fi
}

call_each()
{
	header
	debug_info
	iptables_exec
}

while getopts "h:k:r:e:t:i" option; do
 case "${option}" in
		k) keyword=${OPTARG};;
		r) report=${OPTARG}"-"`date +"%d-%m-%y"`;;
		e) export=${OPTARG};;
		t) thorough=1;;
		i) iptables_exec=1;;
		h) usage; exit;;
		*) usage; exit;;
 esac
done



call_each | tee -a $report 2> /dev/null
#EndOfScript
