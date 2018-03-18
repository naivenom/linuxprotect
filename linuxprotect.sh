#!/bin/bash
#Script for hardening Linux servers
v="version 0.1"
#@naivenom

#help function
usage () 
{ 
echo -e "\n\e[00;31m#########################################################\e[00m" 
echo -e "\e[00;31m#\e[00m" "\e[00;33mMonitoring and defending Linux servers\e[00m" "\e[00;31m#\e[00m"
echo -e "\e[00;31m#########################################################\e[00m"
echo -e "\e[00;33m# www.fwhibbit.es && @naivenom \e[00m"
echo -e "\e[00;33m# $v\e[00m\n"
echo -e "\e[00;33m# Example: ./linuxprotect.sh -i advanced -k status"

		echo "OPTIONS:"
		echo "-k		Enter keyword or option"
		echo "-e		Enter export location"
		echo "-t		Include thorough (lengthy) tests"
		echo "-r		Enter report name" 
		echo "-h		Displays this help text"
		echo "-i  		Displays IPTABLES Execution Command for LAN Network. Mode: -i basic/advanced"
		echo "-r 		Displays RECON in LAN Network. Mode: -r scan/dhcp/dns"
		echo "-s 		Displays SERVICES in Server. Mode: -s disable/enable/info"
		echo "-H 		Displays HOST FILE in Server. Mode: -H configure/malicious/dns"
		echo "-T 		Displays TIMEZONE in Server. Mode: -H configure/malicious/dns"
		echo -e "\n"
		echo "Running with no options = limited execution/no output file"
		
echo -e "\e[00;31m#########################################################\e[00m"		
}
header()
{
echo -e "\n\e[00;31m#########################################################\e[00m" 
echo -e "\e[00;31m#\e[00m" "\e[00;33mMonitoring and defending Linux servers\e[00m" "\e[00;31m#\e[00m" 
echo -e "\e[00;31m#########################################################\e[00m" 
echo -e "\e[00;33m# www.fwhibbit.es\e[00m" 
echo -e "\e[00;33m# @naivenom\e[00m" 
echo -e "\e[00;33m# $v\e[00m\n" 

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

if [ "$iptables" ]; then 
	echo "iptables execution = enabled" 
else 
	echo "iptables execution = disabled" 
fi

if [ "$recon" ]; then 
	echo "recon execution = enabled" 
else 
	echo "recon execution = disabled" 
fi

if [ "$services" ]; then 
	echo "services execution = enabled" 
else 
	echo "services execution = disabled" 
fi

if [ "$host" ]; then 
	echo "host execution = enabled" 
else 
	echo "host execution = disabled" 
fi

sleep 2

if [ "$export" ]; then
	mkdir $export 2>/dev/null
	format=$export/linuxprotect-export-`date +"%d-%m-%y"`
	mkdir $format 2>/dev/null
else 
	:
fi


echo -e "\e[00;33mThe Tool was executed:"; date 
echo -e "\e[00m\n" 
}




recon_dhcp()
{
	echo -e "\e[00;33m### DHCP LEASE LOGS ##############################################\e[00m"
	grep -Ei 'dhcp' /var/log/syslog.1
	
	
}

recon_dns()
{
	echo -e "\e[00;33m### DNS LOGS ##############################################\e[00m"
	tail -f /var/log/messages | grep named
	
	
}

services_info()
{
	echo -e "\e[00;33m### SERVICES INFO ##############################################\e[00m"
	if [ "$keyword" = "service" ]; then
		service --status-all
	else 
		:
	fi

	if [ "$keyword" = "ps" ]; then
		ps -ef
		ps -aux
	else 
		:
	fi
	
	
}

services_start()
{
	echo -e "\e[00;33m### SERVICE START ##############################################\e[00m"
	if [ "$keyword" = "apache2" ]; then
		/etc/init.d/apache2 start
	else 
		:
	fi

	if [ "$keyword" = "mysql" ]; then
		service mysql start
	else 
		:
	fi
	
	
}

services_restart()
{
	echo -e "\e[00;33m### SERVICE RESTART ##############################################\e[00m"
	if [ "$keyword" = "apache2" ]; then
		/etc/init.d/apache2 restart
	else 
		:
	fi

	if [ "$keyword" = "mysql" ]; then
		service mysql restart
	else 
		:
	fi
	
	
}

services_stop()
{
	echo -e "\e[00;33m### SERVICE STOP ##############################################\e[00m"
	if [ "$keyword" = "apache2" ]; then
	/etc/init.d/apache2 stop
	else 
		:
	fi

	if [ "$keyword" = "mysql" ]; then
	service mysql stop
	else 
		:
	fi
	
	
}

host()
{

	if [ "$keyword" = "route_localhost" ]; then
		echo -e "\e[00;33m### NEW MALICIOUS DOMAIN ##############################################\e[00m"
		read -p 'Introduce MALICIOUS DOMAIN: ' domain
		echo 127.0.0.1 $domain >> /etc/hosts
	else 
		:
	fi

	if [ "$keyword" = "check_route" ]; then
		read -p 'Introduce MALICIOUS DOMAIN: ' domain
		ping -c 1 $domain
	else 
		:
	fi
	

	if [ "$keyword" = "dns_flush" ]; then
		echo -e "\e[00;33m### DNS CACHE ##############################################\e[00m"
		/etc/init.d/dns-clean start
	else 
		:
	fi

	if [ "$keyword" = "dnsmasq_flush" ]; then
		noexist=`apt-cache policy dnsmasq | grep Installed | cut -d' ' -f4`
		if [ "$noexist" == "(none)" ]; then
			apt-get install dnsmasq
		else 
			/etc/init.d/dnsmasq restart
		fi
	else 
		:
	fi
	
	if [ "$keyword" = "configure" ]; then
		echo -e "\e[00;33m### CONFIGURE HOSTNAME ##############################################\e[00m"
		echo " Type a HOSTNAME to identify this server :"
		echo -n "For Example: myserver): "; read hostnamee
		echo -n "Domain Name: "; read domainname
		read -p 'Server IP: ' ip
		echo $hostnamee > /etc/hostname
		hostname -F /etc/hostname
		echo "127.0.0.1    localhost.localdomain     localhost" >> /etc/hosts
		echo "$ip    $hostnamee.$domainname    $hostnamee" >> /etc/hosts
		echo "Creating legal Banners for unauthorized access"
		cat files/motd > /etc/motd
		cat files/motd > /etc/issue
		cat files/motd > /etc/issue.net
	else 
		:
	fi
}



timezone()
{
	
	if [ "$keyword" = "configure" ]; then
		echo -e "\e[00;33m### CONFIGURE TIMEZONE ##############################################\e[00m"
		dpkg-reconfigure tzdata
	else 
		:
	fi
	
}


call_functions()
{
	header
	debug_info
	if [ "$iptables" = "basic" ]; then
	./iptables_basic.sh
	else 
		:
	fi
	if [ "$iptables" = "advanced" ]; then
	./iptables_advanced.sh
	else 
		:
	fi
	if [ "$recon" = "scan" ]; then
	./recon_scan.sh
	else 
		:
	fi

	if [ "$recon" = "dhcp" ]; then
	recon_dhcp
	else 
		:
	fi

	if [ "$recon" = "dns" ]; then
	recon_dns
	else 
		:
	fi

	if [ "$services" = "info" ]; then
	services_info
	else 
		:
	fi

	if [ "$services" = "start" ]; then
	services_start
	else 
		:
	fi

	if [ "$services" = "restart" ]; then
	services_restart
	else 
		:
	fi

	if [ "$services" = "stop" ]; then
	services_stop
	else 
		:
	fi

	if [ "$system" = "host" ]; then
	host
	else 
		:
	fi

	if [ "$system" = "timezone_configure" ]; then
	timezone_configure
	else 
		:
	fi
}

while getopts "i:r:s:H:T:h:k:r:e:t" option; do
 case "${option}" in
		i) iptables=${OPTARG};;
		r) recon=${OPTARG};;
		s) services=${OPTARG};;
		S) system=${OPTARG};;
		k) keyword=${OPTARG};;
		r) report=${OPTARG}"-"`date +"%d-%m-%y"`;;
		e) export=${OPTARG};;
		t) thorough=1;;
		h) usage; exit;;
		*) usage; exit;;
 esac
done



call_functions | tee -a $report 2> /dev/null
