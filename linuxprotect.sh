#!/bin/bash
#A script to defend an protect Linux servers like Debian or Ubuntu
v="version 0.1"
#@naivenom

#help function
usage () 
{ 
echo -e "\n\e[00;31m#########################################################\e[00m" 
echo -e "\e[00;31m#\e[00m" "\e[00;33mLinux Defend and Detect Attacks\e[00m" "\e[00;31m#\e[00m"
echo -e "\e[00;31m#########################################################\e[00m"
echo -e "\e[00;33m# www.fwhibbit.es | @naivenom \e[00m"
echo -e "\e[00;33m# $v\e[00m\n"
echo -e "\e[00;33m# Example: ./linuxprotect.sh -k keyword -r report -e /tmp/ -t \e[00m\n"

		echo "OPTIONS:"
		echo "-k	Enter keyword or option"
		echo "-e	Enter export location"
		echo "-t	Include thorough (lengthy) tests"
		echo "-r	Enter report name" 
		echo "-h	Displays this help text"
		echo "-i  	Displays IPTABLES Configuration"
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

echo -e "\e[00;33mTool started at:"; date 
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
	echo -e "Deny all HTTPS packets requests from this server TO remote servers"
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
