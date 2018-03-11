# linuxprotect
Script for hardening Linux servers

| Parameter  | Description|
| ----- | ------ |
| -k | Enter keyword or option |
| -e | Enter export location |
| -t | Include thorough (lengthy) tests |
| -r | Enter report name |
| -h | Displays this help text |
| -i | Displays IPTABLES Basic Execution Command for LAN Network |
| -I | Displays IPTABLES Advanced Execution Command for LAN Network with DMZ |


| Functions  | Keyword|
| ----- | ------ |
| iptables_basic | status: basic iptables status of firewall </br> dns_ext: Allow DNS request through Internet </br> http_ext: Allow HTTP and HTTPS request through Internet </br> dhcp_ext: Allow DHCP request </br> icmp_ext: Allow outgoing ping request </br> ssh_ext: Allow SSH request </br> ssh_server: Allow SSH conexion to this Server </br> icmp_lan: Allow ICMP forwarding to LAN Network<br/> http_lan: Allow HTTP and HTTPS traffic forwarding to LAN Network </br> http_server: Allow HTTP Server forwarding to LAN Network </br> dns_lan: Allow DNS Request forwarding to LAN Network </br> dnat_http: DNAT to client of the LAN Network </br> snat_lan: SNAT for outgoing packets through internet </br> list_filter: List of rules applied to the filter table </br> list_nat: List of rules applied for the table nat </br> delete_selective: Selective deleting by rule number </br> restart_firewall: Deleting (flushing) all the rules and delete chain </br> policy_default: Setting policy by default|
| iptables_advanced | status, dns_ext, http_ext, icmp_ext, ssh_ext, ssh_dmz, ssh_server, icmp_dmz, <br/> http_dmz, dns_dmz, http_dmz_server, mail_dmz_server |

Example:
./linuxprotect.sh -i -k ssh_server
