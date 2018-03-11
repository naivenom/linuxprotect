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
| iptables_basic | status: Basic iptables status of firewall </br> dns_ext: Allow DNS request through Internet </br> http_ext: Allow HTTP and HTTPS request through Internet </br> dhcp_ext: Allow DHCP request </br> icmp_ext: Allow outgoing ping request </br> ssh_ext: Allow SSH request </br> ssh_server: Allow SSH conexion to this Server </br> icmp_lan: Allow ICMP forwarding to LAN Network<br/> http_lan: Allow HTTP and HTTPS traffic forwarding to LAN Network </br> http_server: Allow HTTP Server forwarding to LAN Network </br> dns_lan: Allow DNS Request forwarding to LAN Network </br> dnat_http: DNAT to client of the LAN Network </br> snat_lan: SNAT for outgoing packets through internet </br> list_filter: List of rules applied to the filter table </br> list_nat: List of rules applied for the table nat </br> delete_selective: Selective deleting by rule number </br> restart_firewall: Deleting (flushing) all the rules and delete chain </br> policy_default: Setting policy by default|
| iptables_advanced | status: Basic iptables status of firewall </br> avoid_scan: Restrict certain types of scans or malformed packages </br> avoid_syn: Limit incoming TCP SYN connections </br> avoid_ping: Avoid ping per second and IP ADDRESS </br> dns_ext: Allow DNS request through Internet </br> http_ext: Allow HTTP and HTTPS request through Internet </br> icmp_ext: Allow or enable ping request </br> ssh_ext: Allow SSH </br> ssh_dmz: Allow SSH request to DMZ </br> ssh_server: Allow SSH Server traffic </br> icmp_dmz: Allow source ICMP traffic from DMZ <br/> http_dmz: Allow HTTP and HTTPS traffic </br> dns_dmz: Allow DNS Requests </br> http_dmz_server: Allow DMZ Web Server traffic. HTTP and HTTPS </br> mail_dmz_server: Allow Mail Web Server traffic </br> icmp_lan: Allow source ICMP traffic from LAN Network </br> http_lan: Allow HTTP and HTTPS traffic </br> http_server: Allow HTTP server in LAN Network </br> dns_lan: Allow DNS Requests </br> dnat_http: DNAT to client of the DMZ Network --> HTTP Port 80 </br> dnat_https: DNAT to client of the DMZ Network --> HTTPS Port 443 </br> dnat_smtp: DNAT to client of the DMZ Network --> SMTP Port 25 </br> dnat_smtps: DNAT to client of the DMZ Network --> SMTPS Port 465 </br> dnat_pop3: DNAT to client of the DMZ Network --> POP3 Port 110 </br> dnat_pop3secure: DNAT to client of the DMZ Network --> POP3 Securely Port 995 </br> dnat_imap: DNAT to client of the DMZ Network --> IMAP Port 220 </br> dnat_imaps: DNAT to client of the DMZ Network --> IMAPS Port 993 </br> snat_lan: SNAT for outgoing packets through internet and LAN NETWORK </br> snat_dmz: SNAT for outgoing packets through internet and DMZ NETWORK </br> list_filter: List of rules applied to the filter table </br> list_nat: List of rules applied for the table nat </br> delete_selective: Selective deleting by rule number </br> restart_firewall: Deleting (flushing) all the rules and delete chain </br> policy_default: Setting policy by default|

(avoid_scan,avoid_syn and avoid_ping) These rules must be executed just before the rules for connections**</br>
Example:
./linuxprotect.sh -i basic -k ssh_server
