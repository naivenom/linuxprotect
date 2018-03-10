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
| iptables_basic | status, dns_ext, http_ext, dhcp_ext, icmp_ext, ssh_ext, ssh_server, icmp_lan,<br/> http_lan, http_server, dns_lan, dnat_http, snat_lan, list_filter, list_nat,<br/> delete_selective, restart_firewall, policy_default|
| iptables_advanced | status, dns_ext, http_ext, icmp_ext, ssh_ext, ssh_dmz, ssh_server |

Example:
./linuxprotect.sh -i -k ssh_server
