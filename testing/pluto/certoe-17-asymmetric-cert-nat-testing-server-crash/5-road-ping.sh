# check traffic status after crashing server
ipsec whack --trafficstatus
ipsec whack --shuntstatus
# trigger ping, this will be lost
ping -n -c 1 -I 192.1.3.209 192.1.2.23
# check ping and traffic status
ping -n -c 4 -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
