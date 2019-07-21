# check traffic status after crashing server
ipsec whack --trafficstatus
ipsec whack --shuntstatus
# check ping and traffic status
ping -n -c 5 -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
