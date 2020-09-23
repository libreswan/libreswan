# check traffic status after east was crashed
# we expect the old tunnel and no shunts?
ipsec whack --trafficstatus
ipsec whack --shuntstatus
# ensure DPD on road triggers - clean up happens.
sleep 10
# ping again to trigger OE. packet is lost
ping -n -c 1 -I 192.1.3.209 192.1.2.23
sleep 3
# check ping, expected to succeed now via %pass
ping -n -c 4 -I 192.1.3.209 192.1.2.23
# should show no tunnel
ipsec whack --trafficstatus
