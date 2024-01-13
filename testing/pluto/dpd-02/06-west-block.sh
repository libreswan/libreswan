# wait for at least one R_U_THERE packet
../../guestbin/wait-for-pluto.sh 'processing informational R_U_THERE'
# set up block via iptables
iptables -I INPUT -s 192.1.2.23/32 -d 0/0 -j DROP
iptables -I OUTPUT -d 192.1.2.23/32 -s 0/0 -j DROP
