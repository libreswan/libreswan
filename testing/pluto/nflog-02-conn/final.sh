../../guestbin/ipsec-look.sh
ipsec stop
# show no nflog left behind
iptables -L -n
