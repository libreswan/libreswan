/testing/guestbin/swan-prep --x509
certutil -D -n west -d sql:/etc/ipsec.d
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add ikev2-westnet-eastnet
# block IKE and ESP over UDP
iptables -I INPUT -p udp --dport 500 -j DROP
iptables -I INPUT -p udp --dport 4500 -j DROP
echo "initdone"
