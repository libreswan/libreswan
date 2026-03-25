/testing/guestbin/swan-prep --nokeys

/testing/x509/import.sh real/mainca/east.end.cert
/testing/x509/import.sh real/mainca/west.p12
cp -v OUTPUT/ipsec.conf /etc/ipsec.conf

# confirm that the network is alive
../../guestbin/wait-until-alive -I 192.0.1.254 192.0.2.254
# ensure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# confirm clear text does not get through
../../guestbin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add westnet-eastnet-ikev2
ipsec connectionstatus westnet-eastnet-ikev2
ipsec whack --impair suppress_retransmits
echo "initdone"
