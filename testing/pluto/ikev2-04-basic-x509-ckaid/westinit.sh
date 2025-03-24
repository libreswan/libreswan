# Import EAST's cert and extract its CKAID
/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/east.end.p12
eastckaid=$(ipsec showhostkey --list | sed -e 's/.*ckaid: //')

# Import WEST's cert and extract its CKAID
/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/west.p12
westckaid=$(ipsec showhostkey --list | sed -e 's/.*ckaid: //')

/testing/x509/import.sh real/mainca/east.end.cert

echo west ckaid: $westckaid east ckaid: $eastckaid
sed -i -e "s/WESTCKAID/$westckaid/" -e "s/EASTCKAID/$eastckaid/" /etc/ipsec.conf

# confirm that the network is alive
../../guestbin/wait-until-alive -I 192.0.1.254 192.0.2.254
# ensure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# confirm clear text does not get through
../../guestbin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
ipsec auto --status | grep westnet-eastnet-ikev2
ipsec whack --impair suppress_retransmits
echo "initdone"
