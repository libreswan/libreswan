/testing/guestbin/swan-prep --nokeys # empty NSS DB

# import fiddled keys
ipsec pk12util -i OUTPUT/west.p12 -W foobar
ipsec pk12util -i OUTPUT/east.p12 -W foobar
ipsec certutil -K

# patch up ipsec.conf
sed -i -e "s/@east-ckaid@/`cat OUTPUT/east.ckaid`/" /etc/ipsec.conf
sed -i -e "s/@west-ckaid@/`cat OUTPUT/west.ckaid`/" /etc/ipsec.conf

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
