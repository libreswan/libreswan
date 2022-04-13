/testing/guestbin/swan-prep

# scrub the nssdb (is there a swan-prep option?)
rm /etc/ipsec.d/*.db
modutil -create -dbdir /etc/ipsec.d -force

# import fiddled keys
pk12util -d /etc/ipsec.d/ -i OUTPUT/west.p12 -W foobar
pk12util -d /etc/ipsec.d/ -i OUTPUT/east.p12 -W foobar
certutil -K -d /etc/ipsec.d/

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
ipsec whack --impair suppress-retransmits
echo "initdone"
