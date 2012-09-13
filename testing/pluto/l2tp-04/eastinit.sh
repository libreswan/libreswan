: ==== start ====
TESTNAME=l2tp-04
source /testing/pluto/bin/eastlocal.sh

sh /etc/init.d/inetd restart

if [ -f /var/run/l2tpd.pid ]; then kill `cat /var/run/l2tpd.pid`; fi

ipsec setup restart
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add client--east-l2tp-x509
ipsec whack --debug-control --debug-controlmore --debug-natt

# make sure that clear text does not get through
iptables -A INPUT  -i eth1 -d 192.1.2.23 -p udp --dport 1701 -j REJECT
iptables -A OUTPUT -o eth1 -s 192.1.2.23 -p udp --sport 1701 -j REJECT

if [ ! -f /etc/ppp/chap-secrets ]; then mount --bind /testing/pluto/l2tp-01 /etc/ppp; fi
(cd /tmp && l2tpd -c /testing/pluto/l2tp-01/east.l2tpd.conf -D 2>/tmp/l2tpd.log ) &

