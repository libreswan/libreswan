: ==== start ====
TESTNAME=l2tp-03
export HOST=road
source /testing/pluto/bin/hostlocal.sh

if [ -f /var/run/l2tpd.pid ]; then kill `cat /var/run/l2tpd.pid`; fi

iptables -F INPUT
iptables -F OUTPUT
ipsec setup stop

# make sure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.1.2.23 -p udp --sport 1701 -j REJECT
iptables -A OUTPUT -o eth1 -d 192.1.2.23 -p udp --dport 1701 -j REJECT

ipsec setup restart
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add road--east-l2tp
ipsec whack --debug-control --debug-controlmore --debug-natt

if [ ! -f /etc/ppp/chap-secrets ]; then mount --bind /testing/pluto/l2tp-01 /etc/ppp; fi
(cd /tmp && l2tpd -c /testing/pluto/l2tp-03/road.l2tpd.conf -D 2>/tmp/l2tpd.log ) &

ipsec auto --route road--east-l2tp

echo done

