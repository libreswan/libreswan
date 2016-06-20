: ==== start ====
TESTNAME=mast-l2tp-04
HOST=japan
source /testing/pluto/bin/hostlocal.sh japan

route delete -net default
ifconfig eth0 inet 192.1.3.209 netmask 255.255.255.0
route add -net default gw 192.1.3.254

if [ -f /var/run/l2tpd.pid ]; then kill `cat /var/run/l2tpd.pid`; fi

iptables -F INPUT
iptables -F OUTPUT
ipsec setup stop

# make sure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.1.2.23 -p udp --sport 1701 -j REJECT
iptables -A OUTPUT -o eth1 -d 192.1.2.23 -p udp --dport 1701 -j REJECT

ipsec start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add japan--east-l2tp

ipsec whack --debug-control --debug-controlmore --debug-natt

if [ ! -f /etc/ppp/chap-secrets ]; then mount --bind /testing/pluto/l2tp-01 /etc/ppp; fi
(cd /tmp && l2tpd -c /testing/pluto/mast-l2tp-04/japan.l2tpd.conf -D 2>/tmp/l2tpd.log ) &

ipsec auto --route japan--east-l2tp

echo done

