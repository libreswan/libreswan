: confirm that my key is present in DNS
dig 2.1.0.192.in-addr.arpa. key
dig japan.uml.freeswan.org. key

ipsec setup $CFG start

sleep 2
ipsec eroute
/testing/pluto/co-terminal-02/eroutewait.sh trap
ipsec auto  $CFG --delete packetdefault

ipsec auto  $CFG --add japan--wavesec
ipsec whack --listen

ipsec auto  $CFG --add clear
ipsec whack --listen
ipsec auto  $CFG --route clear

/testing/pluto/co-terminal-02/eroutewait.sh pass

ipsec whack --debug-oppo --debug-control --debug-controlmore

ipsec auto  $CFG --add private-or-clear
ipsec whack --listen
ipsec auto  $CFG --route private-or-clear

sh /testing/pluto/co-terminal-02/eroutewait.sh trap

ipsec auto $CFG --up japan--wavesec
ipsec eroute | sed -e 's/^[0-9]* /n /' -e 's/tun0x..../tun0xABCD/'

ping -n -c 1 1.2.3.4
/testing/pluto/co-terminal-02/eroutewait.sh tun0
ipsec eroute | sed -e 's/^[0-9]* /n /' -e 's/tun0x..../tun0xABCD/'
ping -n -c 1 1.2.3.4

sleep 1

ping -n -c 1 192.0.2.2
/testing/pluto/co-terminal-02/eroutewait.sh 192.1.2.23
ping -n -c 1 192.0.2.2
ipsec eroute | sed -e 's/^[0-9]* /n /' -e 's/tun0x..../tun0xABCD/'

ipsec auto --up japan--wavesec
ipsec eroute | sed -e 's/^[0-9]* /n /' -e 's/tun0x..../tun0xABCD/'

echo done


