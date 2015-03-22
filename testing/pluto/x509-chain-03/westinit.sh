/testing/guestbin/swan-prep --x509 --certchain
certutil -A -n "east_chain_intermediate_2" -d sql:/etc/ipsec.d -t 'c,,' -a -i /testing/x509/cacerts/east_chain_intermediate_2.crt
certutil -A -n "east_chain_intermediate_1" -d sql:/etc/ipsec.d -t 'c,,' -a -i /testing/x509/cacerts/east_chain_intermediate_1.crt
# confirm that the network is alive
ping -n -c 4 -I 192.0.1.254 192.0.2.254
# make sure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j LOGDROP
# confirm with a ping
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --debug-all --impair-retransmits
ipsec auto --add westnet-eastnet-x509-chain
echo "initdone"
