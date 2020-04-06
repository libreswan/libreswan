systemctl start ipsec.service || echo failed
systemctl status ipsec.service || echo failed
systemctl start ipsec.service && echo detected proper failure
systemctl status ipsec.service || echo failed
systemctl restart ipsec.service || echo failed
systemctl status ipsec.service || echo failed
systemctl stop ipsec.service || echo failed
systemctl status ipsec.service && echo detected proper failure
systemctl stop ipsec.service || echo failed
systemctl status ipsec.service && echo detected proper failure
systemctl start ipsec.service || echo failed
systemctl force-reload ipsec.service || echo failed
systemctl status ipsec.service || echo failed	
systemctl start ipsec.service || echo failed
systemctl restart ipsec.service || echo failed
systemctl status ipsec.service || echo failed	
systemctl start ipsec.service || echo failed
systemctl condrestart ipsec.service || echo failed
systemctl status ipsec.service || echo failed	
service ipsec start || echo failed
service ipsec status || echo failed
service ipsec start || echo failed
service ipsec status || echo failed
service ipsec restart || echo failed
service ipsec status || echo failed
service ipsec stop || echo failed
service ipsec status && echo detected proper failure
service ipsec stop || echo failed
service ipsec status && echo detected proper failure
service ipsec start || echo failed
service ipsec force-reload || echo failed
service ipsec status || echo failed	
service ipsec start || echo failed
service ipsec restart || echo failed
service ipsec status || echo failed	
service ipsec start || echo failed
service ipsec condrestart || echo failed
service ipsec status || echo failed	
# test for rhbz#1127313 (IPsec holes for IPv6 neighbour discovery)
ip -o xfrm pol |grep ipv6-icmp
# test for rhbz#1572620
ipsec auto --add mytunnel
# will fail
timeout 10s ipsec auto --up mytunnel
ipsec status > /dev/null || echo status should have returned 0
grep "pending IPsec SA" /tmp/pluto.log
echo done
