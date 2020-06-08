systemctl start ipsec.service || echo failed
systemctl status ipsec.service >/dev/null || echo failed
systemctl start ipsec.service && echo detected proper failure
systemctl status ipsec.service >/dev/null || echo failed
systemctl restart ipsec.service || echo failed
systemctl status ipsec.service >/dev/null || echo failed
systemctl stop ipsec.service || echo failed
systemctl status ipsec.service >/dev/null && echo detected proper failure
systemctl stop ipsec.service || echo failed
systemctl status ipsec.service >/dev/null && echo detected proper failure
systemctl start ipsec.service || echo failed
systemctl force-reload ipsec.service || echo failed
systemctl status ipsec.service >/dev/null || echo failed	
systemctl start ipsec.service || echo failed
systemctl restart ipsec.service || echo failed
systemctl status ipsec.service >/dev/null || echo failed	
systemctl start ipsec.service || echo failed
systemctl condrestart ipsec.service || echo failed
systemctl status ipsec.service >/dev/null || echo failed	
service ipsec start || echo failed
service ipsec status >/dev/null || echo failed
service ipsec start || echo failed
service ipsec status >/dev/null || echo failed
service ipsec restart || echo failed
service ipsec status >/dev/null || echo failed
service ipsec stop || echo failed
service ipsec status >/dev/null && echo detected proper failure
service ipsec stop || echo failed
service ipsec status >/dev/null && echo detected proper failure
service ipsec start || echo failed
service ipsec force-reload || echo failed
service ipsec status >/dev/null || echo failed	
service ipsec start || echo failed
service ipsec restart || echo failed
service ipsec status >/dev/null || echo failed	
service ipsec start || echo failed
service ipsec condrestart || echo failed
service ipsec status >/dev/null || echo failed	
# test for fix that starts ipsec only after nic/network is online, rhbz#1145245
grep "After=network-online.target" /lib/systemd/system/ipsec.service
# test for rhbz#1127313 (IPsec holes for IPv6 neighbour discovery)
ip -o xfrm pol |grep ipv6-icmp
# test for rhbz#1572620
ipsec auto --add mytunnel
# will fail
timeout 10s ipsec auto --up mytunnel
ipsec status > /dev/null || echo status should have returned 0
grep "pending IPsec SA" /tmp/pluto.log
echo done
