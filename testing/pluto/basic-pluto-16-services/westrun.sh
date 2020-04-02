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
echo done
