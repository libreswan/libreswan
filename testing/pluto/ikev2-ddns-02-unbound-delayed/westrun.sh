sleep 5
ipsec status |grep "===" # should show %dns for pending resolving
unbound-control-setup > /dev/null 2>&1
# use modified service file that skips ICANN root key checks
cat /lib/systemd/system/unbound.service | grep -v ExecStartPre > /etc/systemd/system/unbound.service
systemctl daemon-reload
systemctl start unbound.service
unbound-control local_data right.libreswan.org 3600 IN A 192.1.2.23
# trigger DDNS event (saves us from waiting)
ipsec whack --ddns --name named
# give conn time to establish by itself
sleep 3
# tunnel should show up in final.sh
# seems to slow down/hang shutdown 
rm /etc/resolv.conf
echo done
