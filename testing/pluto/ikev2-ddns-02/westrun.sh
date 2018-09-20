sleep 5
unbound-control-setup > /dev/null 2>&1
# use modified service file that skips ICANN root key checks
cat /lib/systemd/system/unbound.service | grep -v ExecStartPre > /etc/systemd/system/unbound.service
systemctl daemon-reload
systemctl start unbound.service
unbound-control local_data right.libreswan.org 3600 IN A 192.1.2.23
# wait for DDNS event
# Oddly designed connection_check_ddns will trigger --up
sleep 30
sleep 30
sleep 30
# tunnel should show up in final.sh
# seems to slow down/hang shutdown 
rm /etc/resolv.conf
echo done
