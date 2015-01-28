sleep 5
echo "192.1.2.23 right.libreswan.org" >> /etc/hosts
# wait for DDNS event
# Oddly designed connection_check_ddns() will trigger --up
sleep 30
sleep 30
sleep 30
# tunnel should show up in final.sh
echo done
