sleep 5
ipsec status |grep "===" # should show %dns for pending resolving
echo "192.1.2.23 right.libreswan.org" >> /etc/hosts
# trigger DDNS event (saves us from waiting)
ipsec whack --ddns
# give conn time to establish by itself
sleep 3
# tunnel should show up in final.sh
echo done
