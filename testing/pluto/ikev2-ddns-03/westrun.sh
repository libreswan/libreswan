sleep 5
echo "192.1.2.23 right.libreswan.org" >> /etc/hosts
# trigger DDNS event (saves us from waiting)
ipsec whack --ddns
# there should be no states
ipsec showstates
ipsec status | grep "===" # should no longer show %dns as resolving completed
# confirm it all resolved by bringing the conn up manually
ipsec auto --up named
echo done
