# show default listen on all IPs
ipsec pluto --config west.conf
../../guestbin/wait-until-pluto-started
ipsec whack --listen > /dev/null
ipsec status | grep "000 interface"
ipsec whack --shutdown
ipsec pluto --config west-listen.conf
../../guestbin/wait-until-pluto-started
ipsec whack --listen > /dev/null
# It should only listen on 192.1.2.45 and not on 192.0.1.254
ipsec status | grep "000 interface"
ipsec whack --shutdown
echo done
