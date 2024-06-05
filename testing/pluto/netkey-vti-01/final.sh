grep -v -P "\t0$" /proc/net/xfrm_stat
ipsec whack --shutdown
# there should be no vti0 device left
../../guestbin/ip.sh address show vti0
