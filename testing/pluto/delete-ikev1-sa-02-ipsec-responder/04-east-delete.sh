ipsec whack --deletestate 2

../../guestbin/wait-for-pluto.sh --match '#3: IPsec SA established tunnel mode'

../../guestbin/ping-once.sh --up 192.1.2.45
ipsec trafficstatus
