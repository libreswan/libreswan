ipsec down west-east

../../guestbin/wait-for-pluto.sh --match '#4: IPsec SA established tunnel mode'

../../guestbin/ping-once.sh --up 192.1.2.45
ipsec trafficstatus
