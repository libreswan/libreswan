# this end still things tunnel is up, when it isn't
# - responder has dpdactin=clear
ipsec whack --trafficstatus
../../guestbin/ping-once.sh --down 192.1.2.23
ipsec whack --trafficstatus
