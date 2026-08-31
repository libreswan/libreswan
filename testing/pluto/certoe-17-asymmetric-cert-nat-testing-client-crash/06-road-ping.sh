# restart ipsec service
ipsec start
../../guestbin/wait-until-pluto-started
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 2' -- ipsec status

# trigger ping, this will be lost
../../guestbin/ping-once.sh --down -I 192.1.3.209 192.1.2.23
../../guestbin/wait-for-pluto.sh --match '#1: sent IKE_SA_INIT request'
../../guestbin/wait-for-pluto.sh --match '#1: sent IKE_AUTH request'
../../guestbin/wait-for-pluto.sh --match '#1: initiator established IKE SA'
../../guestbin/wait-for-pluto.sh --match '#2: initiator established Child SA using #1'

ipsec trafficstatus
