# we should see a connection switch on east
ipsec whack --trafficstatus
hostname | grep east && grep '^[^|].* switched ' /tmp/pluto.log
