# let road and north wait for east to show tunnels before shutting down
hostname | grep road > /dev/null && sleep 5
hostname | grep north > /dev/null && sleep 5
hostname | grep east > /dev/null && ipsec whack --trafficstatus
