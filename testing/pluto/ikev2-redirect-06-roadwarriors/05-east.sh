sleep 2
# both clients should be connected now
ipsec whack --trafficstatus | sed -e "s/#./#X/" -e "s/\[[0-9]\]/[X]/" -e "s/192.0.2.10./192.0.2.10X/" -e "s/192.1.3.[0-9]*/192.1.3.XX/" | sort
# send REDIRECT in informational to all tunnels from connection east-any (north and road)
ipsec whack --name east-any --redirect-to 192.1.2.45
# give them time to be redirected
sleep 2
# both should be gone now
