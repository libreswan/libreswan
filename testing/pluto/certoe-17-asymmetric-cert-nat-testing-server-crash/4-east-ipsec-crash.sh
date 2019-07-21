# confirm tunnel is up
ipsec whack --trafficstatus
# killing service ipsec
#pidipsec=$(ps x | grep ipsec)
pidipsec=$(pidof pluto)
#shortpid="${long:0:5}"
kill -9 "$pidipsec"
#echo "$pidipsec"
# give OE conns time to load
sleep 5
# check ipsec service status
echo "ipsec service status"
systemctl status ipsec
