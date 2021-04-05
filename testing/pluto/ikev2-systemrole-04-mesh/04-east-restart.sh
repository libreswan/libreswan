# New files should have dropped in, and we are ready to restart
ipsec restart
../../guestbin/wait-until-pluto-started
# give OE a chance to load
sleep 3
ipsec status
echo done
