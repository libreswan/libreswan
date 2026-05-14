# New files should have dropped in, and we are ready to restart
ipsec restart
../../guestbin/wait-until-pluto-started
ipsec connectionstatus 192.1.2
echo done
