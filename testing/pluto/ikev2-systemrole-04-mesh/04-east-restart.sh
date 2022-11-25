# New files should have dropped in, and we are ready to restart
ipsec restart
../../guestbin/wait-until-pluto-started
# give OE a chance to load
../../guestbin/wait-for.sh --match 'loaded 6,' -- ipsec status
ipsec status
echo done
