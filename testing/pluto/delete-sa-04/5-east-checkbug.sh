# Connection should be up, and there should be NO log message about "already replacing"
ipsec trafficstatus
grep "already replacing" /tmp/pluto.log && echo "bug triggered"
