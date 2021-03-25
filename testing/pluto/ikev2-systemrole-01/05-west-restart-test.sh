# New files should have dropped in, and we are ready to restart
# NOTE: for now only works on KVM/qemu until we support *.sh in nsrun
ipsec restart
/testing/pluto/bin/wait-until-pluto-started
ipsec status
# this assumes conection loaded with auto=ondemand
# trigger tunnel - the first trigger ping packet is lost
../../pluto/bin/ping-once.sh --up -I 192.1.2.45 192.1.2.23
# show non-zero IPsec traffic counters
ipsec whack --trafficstatus
echo done
