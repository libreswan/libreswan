# New files should have dropped in, and we are ready to restart
# NOTE: for now only works on KVM/qemu until we support *.sh in nsrun
ipsec restart
/testing/pluto/bin/wait-until-pluto-started
ipsec status
echo done
