ipsec _kernel state
ipsec _kernel policy

if test -r /tmp/$(hostname).gdb.log ; then cp -v /tmp/*.gdb.log OUTPUT ; ./locks.sh ; fi
