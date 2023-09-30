ipsec whack --trafficstatus | sed -e 's/#[0-9]/#N/' -e 's/\[[0-9]\]/[N]/' -e 's/192.0.2.10[0-9]/192.0.2.10x/' | sort
: ==== cut ====
ipsec auto --status
../../guestbin/ipsec-kernel-state.sh
ip xfrm policy
: ==== tuc ====
: ==== end ====
