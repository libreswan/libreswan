ipsec whack --trafficstatus | sed -e "s/#./#X/" -e "s/\[[0-9]\]/[X]/" -e "s/192.0.2.10./192.0.2.10X/" | sort
: ==== cut ====
ipsec auto --status
ip xfrm state
ip xfrm policy
: ==== tuc ====
: ==== end ====
