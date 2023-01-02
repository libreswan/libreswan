ipsec whack --trafficstatus | sed -e 's/#[0-9]/#N/' -e 's/192.0.2.10[1-2]/192.0.2.10x/' -e 's/192.1.3.[0-9]*/192.1.3.x/' | sort
: ==== cut ====
ipsec auto --status
ip xfrm state
ip xfrm policy
: ==== tuc ====
: ==== end ====
