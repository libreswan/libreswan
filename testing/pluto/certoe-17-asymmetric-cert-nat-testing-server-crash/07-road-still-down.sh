# check traffic status after crashed server restarted
# we expect no tunnel and %pass shunt still in place
ipsec trafficstatus
ipsec shuntstatus
ipsec _kernel policy
