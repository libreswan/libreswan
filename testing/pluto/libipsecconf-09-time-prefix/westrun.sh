ipsec auto --add time-good
# rekey_margin: should be less than rekey interval
ipsec status | grep margin
# output is unpredictable, include ephemeral values
ipsec addconn --verbose time-wip
ipsec status | grep margin
ipsec addconn --verbose time-wip
ipsec status | grep margin
