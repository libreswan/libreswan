ipsec add time-good
# rekey_margin: should be less than rekey interval
ipsec status | grep margin
# output is unpredictable, include ephemeral values
ipsec addconn time-wip
ipsec status | grep time-wip | grep margin
ipsec addconn time-wip-hex
ipsec status | grep time-wip-hex | grep margin
