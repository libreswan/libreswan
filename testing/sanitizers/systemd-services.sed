s/Process: [0-9]* /[XXX]/
s/Main PID:.*$/Main PID: XXX/
s/Memory:.*$/Memory: XXX/
s/^.* west systemd/TIMESTAMP west systemd/
s/^.* west ipsec\[[0-9]*\]/TIMESTAMP west ipsec[XXX]/
s/^.* west whack\[[0-9]*\]/TIMESTAMP west whack[XXX]/
s/since .*$/since TIMESTAMP/
s/[0-9]* PATH/ XXX PATH/
s/limit: [0-9]*/limit: XXX/
